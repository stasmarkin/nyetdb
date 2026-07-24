//! Config parsing: TOML text -> validated structures. Pure: no IO here;
//! the cli layer reads the file and passes an env lookup closure in.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    // Validated now; defaults get applied when query execution lands (step 2).
    #[allow(dead_code)]
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
}

// Parsed and schema-validated now; consumed by later steps (query/formats).
#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub row_limit: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub format: Option<String>,
}

// url/path/password_env/limits are validated now, used by engines in step 2+.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub engine: String,
    pub url: Option<String>,
    pub path: Option<String>,
    /// Name of the env variable holding the password; the value is never printed.
    pub password_env: Option<String>,
    /// Empty or absent = denied everywhere (fail closed).
    #[serde(default)]
    pub allowed_dirs: Vec<String>,
    pub row_limit: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub validator: Option<Validator>,
    pub ssh: Option<Ssh>,
}

// Accepted now so configs written for later steps stay valid; used in step 3.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub allow_functions: Option<Vec<String>>,
    pub deny_functions: Option<Vec<String>>,
}

// Accepted now; used in step 5 (ssh tunnels).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    pub host: Option<String>,
    pub remote: Option<String>,
    pub control_persist: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    /// TOML syntax error or schema violation (unknown key, wrong type, ...).
    Invalid(String),
    /// `${VAR}` referenced in the config but the variable is not set.
    MissingEnvVar(String),
    /// `${VAR}` is set but its value is not valid UTF-8.
    NotUnicodeEnvVar(String),
    /// An allowed_dirs entry that is neither absolute nor a safe `~/` path
    /// (relative, or `~//...` whose remainder is rooted) — both fail-open.
    InvalidAllowedDir { alias: String, dir: String },
    /// `${VAR}` in an allowed_dirs entry: the environment is controlled by
    /// the calling agent, so substitution there would let it widen the scope.
    EnvVarInAllowedDir { alias: String, dir: String },
}

/// Environment lookup, injected for purity (cli passes `std::env::var`).
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Result<String, std::env::VarError>;

/// Parse config text.
pub fn parse(text: &str, env: EnvLookup) -> Result<Config, ConfigError> {
    let value: toml::Value =
        toml::from_str(text).map_err(|e| ConfigError::Invalid(toml_message(&e, text)))?;
    // On the RAW value, before substitution: allowed_dirs must be literal.
    reject_env_vars_in_allowed_dirs(&value)?;
    let value = substitute(value, env)?;
    let config: Config = value
        .try_into()
        .map_err(|e: toml::de::Error| ConfigError::Invalid(toml_message(&e, text)))?;
    // Defense in depth below (the literal-only rule already bars env-driven
    // widening). A relative entry would canonicalize against cwd ("." =
    // allowed everywhere); a rooted remainder after `~/` would make join()
    // return the root itself ("~//" = allowed everywhere). Fail closed.
    for (alias, conn) in &config.connections {
        for dir in &conn.allowed_dirs {
            if !valid_allowed_dir(dir) {
                return Err(ConfigError::InvalidAllowedDir {
                    alias: alias.clone(),
                    dir: dir.clone(),
                });
            }
        }
    }
    Ok(config)
}

/// `allowed_dirs` must be static literals: `${VAR}` there would let the
/// calling agent (who controls the environment) widen the scope at will,
/// e.g. "/srv/${P}" with P="" resolves to the parent "/srv/".
fn reject_env_vars_in_allowed_dirs(value: &toml::Value) -> Result<(), ConfigError> {
    let Some(connections) = value.get("connections").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    for (alias, conn) in connections {
        let Some(dirs) = conn.get("allowed_dirs").and_then(toml::Value::as_array) else {
            continue;
        };
        for dir in dirs.iter().filter_map(toml::Value::as_str) {
            if dir.contains("${") {
                return Err(ConfigError::EnvVarInAllowedDir {
                    alias: alias.clone(),
                    dir: dir.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn valid_allowed_dir(dir: &str) -> bool {
    use std::path::{Component, Path};
    // ".." anywhere (also in the absolute form) escapes the intended prefix.
    if Path::new(dir)
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return false;
    }
    if dir == "~" {
        return true;
    }
    if let Some(rest) = dir.strip_prefix("~/") {
        // A rooted remainder or (on Windows) a drive prefix like "C:." makes
        // home.join(rest) ignore home entirely -> widened scope.
        return !Path::new(rest).has_root()
            && !Path::new(rest)
                .components()
                .any(|c| matches!(c, Component::Prefix(_)));
    }
    Path::new(dir).is_absolute()
}

/// toml::de::Error's Display embeds an excerpt of the offending source line —
/// which may contain credentials. Emit only the bare message + a line number,
/// with double-quoted spans redacted: schema errors echo the offending value
/// ('invalid type: string "secret"...'). Key names use backticks and survive.
fn toml_message(e: &toml::de::Error, text: &str) -> String {
    let msg = redact_quoted(e.message());
    match e.span() {
        Some(span) => {
            let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
            format!("{msg} (at line {line})")
        }
        None => msg,
    }
}

fn redact_quoted(msg: &str) -> String {
    // Greedy: the value itself may contain a quote, so pairwise matching
    // would leave parts of it outside the redaction. Everything from the
    // first to the last quote goes; a lone quote redacts to the end.
    // Over-redacting is the safe direction, under-redacting is not.
    match msg.find('"') {
        None => msg.to_string(),
        Some(first) => {
            let last = msg.rfind('"').unwrap_or(first);
            let tail = if last > first { &msg[last + 1..] } else { "" };
            format!("{}\"...\"{tail}", &msg[..first])
        }
    }
}

/// group/other permission bits set -> warning text (pure; cli reads the mode).
pub fn permissions_warning(mode: u32) -> Option<String> {
    if mode & 0o077 != 0 {
        Some(format!(
            "config file is accessible by group/others (mode {:03o}); credentials may leak — run `chmod 600` on it",
            mode & 0o777
        ))
    } else {
        None
    }
}

/// `${VAR}` substitution in every string value, recursively.
fn substitute(value: toml::Value, env: EnvLookup) -> Result<toml::Value, ConfigError> {
    Ok(match value {
        toml::Value::String(s) => toml::Value::String(substitute_str(&s, env)?),
        toml::Value::Array(items) => toml::Value::Array(
            items
                .into_iter()
                .map(|v| substitute(v, env))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(table) => toml::Value::Table(
            table
                .into_iter()
                .map(|(k, v)| Ok((k, substitute(v, env)?)))
                .collect::<Result<_, _>>()?,
        ),
        other => other,
    })
}

fn substitute_str(s: &str, env: EnvLookup) -> Result<String, ConfigError> {
    use std::env::VarError;
    let mut parts = s.split("${");
    let mut out = String::from(parts.next().unwrap_or(""));
    for part in parts {
        match part.find('}') {
            Some(end) if is_var_name(&part[..end]) => {
                let name = &part[..end];
                match env(name) {
                    Ok(val) => out.push_str(&val),
                    Err(VarError::NotPresent) => {
                        return Err(ConfigError::MissingEnvVar(name.to_string()))
                    }
                    Err(VarError::NotUnicode(_)) => {
                        return Err(ConfigError::NotUnicodeEnvVar(name.to_string()))
                    }
                }
                out.push_str(&part[end + 1..]);
            }
            // Not a well-formed ${NAME} — keep the text literally.
            _ => {
                out.push_str("${");
                out.push_str(part);
            }
        }
    }
    Ok(out)
}

fn is_var_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, std::env::VarError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned().ok_or(std::env::VarError::NotPresent)
    }

    const FULL: &str = r#"
        [defaults]
        row_limit = 1000
        timeout_secs = 30
        format = "json"

        [connections.prod]
        engine = "postgres"
        url = "postgres://nyet_ro@db.internal:5432/app"
        password_env = "PROD_DB_PASSWORD"
        allowed_dirs = ["~/Workspace/app"]
        row_limit = 500
        timeout_secs = 10

        [connections.prod.validator]
        allow_functions = ["pg_sleep"]
        deny_functions = ["my_scary_fn"]

        [connections.prod.ssh]
        host = "deploy@bastion.corp:22"
        remote = "db.internal:5432"
        control_persist = "15m"

        [connections.localdev]
        engine = "sqlite"
        path = "./dev.db"
        allowed_dirs = ["~/Workspace/app"]
    "#;

    #[test]
    fn full_config_parses() {
        let cfg = parse(FULL, &env_of(&[])).unwrap();
        assert_eq!(cfg.defaults.row_limit, Some(1000));
        assert_eq!(cfg.connections.len(), 2);
        let prod = &cfg.connections["prod"];
        assert_eq!(prod.engine, "postgres");
        // password_env holds the variable *name*, never its value.
        assert_eq!(prod.password_env.as_deref(), Some("PROD_DB_PASSWORD"));
        assert_eq!(
            prod.validator.as_ref().unwrap().allow_functions,
            Some(vec!["pg_sleep".to_string()])
        );
        assert_eq!(
            prod.ssh.as_ref().unwrap().host.as_deref(),
            Some("deploy@bastion.corp:22")
        );
        assert_eq!(
            cfg.connections["localdev"].path.as_deref(),
            Some("./dev.db")
        );
    }

    #[test]
    fn broken_toml_is_invalid() {
        assert!(matches!(
            parse("not = [valid", &env_of(&[])),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn unknown_key_is_invalid() {
        let err = parse(
            "[connections.a]\nengine = \"sqlite\"\ntypo_key = 1",
            &env_of(&[]),
        )
        .unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("typo_key"), "{msg}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn env_substitution_works() {
        let cfg = parse(
            "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u:${PW}@h/db\"",
            &env_of(&[("PW", "s3cret")]),
        )
        .unwrap();
        assert_eq!(
            cfg.connections["a"].url.as_deref(),
            Some("postgres://u:s3cret@h/db")
        );
    }

    #[test]
    fn missing_env_var_is_hard_error() {
        let err = parse(
            "[connections.a]\nengine = \"postgres\"\nurl = \"${NO_SUCH_VAR_XYZ}\"",
            &env_of(&[]),
        )
        .unwrap_err();
        match err {
            ConfigError::MissingEnvVar(name) => assert_eq!(name, "NO_SUCH_VAR_XYZ"),
            other => panic!("expected MissingEnvVar, got {other:?}"),
        }
    }

    #[test]
    fn non_utf8_env_var_is_hard_error() {
        let env = |_: &str| {
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "garbage",
            )))
        };
        let err = parse(
            "[connections.a]\nengine = \"postgres\"\nurl = \"${BAD_VAR}\"",
            &env,
        )
        .unwrap_err();
        match err {
            ConfigError::NotUnicodeEnvVar(name) => assert_eq!(name, "BAD_VAR"),
            other => panic!("expected NotUnicodeEnvVar, got {other:?}"),
        }
    }

    #[test]
    fn bad_allowed_dirs_are_rejected() {
        // Relative entries, rooted-remainder tilde entries and ".." are fail-open.
        for dir in [
            ".",
            "./app",
            "relative/path",
            "~//",
            "~//etc",
            "~/..",
            "~/../etc",
            "/abs/../etc",
        ] {
            let text = format!("[connections.a]\nengine = \"sqlite\"\nallowed_dirs = [\"{dir}\"]");
            let err = parse(&text, &env_of(&[])).unwrap_err();
            match err {
                ConfigError::InvalidAllowedDir { alias, dir: got } => {
                    assert_eq!(alias, "a");
                    assert_eq!(got, dir);
                }
                other => panic!("expected InvalidAllowedDir for {dir:?}, got {other:?}"),
            }
        }
        // Absolute and tilde forms pass.
        for dir in ["/abs/path", "~", "~/proj"] {
            let text = format!("[connections.a]\nengine = \"sqlite\"\nallowed_dirs = [\"{dir}\"]");
            assert!(parse(&text, &env_of(&[])).is_ok(), "{dir} should be valid");
        }
    }

    #[test]
    fn env_vars_in_allowed_dirs_are_rejected_before_substitution() {
        // The calling agent controls the environment: "/srv/${P}" with P=""
        // would resolve to the parent "/srv/". Literal paths only.
        for (dir, env) in [
            ("~/${X}", env_of(&[("X", "/etc")])),
            ("/srv/${P}", env_of(&[("P", "")])),
            ("/srv/${UNSET}", env_of(&[])), // rejected even if VAR is unset
        ] {
            let text = format!("[connections.a]\nengine = \"sqlite\"\nallowed_dirs = [\"{dir}\"]");
            let err = parse(&text, &env).unwrap_err();
            assert!(
                matches!(err, ConfigError::EnvVarInAllowedDir { dir: ref got, .. } if got == dir),
                "for {dir:?} got {err:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn drive_prefix_remainder_after_tilde_is_rejected() {
        // "C:." parses as Component::Prefix only on Windows; there
        // home.join("C:.") ignores home entirely.
        assert!(!valid_allowed_dir("~/C:."));
    }

    #[test]
    fn schema_error_does_not_leak_values_containing_quotes() {
        // The value itself contains a `"`: pairwise quote matching would
        // leave SUPERSECRET outside the redacted span.
        let err = parse(
            "[connections.a]\nengine = \"sqlite\"\nrow_limit = \"prefix\\\"SUPERSECRET\"",
            &env_of(&[]),
        )
        .unwrap_err();
        match err {
            ConfigError::Invalid(msg) => {
                assert!(!msg.contains("SUPERSECRET"), "leaked: {msg}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        // Direct check of the greedy redaction on a raw message.
        assert_eq!(
            redact_quoted(r#"invalid type: string "prefix"SUPERSECRET", expected u64"#),
            r#"invalid type: string "...", expected u64"#
        );
        // Lone quote: redact to the end (unclosed span may hold the value).
        assert_eq!(redact_quoted(r#"got "secret tail"#), r#"got "...""#);
        assert_eq!(redact_quoted("no quotes here"), "no quotes here");
    }

    #[test]
    fn schema_error_does_not_leak_values() {
        // Wrong-type schema errors echo the offending value in quotes;
        // it must be redacted (the value may be a credential).
        let err = parse(
            "[connections.a]\nengine = \"sqlite\"\nrow_limit = \"supersecret\"",
            &env_of(&[]),
        )
        .unwrap_err();
        match err {
            ConfigError::Invalid(msg) => {
                assert!(!msg.contains("supersecret"), "leaked: {msg}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn toml_error_does_not_leak_source_text() {
        // Unterminated string: the offending line holds a credential; the
        // error message must not echo the source excerpt (threat model:
        // credentials never reach the LLM context).
        let err = parse(
            "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://user:supersecret@host/db\n",
            &env_of(&[]),
        )
        .unwrap_err();
        match err {
            ConfigError::Invalid(msg) => {
                assert!(!msg.contains("supersecret"), "leaked: {msg}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn malformed_placeholder_kept_literally() {
        let cfg = parse(
            "[connections.a]\nengine = \"postgres\"\nurl = \"${not closed\"",
            &env_of(&[]),
        )
        .unwrap();
        assert_eq!(cfg.connections["a"].url.as_deref(), Some("${not closed"));
    }

    #[test]
    fn permissions_warning_on_group_other_bits() {
        assert!(permissions_warning(0o100600).is_none());
        assert!(permissions_warning(0o100644).is_some());
        assert!(permissions_warning(0o100640).is_some());
        assert!(permissions_warning(0o100601).is_some());
    }
}
