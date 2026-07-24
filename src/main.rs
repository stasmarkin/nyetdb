//! cli layer: clap, orchestration, all IO, exit codes. The "лапша" lives
//! here and only here; config/resolver/output stay pure.

#![forbid(unsafe_code)]

mod config;
mod engine;
mod output;
mod resolver;
mod validator;

use clap::{Parser, Subcommand, ValueEnum};
use engine::Engine;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "nyet",
    version,
    about = "Read-only database access for AI agents. Your agent can look; for everything else — nyet."
)]
struct Cli {
    /// Path to config file (default: $NYET_CONFIG, then ~/.config/nyet/config.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List connections available from the current directory
    List {
        /// Output format (default: [defaults].format from the config, then json)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
    /// Run a read-only query against a connection
    Query {
        /// Connection alias from the config
        alias: String,
        /// The query to run
        query: String,
        /// Output format (default: [defaults].format from the config, then json)
        #[arg(long, value_enum)]
        format: Option<Format>,
        /// Max rows to return (default: per-connection row_limit, then
        /// [defaults].row_limit, then 1000)
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
        limit: Option<u64>,
        /// Query timeout in seconds (default: per-connection timeout_secs,
        /// then [defaults].timeout_secs, then 30)
        #[arg(long, value_name = "SECS", value_parser = clap::value_parser!(u64).range(1..))]
        timeout: Option<u64>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Table,
}

/// Closed list of error codes: the single owner of the code<->exit mapping.
#[derive(Clone, Copy)]
enum ErrorCode {
    ConfigInvalid,
    DirNotAllowed,
    NotImplemented,
    Internal,
    /// Validator refusal; carries the `error.reason` string (closed list,
    /// owned by the validator).
    Nyet(&'static str),
    ConnectionFailed,
    DbError,
    Timeout,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            ErrorCode::ConfigInvalid => "CONFIG_INVALID",
            ErrorCode::DirNotAllowed => "DIR_NOT_ALLOWED",
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::Nyet(_) => "NYET",
            ErrorCode::ConnectionFailed => "CONNECTION_FAILED",
            ErrorCode::DbError => "DB_ERROR",
            ErrorCode::Timeout => "TIMEOUT",
        }
    }

    fn reason(self) -> Option<&'static str> {
        match self {
            ErrorCode::Nyet(reason) => Some(reason),
            _ => None,
        }
    }

    fn exit(self) -> u8 {
        match self {
            ErrorCode::ConfigInvalid => 3,
            ErrorCode::DirNotAllowed => 4,
            ErrorCode::NotImplemented | ErrorCode::Internal => 1,
            ErrorCode::Nyet(_) => 5,
            ErrorCode::ConnectionFailed => 6,
            ErrorCode::DbError => 7,
            ErrorCode::Timeout => 8,
        }
    }
}

/// A failed run: everything needed for the error envelope and the exit code.
struct Failure {
    code: ErrorCode,
    message: String,
    hint: String,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Failure {
            code,
            message: message.into(),
            hint: hint.into(),
        }
    }
}

/// The single owner of stream routing (DESIGN §1): the envelope's place is
/// decided by the format, not the outcome. json — the envelope is the whole
/// stdout output; table — data on stdout, envelope as one JSON line on
/// stderr. Write failures (closed pipe) are ignored, not panics — the exit
/// code still carries the contract; the writes are independent so a failed
/// stdout write cannot swallow the stderr envelope.
fn emit(format: Format, data: &str, envelope: &str) {
    match format {
        Format::Json => {
            let _ = writeln!(std::io::stdout(), "{envelope}");
        }
        Format::Table => {
            let _ = write!(std::io::stdout(), "{data}");
            let _ = writeln!(std::io::stderr(), "{envelope}");
        }
    }
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2.
    let cli = Cli::parse();
    // Effective format for envelope routing. Before the config is read only
    // the flag is known; run() updates this once [defaults].format applies.
    let mut format = match &cli.command {
        Command::List { format } | Command::Query { format, .. } => *format,
    }
    .unwrap_or(Format::Json);
    match run(cli, &mut format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            let envelope =
                output::error_json(f.code.as_str(), f.code.reason(), &f.message, &f.hint);
            emit(format, "", &envelope);
            ExitCode::from(f.code.exit())
        }
    }
}

fn run(cli: Cli, route_format: &mut Format) -> Result<(), Failure> {
    let path = config_path(cli.config)?;
    let text = read_config(&path)?;
    warn_bad_permissions(&path);

    let cfg = config::parse(&text, &|name: &str| std::env::var(name))
        .map_err(|e| config_failure(e, &path))?;

    // Format is settled immediately after the config parses — before any
    // other check — so every later error routes to the right stream.
    let format = match &cli.command {
        Command::List { format } | Command::Query { format, .. } => *format,
    };
    let format = resolve_format(format, cfg.defaults.format.as_deref())?;
    *route_format = format;

    let cwd = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| {
            Failure::new(
                ErrorCode::Internal,
                format!("cannot resolve current directory: {e}"),
                "run nyet from an existing, readable directory",
            )
        })?;
    let home = home_dir();
    let canon = |p: &Path| std::fs::canonicalize(p).ok();
    let allowed = |conn: &config::Connection| {
        resolver::is_allowed(&cwd, &conn.allowed_dirs, home.as_deref(), &canon)
    };

    match cli.command {
        Command::List { .. } => {
            let items: Vec<output::ConnectionInfo> = cfg
                .connections
                .iter()
                .filter(|(_, conn)| allowed(conn))
                .map(|(alias, conn)| output::ConnectionInfo {
                    alias: alias.clone(),
                    engine: conn.engine.clone(),
                })
                .collect();
            let (data, envelope) = match format {
                Format::Json => (String::new(), output::list_json(&items)),
                Format::Table => (output::list_table(&items), output::bare_success()),
            };
            emit(format, &data, &envelope);
            Ok(())
        }
        Command::Query {
            alias,
            query,
            format: _,
            limit,
            timeout,
        } => {
            // Order matters and is pinned by tests: alias -> directory
            // scoping -> engine support -> connection config -> validator ->
            // execution. Scoping fires before the validator (a denied
            // directory answers with exit 4, not a SQL lecture); engine
            // support fires before the validator (an unsupported engine
            // answers NOT_IMPLEMENTED, not NYET with a misleading SQL hint).
            let Some(conn) = cfg.connections.get(&alias) else {
                let known: Vec<&str> = cfg.connections.keys().map(String::as_str).collect();
                return Err(Failure::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "unknown connection alias '{alias}': not defined in {}",
                        path.display()
                    ),
                    if known.is_empty() {
                        "the config defines no connections; add a [connections.<alias>] section"
                            .to_string()
                    } else {
                        format!("known aliases: {}", known.join(", "))
                    },
                ));
            };
            if !allowed(conn) {
                return Err(Failure::new(
                    ErrorCode::DirNotAllowed,
                    format!(
                        "connection '{alias}' is not allowed from {} (directory scoping)",
                        cwd.display()
                    ),
                    if conn.allowed_dirs.is_empty() {
                        format!(
                            "allowed_dirs for '{alias}' is empty, which denies everywhere; \
                             add allowed_dirs = [\"~/path/to/project\"] to the config"
                        )
                    } else {
                        format!(
                            "'{alias}' is allowed from: {}; run nyet from one of those \
                             directories or extend allowed_dirs in the config",
                            conn.allowed_dirs.join(", ")
                        )
                    },
                ));
            }
            let engine = match conn.engine.as_str() {
                "sqlite" => {
                    let Some(path) = &conn.path else {
                        return Err(Failure::new(
                            ErrorCode::ConfigInvalid,
                            format!("connection '{alias}' has engine = \"sqlite\" but no `path`"),
                            "add path = \"/path/to/file.db\" to this connection in the config",
                        ));
                    };
                    engine::Sqlite {
                        path: PathBuf::from(path),
                    }
                }
                other => {
                    return Err(Failure::new(
                        ErrorCode::NotImplemented,
                        format!("engine \"{other}\" of connection '{alias}' is not supported yet"),
                        "sqlite is the only engine in this version; other engines arrive \
                         in later releases",
                    ))
                }
            };

            // Layer 1: the validator. Any deny -> code NYET + reason, exit 5.
            if let validator::Verdict::Deny {
                reason,
                message,
                hint,
            } = validator::validate(&query)
            {
                return Err(Failure::new(
                    ErrorCode::Nyet(reason.as_str()),
                    message,
                    hint,
                ));
            }

            // Flag > per-connection > [defaults] > built-in.
            let limit = limit
                .or(conn.row_limit)
                .or(cfg.defaults.row_limit)
                .unwrap_or(1000);
            let timeout_secs = timeout
                .or(conn.timeout_secs)
                .or(cfg.defaults.timeout_secs)
                .unwrap_or(30);

            // The runtime is built lazily, only when an engine actually runs
            // (Д9: config/validator failures never pay the async tax).
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|e| {
                    Failure::new(
                        ErrorCode::Internal,
                        format!("cannot start the async runtime: {e}"),
                        "this is a bug in nyet; please report it",
                    )
                })?;
            let started = Instant::now();
            // Fetch limit+1 to detect truncation without reading everything.
            // timeout() must be created inside the runtime (it arms a timer).
            let result = rt.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    engine.execute(&query, limit.saturating_add(1)),
                )
                .await
            });
            // After a timeout the sqlite worker may still be grinding; a
            // background shutdown lets the process exit instead of joining it.
            rt.shutdown_background();
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

            let mut rs = match result {
                // Honest wording: the future is dropped, but the sqlite
                // worker thread may keep grinding until the process exits.
                Err(_elapsed) => {
                    return Err(Failure::new(
                        ErrorCode::Timeout,
                        format!(
                            "query on '{alias}' did not finish within the {timeout_secs}s timeout"
                        ),
                        "narrow the query (WHERE / LIMIT), or raise --timeout or \
                         timeout_secs in the config",
                    ))
                }
                Ok(Err(engine::EngineError::Connect { message, hint })) => {
                    return Err(Failure::new(ErrorCode::ConnectionFailed, message, hint))
                }
                Ok(Err(engine::EngineError::Db { message, hint })) => {
                    return Err(Failure::new(ErrorCode::DbError, message, hint))
                }
                Ok(Ok(rs)) => rs,
            };

            let truncated = rs.rows.len() as u64 > limit;
            if truncated {
                rs.rows
                    .truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            let mut warnings = Vec::new();
            if truncated {
                warnings.push(output::Warning {
                    code: "TRUNCATED",
                    message: format!(
                        "result truncated to {limit} rows; add WHERE/LIMIT or raise --limit"
                    ),
                });
            }
            // Duplicate column names collapse in json row objects (later
            // values overwrite earlier ones in most JSON parsers) — never
            // let that happen silently.
            let duplicates = duplicate_columns(&rs.columns);
            if !duplicates.is_empty() {
                warnings.push(output::Warning {
                    code: "DUPLICATE_COLUMNS",
                    message: format!(
                        "duplicate column names in the result: {}; in json rows the last \
                         value wins — use AS aliases to keep every column",
                        duplicates.join(", ")
                    ),
                });
            }
            let meta = output::QueryMeta {
                row_count: rs.rows.len() as u64,
                truncated,
                duration_ms,
                connection: alias,
            };
            let (data, envelope) = match format {
                Format::Json => (
                    String::new(),
                    output::query_json(&rs.columns, &rs.rows, &meta, &warnings),
                ),
                Format::Table => (
                    output::query_table(&rs.columns, &rs.rows),
                    output::query_meta_json(&meta, &warnings),
                ),
            };
            emit(format, &data, &envelope);
            Ok(())
        }
    }
}

fn duplicate_columns(columns: &[String]) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    let mut duplicates: Vec<&str> = Vec::new();
    for column in columns {
        if !seen.insert(column.as_str()) && !duplicates.contains(&column.as_str()) {
            duplicates.push(column.as_str());
        }
    }
    duplicates
}

/// Flag > [defaults].format > json. Runs right after config parsing, for
/// every command, so a bad config value fails loudly even when a flag
/// overrides it. Names come from the clap ValueEnum — one source of truth.
fn resolve_format(flag: Option<Format>, cfg_default: Option<&str>) -> Result<Format, Failure> {
    let from_config = match cfg_default {
        None => Format::Json,
        Some(name) => <Format as ValueEnum>::from_str(name, false).map_err(|_| {
            let known: Vec<String> = Format::value_variants()
                .iter()
                .filter_map(|v| v.to_possible_value())
                .map(|p| p.get_name().to_string())
                .collect();
            Failure::new(
                ErrorCode::ConfigInvalid,
                format!("[defaults].format is \"{name}\", which this version does not support"),
                format!("supported formats: {}", known.join(", ")),
            )
        })?,
    };
    Ok(flag.unwrap_or(from_config))
}

fn config_failure(e: config::ConfigError, path: &Path) -> Failure {
    let (message, hint) = match e {
        config::ConfigError::Invalid(msg) => (
            format!("config file {} is invalid: {msg}", path.display()),
            "fix the config file; see README for a full annotated example".to_string(),
        ),
        config::ConfigError::MissingEnvVar(name) => (
            format!(
                "config file {} references ${{{name}}} but that environment variable is not set",
                path.display()
            ),
            format!("export {name}=... before running nyet, or remove the reference"),
        ),
        config::ConfigError::NotUnicodeEnvVar(name) => (
            format!(
                "config file {} references ${{{name}}} but that environment variable \
                 is set to a value that is not valid UTF-8",
                path.display()
            ),
            format!("re-export {name} with a valid UTF-8 value, or remove the reference"),
        ),
        config::ConfigError::EnvVarInAllowedDir { alias, dir } => (
            format!(
                "config file {}: allowed_dirs entry \"{dir}\" for connection '{alias}' \
                 uses ${{VAR}} substitution",
                path.display()
            ),
            "allowed_dirs entries must be literal paths; ${VAR} substitution is not \
             allowed here because the environment is controlled by the calling agent"
                .to_string(),
        ),
        config::ConfigError::InvalidAllowedDir { alias, dir } => (
            format!(
                "config file {}: allowed_dirs entry \"{dir}\" for connection '{alias}' \
                 is not a valid scoping path",
                path.display()
            ),
            "entries must be absolute or ~/relative; relative entries, \"~//...\" \
             and \"..\" components are rejected because they would widen the scope — \
             write the resolved absolute path instead"
                .to_string(),
        ),
        config::ConfigError::ZeroValue { key } => (
            format!("config file {}: {key} is 0", path.display()),
            "row_limit and timeout_secs must be at least 1; to use the built-in \
             default, omit the key"
                .to_string(),
        ),
    };
    Failure::new(ErrorCode::ConfigInvalid, message, hint)
}

/// Single source of truth for the home dir: empty HOME counts as unset.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// --config flag -> $NYET_CONFIG -> ~/.config/nyet/config.toml.
fn config_path(flag: Option<PathBuf>) -> Result<PathBuf, Failure> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if let Some(p) = std::env::var_os("NYET_CONFIG") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    match home_dir() {
        Some(h) => Ok(h.join(".config/nyet/config.toml")),
        None => Err(Failure::new(
            ErrorCode::ConfigInvalid,
            "cannot locate the config file: HOME is not set",
            "pass --config <path> or set NYET_CONFIG",
        )),
    }
}

fn read_config(path: &Path) -> Result<String, Failure> {
    std::fs::read_to_string(path).map_err(|e| {
        let (message, hint) = match e.kind() {
            std::io::ErrorKind::NotFound => (
                format!("config file not found: {}", path.display()),
                "create ~/.config/nyet/config.toml (see README for a full example) \
                 or point --config / $NYET_CONFIG at an existing file"
                    .to_string(),
            ),
            std::io::ErrorKind::InvalidData => (
                format!("config file {} is not valid UTF-8", path.display()),
                "re-save the file with UTF-8 encoding".to_string(),
            ),
            _ => (
                format!("cannot read config file {}: {e}", path.display()),
                "check that the file is readable by the current user".to_string(),
            ),
        };
        Failure::new(ErrorCode::ConfigInvalid, message, hint)
    })
}

/// Config accessible by group/others -> human warning on stderr (not a refusal).
fn warn_bad_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata(path) {
            if let Some(warning) = config::permissions_warning(md.mode()) {
                let _ = writeln!(std::io::stderr(), "warning: {}: {warning}", path.display());
            }
        }
    }
}
