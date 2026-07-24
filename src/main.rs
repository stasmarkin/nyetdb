//! cli layer: clap, orchestration, all IO, exit codes. The "лапша" lives
//! here and only here; config/resolver/output stay pure.

#![forbid(unsafe_code)]

mod config;
mod output;
mod resolver;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// Run a read-only query against a connection (not implemented yet)
    Query {
        /// Connection alias from the config
        alias: String,
        /// The query to run
        query: String,
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
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            ErrorCode::ConfigInvalid => "CONFIG_INVALID",
            ErrorCode::DirNotAllowed => "DIR_NOT_ALLOWED",
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    fn exit(self) -> u8 {
        match self {
            ErrorCode::ConfigInvalid => 3,
            ErrorCode::DirNotAllowed => 4,
            ErrorCode::NotImplemented | ErrorCode::Internal => 1,
        }
    }
}

/// A failed run: everything needed for the error envelope and the exit code.
struct Failure {
    code: ErrorCode,
    message: String,
    hint: String,
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2.
    let cli = Cli::parse();
    let format = match &cli.command {
        Command::List { format } => *format,
        Command::Query { .. } => Format::Json,
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            let envelope = output::error_json(f.code.as_str(), &f.message, &f.hint);
            // Envelope placement is decided by the format, not the outcome:
            // json -> stdout; other data formats -> stderr, stdout stays
            // data-only (empty on error). Write failures (e.g. closed pipe)
            // are ignored — the exit code still carries the contract.
            let _ = match format {
                Format::Json => writeln!(std::io::stdout(), "{envelope}"),
                Format::Table => writeln!(std::io::stderr(), "{envelope}"),
            };
            ExitCode::from(f.code.exit())
        }
    }
}

fn run(cli: Cli) -> Result<(), Failure> {
    let path = config_path(cli.config)?;
    let text = read_config(&path)?;
    warn_bad_permissions(&path);

    let cfg = config::parse(&text, &|name: &str| std::env::var(name))
        .map_err(|e| config_failure(e, &path))?;

    let cwd = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| Failure {
            code: ErrorCode::Internal,
            message: format!("cannot resolve current directory: {e}"),
            hint: "run nyet from an existing, readable directory".into(),
        })?;
    let home = home_dir();
    let canon = |p: &Path| std::fs::canonicalize(p).ok();
    let allowed = |conn: &config::Connection| {
        resolver::is_allowed(&cwd, &conn.allowed_dirs, home.as_deref(), &canon)
    };

    match cli.command {
        Command::List { format } => {
            let items: Vec<output::ConnectionInfo> = cfg
                .connections
                .iter()
                .filter(|(_, conn)| allowed(conn))
                .map(|(alias, conn)| output::ConnectionInfo {
                    alias: alias.clone(),
                    engine: conn.engine.clone(),
                })
                .collect();
            // Write failures (closed pipe) are ignored, not panics.
            match format {
                Format::Json => {
                    let _ = writeln!(std::io::stdout(), "{}", output::list_json(&items));
                }
                // Data formats other than json: data on stdout, data-less
                // envelope as one JSON line on stderr (contract, DESIGN §1).
                // Independent writes: a failed stdout write must not swallow
                // the stderr envelope.
                Format::Table => {
                    let _ = write!(std::io::stdout(), "{}", output::list_table(&items));
                    let _ = writeln!(std::io::stderr(), "{}", output::bare_success());
                }
            }
            Ok(())
        }
        Command::Query { alias, query: _ } => {
            let Some(conn) = cfg.connections.get(&alias) else {
                let known: Vec<&str> = cfg.connections.keys().map(String::as_str).collect();
                return Err(Failure {
                    code: ErrorCode::ConfigInvalid,
                    message: format!(
                        "unknown connection alias '{alias}': not defined in {}",
                        path.display()
                    ),
                    hint: if known.is_empty() {
                        "the config defines no connections; add a [connections.<alias>] section"
                            .into()
                    } else {
                        format!("known aliases: {}", known.join(", "))
                    },
                });
            };
            if !allowed(conn) {
                return Err(Failure {
                    code: ErrorCode::DirNotAllowed,
                    message: format!(
                        "connection '{alias}' is not allowed from {} (directory scoping)",
                        cwd.display()
                    ),
                    hint: if conn.allowed_dirs.is_empty() {
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
                });
            }
            // Honest stub: full resolution above gives exit codes 3/4 real
            // paths already; execution lands in the next step.
            Err(Failure {
                code: ErrorCode::NotImplemented,
                message: format!(
                    "nyet query is not implemented yet; connection '{alias}' resolved successfully"
                ),
                hint: "query arrives in the next release; use `nyet list` to inspect available connections".into(),
            })
        }
    }
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
    };
    Failure {
        code: ErrorCode::ConfigInvalid,
        message,
        hint,
    }
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
        None => Err(Failure {
            code: ErrorCode::ConfigInvalid,
            message: "cannot locate the config file: HOME is not set".into(),
            hint: "pass --config <path> or set NYET_CONFIG".into(),
        }),
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
        Failure {
            code: ErrorCode::ConfigInvalid,
            message,
            hint,
        }
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
