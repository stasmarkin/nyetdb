//! cli layer: clap, orchestration, all IO, exit codes. The "лапша" lives
//! here and only here; config/resolver/output stay pure.

#![forbid(unsafe_code)]

mod config;
mod engine;
mod output;
mod resolver;
mod tunnel;
mod validator;

use clap::{Parser, Subcommand, ValueEnum};
use engine::Engine;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

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
        format: Option<PlainFormat>,
    },
    /// Show the schema of a connection: tables, views, columns, indexes, foreign keys
    ///
    /// Examples:
    ///   nyet schema prod                # every table and view (details up to 50 objects)
    ///   nyet schema prod users          # one table, always in full
    ///   nyet schema prod sales.orders   # PostgreSQL: a table outside the public schema
    // verbatim: clap reflows a doc comment into one paragraph otherwise, and
    // the examples are the point (UX-3: --help is written for an LLM).
    #[command(verbatim_doc_comment)]
    Schema {
        /// Connection alias from the config
        alias: String,
        /// One table or view to detail (PostgreSQL: `schema.table` outside public)
        table: Option<String>,
        /// Output format (default: [defaults].format from the config, then json)
        #[arg(long, value_enum)]
        format: Option<PlainFormat>,
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
    Jsonl,
    Table,
    Csv,
}

/// `list` and `schema` have no row stream, so jsonl/csv make no sense there
/// (DESIGN §1 gives list json|table only); a separate clap enum makes
/// `--format jsonl` a native usage error (exit 2) instead of a runtime refusal.
#[derive(Clone, Copy, ValueEnum)]
enum PlainFormat {
    Json,
    Table,
}

impl PlainFormat {
    fn as_format(self) -> Format {
        match self {
            PlainFormat::Json => Format::Json,
            PlainFormat::Table => Format::Table,
        }
    }
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

/// Engine dispatch. `Engine::execute` is a native `async fn` in a trait, which
/// is not object-safe, so a small enum stands in for `Box<dyn Engine>`.
enum Db {
    Sqlite(engine::Sqlite),
    Postgres(engine::Postgres),
    Mysql(engine::Mysql),
}

impl Db {
    async fn execute(
        &self,
        sql: &str,
        fetch_limit: u64,
    ) -> Result<engine::ResultSet, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.execute(sql, fetch_limit).await,
            Db::Postgres(e) => e.execute(sql, fetch_limit).await,
            Db::Mysql(e) => e.execute(sql, fetch_limit).await,
        }
    }

    /// Point a server engine at the tunnel's local end. Exhaustive match so a
    /// future engine that forgot to wire the tunnel fails to compile rather than
    /// silently connecting straight to the real host (a bastion bypass). SQLite
    /// has no host (sqlite + `[ssh]` is rejected at config parse).
    fn set_host_override(&mut self, over: (String, u16)) {
        match self {
            Db::Postgres(pg) => pg.host_override = Some(over),
            Db::Mysql(my) => my.host_override = Some(over),
            Db::Sqlite(_) => {}
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<output::Schema, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.schema(table).await,
            Db::Postgres(e) => e.schema(table).await,
            Db::Mysql(e) => e.schema(table).await,
        }
    }
}

/// The single owner of stream routing (DESIGN §1): the envelope's place is
/// decided by the format, not the outcome. json — the envelope is the whole
/// stdout output; table/jsonl/csv — data on stdout, envelope as one JSON
/// line on stderr. The stderr envelope write is always best-effort (a gone
/// consumer must not swallow it). The stdout (data) write is best-effort for
/// a closed pipe — the consumer walked away, that is graceful — but a real
/// failure (e.g. a full disk) is returned as Err so the caller does NOT
/// then claim success: silently dropping query output while reporting ok is
/// exactly the data loss to avoid. No panics either way.
fn emit(format: Format, data: &str, envelope: &str) -> io::Result<()> {
    match format {
        // The envelope IS the whole stdout output here, so it is the data.
        Format::Json => write_stdout(format!("{envelope}\n").as_bytes()),
        Format::Jsonl | Format::Table | Format::Csv => {
            let result = write_stdout(data.as_bytes());
            let _ = writeln!(std::io::stderr(), "{envelope}");
            result
        }
    }
}

/// Write to stdout, treating a closed pipe (consumer exited) as graceful
/// success and surfacing every other error (the data was lost).
fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    match std::io::stdout().write_all(bytes) {
        Err(e) if !broken_pipe(&e) => Err(e),
        _ => Ok(()),
    }
}

/// A closed pipe means the consumer walked away — graceful, exit 0. Any
/// other write error is real output loss and must fail loudly.
fn broken_pipe(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe
}

/// stdout write failed for something other than a gone consumer (e.g. a
/// full disk): the query output is lost, so fail loudly instead of claiming
/// success.
fn output_write_failure(e: io::Error) -> Failure {
    Failure::new(
        ErrorCode::Internal,
        format!("failed to write query output to stdout: {e}"),
        "check the output stream and free disk space, then retry",
    )
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2.
    let cli = Cli::parse();
    // Effective format for envelope routing. Before the config is read only
    // the flag is known; run() updates this once [defaults].format applies.
    let mut format = match &cli.command {
        Command::List { format } => format.map(PlainFormat::as_format),
        Command::Schema { format, .. } => format.map(PlainFormat::as_format),
        Command::Query { format, .. } => *format,
    }
    .unwrap_or(Format::Json);
    match run(cli, &mut format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            let envelope =
                output::error_json(f.code.as_str(), f.code.reason(), &f.message, &f.hint);
            // Best-effort: we are already failing, and there is no data to
            // lose (the envelope goes out; its write failing changes nothing).
            let _ = emit(format, "", &envelope);
            ExitCode::from(f.code.exit())
        }
    }
}

fn run(cli: Cli, route_format: &mut Format) -> Result<(), Failure> {
    let path = config_path(cli.config)?;
    let text = read_config(&path)?;
    warn_bad_permissions(&path);

    // Routing format is settled from a raw peek of [defaults].format BEFORE
    // the semantic config parse — so a config error (e.g. row_limit = 0)
    // under [defaults].format = "csv" still routes its envelope by that
    // format (data stream on stdout, envelope on stderr) instead of
    // defaulting to json on stdout.
    let format = resolve_format(
        match &cli.command {
            Command::List { format } => format.map(PlainFormat::as_format),
            Command::Schema { format, .. } => format.map(PlainFormat::as_format),
            Command::Query { format, .. } => *format,
        },
        config::peek_defaults_format(&text).as_deref(),
    )?;
    // list/schema have no row stream, so a jsonl/csv [defaults].format (set
    // for query workflows) degrades to json for them — documented in README.
    let format = match (&cli.command, format) {
        (Command::List { .. } | Command::Schema { .. }, Format::Jsonl | Format::Csv) => {
            Format::Json
        }
        (_, f) => f,
    };
    *route_format = format;

    let cfg = config::parse(&text, &|name: &str| std::env::var(name))
        .map_err(|e| config_failure(e, &path))?;

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
                Format::Table => (output::list_table(&items), output::bare_success()),
                // Only Json remains: jsonl/csv were degraded to json above.
                _ => (String::new(), output::list_json(&items)),
            };
            emit(format, &data, &envelope).map_err(output_write_failure)?;
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
            let conn = lookup_alias(&cfg, &path, &alias)?;
            check_scope(&alias, conn, &cwd, allowed(conn))?;
            // Flag > per-connection > [defaults] > built-in. Timeout is
            // resolved here (before the engine) because Postgres feeds it into
            // the server-side statement_timeout at connect time.
            let limit = limit
                .or(conn.row_limit)
                .or(cfg.defaults.row_limit)
                .unwrap_or(1000);
            let timeout_secs = timeout
                .or(conn.timeout_secs)
                .or(cfg.defaults.timeout_secs)
                .unwrap_or(30);
            let (mut db, policy) = build_engine(&alias, conn, timeout_secs)?;
            let insecure_transport = insecure_transport(conn);

            // Layer 1: the validator. Any deny -> code NYET + reason, exit 5.
            let (query, mut warnings) = match validator::validate(&query, &policy) {
                validator::Verdict::Deny {
                    reason,
                    message,
                    hint,
                } => {
                    return Err(Failure::new(
                        ErrorCode::Nyet(reason.as_str()),
                        message,
                        hint,
                    ))
                }
                // Execute the NORMALIZED text — it is what the validator
                // classified; running the original would reopen the gap
                // Unicode stripping closes.
                validator::Verdict::Allow { sql, warnings } => (
                    sql,
                    warnings
                        .into_iter()
                        .map(|w| output::Warning {
                            code: w.code,
                            message: w.message,
                        })
                        .collect::<Vec<_>>(),
                ),
            };

            // Layer 2.5: an SSH tunnel to a bastion, opened AFTER the validator
            // (a refused query exits 5 without paying for ssh) and BEFORE the
            // engine connects. The guard is held for the whole query and torn
            // down on drop, so forwards never accumulate.
            let _tunnel = open_tunnel(conn, timeout_secs, &mut db)?;

            let rt = runtime()?;
            let started = Instant::now();
            // The engine owns BOTH deadlines internally: a hung/slow CONNECT is
            // bounded by its own generous deadline (-> Connect, exit 6) and only
            // the QUERY phase is bounded by the effective per-query timeout (->
            // Timeout, exit 8). Keeping them inside execute (not one outer tokio
            // timeout over connect+query) makes the exit code deterministic even
            // when --timeout is smaller than a legitimate connect. Fetch limit+1
            // to detect truncation without reading everything.
            let result = rt.block_on(db.execute(&query, limit.saturating_add(1)));
            // After a query timeout the sqlite worker may still be grinding; a
            // background shutdown lets the process exit instead of joining it.
            rt.shutdown_background();
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

            let mut rs = result.map_err(engine_failure)?;

            let truncated = rs.rows.len() as u64 > limit;
            if truncated {
                rs.rows
                    .truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            if truncated {
                warnings.push(output::Warning {
                    code: "TRUNCATED",
                    message: format!(
                        "result truncated to {limit} rows; add WHERE/LIMIT or raise --limit"
                    ),
                });
            }
            // Warned for every format (json/jsonl collapse same-named keys to
            // the last value; table/csv keep the columns but the ambiguity is
            // still worth flagging) — so the message stays format-neutral.
            let duplicates = duplicate_columns(&rs.columns);
            if !duplicates.is_empty() {
                warnings.push(output::Warning {
                    code: "DUPLICATE_COLUMNS",
                    message: format!(
                        "duplicate column name(s): {}; disambiguate with AS aliases — \
                         in JSON/JSONL output duplicates collapse to the last value",
                        duplicates.join(", ")
                    ),
                });
            }
            if insecure_transport {
                warnings.push(insecure_transport_warning());
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
                Format::Jsonl => (
                    output::query_jsonl(&rs.columns, &rs.rows),
                    output::query_meta_json(&meta, &warnings),
                ),
                Format::Table => (
                    output::query_table(&rs.columns, &rs.rows),
                    output::query_meta_json(&meta, &warnings),
                ),
                Format::Csv => (
                    output::query_csv(&rs.columns, &rs.rows),
                    output::query_meta_json(&meta, &warnings),
                ),
            };
            emit(format, &data, &envelope).map_err(output_write_failure)?;
            Ok(())
        }
        Command::Schema {
            alias,
            table,
            format: _,
        } => {
            // Same pipeline order as query, minus the validator (there is no
            // agent SQL here): alias -> directory scoping -> engine support /
            // connection config -> execution.
            let conn = lookup_alias(&cfg, &path, &alias)?;
            check_scope(&alias, conn, &cwd, allowed(conn))?;
            let timeout_secs = conn
                .timeout_secs
                .or(cfg.defaults.timeout_secs)
                .unwrap_or(30);
            let (mut db, _policy) = build_engine(&alias, conn, timeout_secs)?;
            let insecure_transport = insecure_transport(conn);
            let _tunnel = open_tunnel(conn, timeout_secs, &mut db)?;

            let rt = runtime()?;
            let started = Instant::now();
            let result = rt.block_on(db.schema(table.as_deref()));
            rt.shutdown_background();
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let schema = result.map_err(engine_failure)?;

            // An explicit [table] that matched nothing: the catalog answered,
            // the object simply is not there. DB_ERROR (exit 7) with the way
            // out (Д10) — no new error code for it.
            if let Some(name) = &table {
                if schema.tables.is_empty() {
                    return Err(Failure::new(
                        ErrorCode::DbError,
                        format!("table '{name}' not found in {alias}"),
                        format!("run nyet schema {alias} to list available tables"),
                    ));
                }
            }

            let mut warnings: Vec<output::Warning> = Vec::new();
            if schema.is_listing() {
                warnings.push(output::Warning {
                    code: "SCHEMA_TRUNCATED",
                    message: format!(
                        "schema listing truncated to names: {} objects exceed the {}-object \
                         detail limit; run nyet schema {alias} <table> for one table's details",
                        schema.tables.len(),
                        output::DETAIL_LIMIT
                    ),
                });
            }
            if insecure_transport {
                warnings.push(insecure_transport_warning());
            }
            let meta = output::SchemaMeta {
                table_count: schema.tables.len() as u64,
                duration_ms,
                connection: alias,
            };
            let (data, envelope) = match format {
                Format::Table => (
                    output::schema_text(&schema),
                    output::schema_meta_json(&meta, &warnings),
                ),
                // Only Json remains: jsonl/csv were degraded to json above.
                _ => (
                    String::new(),
                    output::schema_json(&schema, &meta, &warnings),
                ),
            };
            emit(format, &data, &envelope).map_err(output_write_failure)?;
            Ok(())
        }
    }
}

/// alias -> connection, with the known-alias hint (CONFIG_INVALID, exit 3).
fn lookup_alias<'a>(
    cfg: &'a config::Config,
    path: &Path,
    alias: &str,
) -> Result<&'a config::Connection, Failure> {
    cfg.connections.get(alias).ok_or_else(|| {
        let known: Vec<&str> = cfg.connections.keys().map(String::as_str).collect();
        Failure::new(
            ErrorCode::ConfigInvalid,
            format!(
                "unknown connection alias '{alias}': not defined in {}",
                path.display()
            ),
            if known.is_empty() {
                "the config defines no connections; add a [connections.<alias>] section".to_string()
            } else {
                format!("known aliases: {}", known.join(", "))
            },
        )
    })
}

/// Directory scoping (DIR_NOT_ALLOWED, exit 4).
fn check_scope(
    alias: &str,
    conn: &config::Connection,
    cwd: &Path,
    allowed: bool,
) -> Result<(), Failure> {
    if allowed {
        return Ok(());
    }
    Err(Failure::new(
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
    ))
}

/// Engine dispatch: the concrete engine, its SQL dialect and its built-in
/// validator policy are chosen together by `engine`. Shared by query and
/// schema, so both answer a missing `path`/`url` (CONFIG_INVALID, exit 3) or an
/// unsupported engine (NOT_IMPLEMENTED, exit 1) identically. `schema` ignores
/// the policy — introspection runs no agent SQL.
fn build_engine(
    alias: &str,
    conn: &config::Connection,
    timeout_secs: u64,
) -> Result<(Db, validator::Policy), Failure> {
    // Per-connection validator policy tunes only the function denylist.
    let (v_allow, v_deny) = match &conn.validator {
        Some(v) => (
            v.allow_functions.as_deref().unwrap_or(&[]),
            v.deny_functions.as_deref().unwrap_or(&[]),
        ),
        None => (&[][..], &[][..]),
    };
    match conn.engine.as_str() {
        "sqlite" => {
            let Some(path) = &conn.path else {
                return Err(Failure::new(
                    ErrorCode::ConfigInvalid,
                    format!("connection '{alias}' has engine = \"sqlite\" but no `path`"),
                    "add path = \"/path/to/file.db\" to this connection in the config",
                ));
            };
            Ok((
                Db::Sqlite(engine::Sqlite {
                    path: PathBuf::from(path),
                    // sqlite has no server-side timeout, so this in-process
                    // budget (bounding the fetch inside execute) is the
                    // ONLY query timeout — the cli no longer wraps execute
                    // in an outer timeout.
                    query_timeout_ms: timeout_secs.saturating_mul(1000),
                }),
                validator::Policy::sqlite(v_allow, v_deny),
            ))
        }
        "postgres" => {
            let Some(url) = &conn.url else {
                return Err(Failure::new(
                    ErrorCode::ConfigInvalid,
                    format!("connection '{alias}' has engine = \"postgres\" but no `url`"),
                    "add url = \"postgres://user@host:port/dbname\" to this connection \
                     in the config",
                ));
            };
            let password = read_password_env(alias, conn)?;
            Ok((
                Db::Postgres(engine::Postgres {
                    url: url.clone(),
                    password,
                    // Postgres rejects statement_timeout > INT_MAX ms
                    // at connect; clamp so a huge timeout_secs still
                    // connects. i32::MAX ms is ~24.8 days.
                    statement_timeout_ms: timeout_secs.saturating_mul(1000).min(i32::MAX as u64),
                    // The in-process query-phase deadline (unclamped): the
                    // full per-query wall budget, backstopping the server
                    // statement_timeout above.
                    query_timeout_ms: timeout_secs.saturating_mul(1000),
                    // Filled in by open_tunnel once the SSH tunnel (if any) is up.
                    host_override: None,
                    // Production: the generous connect_deadline floor.
                    connect_timeout_ms: None,
                }),
                validator::Policy::postgres(v_allow, v_deny),
            ))
        }
        // MariaDB is dialect- and protocol-identical to MySQL here; the
        // engine sets both server-timeout variables (MySQL's and
        // MariaDB's) and swallows the wrong-flavor error, so the label
        // needs no special handling.
        "mysql" | "mariadb" => {
            let Some(url) = &conn.url else {
                return Err(Failure::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "connection '{alias}' has engine = \"{}\" but no `url`",
                        conn.engine
                    ),
                    "add url = \"mysql://user@host:port/dbname\" to this connection \
                     in the config",
                ));
            };
            let password = read_password_env(alias, conn)?;
            Ok((
                Db::Mysql(engine::Mysql {
                    url: url.clone(),
                    password,
                    // Clamp to u32::MAX ms so a huge timeout_secs stays
                    // within MySQL's max_execution_time range.
                    statement_timeout_ms: timeout_secs.saturating_mul(1000).min(u32::MAX as u64),
                    // The in-process query-phase deadline (unclamped): the
                    // full per-query wall budget, backstopping the server
                    // max_execution_time/max_statement_time above.
                    query_timeout_ms: timeout_secs.saturating_mul(1000),
                    // Filled in by open_tunnel once the SSH tunnel (if any) is up.
                    host_override: None,
                    // Production: the generous connect_deadline floor.
                    connect_timeout_ms: None,
                }),
                validator::Policy::mysql(v_allow, v_deny),
            ))
        }
        other => Err(Failure::new(
            ErrorCode::NotImplemented,
            format!("engine \"{other}\" of connection '{alias}' is not supported yet"),
            "supported engines: sqlite, postgres, mysql, mariadb; others arrive in \
             later releases",
        )),
    }
}

/// Open the SSH tunnel (if the connection has one) and point the engine at its
/// local end. A tunnel failure is CONNECTION_FAILED (exit 6). sqlite + ssh was
/// already rejected at config parse, so only the server engines reach here.
/// The returned guard tears the forward down on drop — the caller holds it for
/// the whole database operation.
fn open_tunnel(
    conn: &config::Connection,
    timeout_secs: u64,
    db: &mut Db,
) -> Result<Option<tunnel::Tunnel>, Failure> {
    let Some(ssh) = &conn.ssh else {
        return Ok(None);
    };
    // host/remote are guaranteed Some+valid by config parse; a None here is an
    // internal invariant break, not agent input, so fail fast rather than
    // silently skipping the tunnel (which would connect straight to the real
    // host — the wrong failure mode).
    let host = ssh
        .host
        .as_deref()
        .expect("ssh host validated non-empty at config parse");
    let remote = ssh
        .remote
        .as_deref()
        .expect("ssh remote validated non-empty at config parse");
    let control_persist = ssh.control_persist.as_deref().unwrap_or("15m");
    let tunnel = tunnel::open(host, remote, control_persist, timeout_secs)
        .map_err(|e| Failure::new(ErrorCode::ConnectionFailed, e.message, e.hint))?;
    db.set_host_override(("127.0.0.1".to_string(), tunnel.local_port));
    Ok(Some(tunnel))
}

/// The runtime is built lazily, only when an engine actually runs (Д9:
/// config/validator failures never pay the async tax). enable_all: the time
/// driver arms the engine's in-process connect and query deadlines, and the IO
/// driver backs the TCP connection (SQLite needs neither but pays nothing
/// measurable).
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            Failure::new(
                ErrorCode::Internal,
                format!("cannot start the async runtime: {e}"),
                "this is a bug in nyet; please report it",
            )
        })
}

/// The single owner of the EngineError -> contract-code mapping. Both the
/// in-process timer and a server-side statement_timeout (Postgres 57014 /
/// MySQL 3024 / MariaDB 1969) surface as `Timeout` -> exit 8, deterministic
/// whichever fires.
fn engine_failure(e: engine::EngineError) -> Failure {
    match e {
        engine::EngineError::Connect { message, hint } => {
            Failure::new(ErrorCode::ConnectionFailed, message, hint)
        }
        engine::EngineError::Db { message, hint } => {
            Failure::new(ErrorCode::DbError, message, hint)
        }
        engine::EngineError::Timeout { message, hint } => {
            Failure::new(ErrorCode::Timeout, message, hint)
        }
    }
}

/// Static transport check for the INSECURE_TRANSPORT warning: a direct (no ssh)
/// server connection whose url sslmode is below require gives no
/// encryption/verification guarantee. Computed from config + url only (no
/// server round-trip).
fn insecure_transport(conn: &config::Connection) -> bool {
    conn.ssh.is_none()
        && engine::transport_below_require(&conn.engine, conn.url.as_deref().unwrap_or(""))
}

/// Security signal (not a refusal), shared by query and schema: the transport
/// gave no encryption guarantee. `Warning` has no hint field, so the remedy is
/// folded into the message.
fn insecure_transport_warning() -> output::Warning {
    output::Warning {
        code: "INSECURE_TRANSPORT",
        message: "this connection's transport is not guaranteed encrypted or \
                  verified (sslmode below require and no ssh tunnel); set \
                  sslmode=verify-full (Postgres) or ssl-mode=VERIFY_IDENTITY \
                  (MySQL) in the url, or route through an ssh tunnel"
            .to_string(),
    }
}

/// Read the password for a server connection. `password_env` holds the NAME of
/// an env var; its value is read here and never printed. A named-but-unset var
/// is a hard config error (like a missing `${VAR}`). Shared by the postgres and
/// mysql/mariadb engines.
fn read_password_env(alias: &str, conn: &config::Connection) -> Result<Option<String>, Failure> {
    match &conn.password_env {
        Some(var) => match std::env::var(var) {
            Ok(v) => Ok(Some(v)),
            Err(_) => Err(Failure::new(
                ErrorCode::ConfigInvalid,
                format!(
                    "connection '{alias}' sets password_env = \"{var}\" but that environment \
                     variable is not set"
                ),
                format!(
                    "export {var}=... before running nyet, or remove password_env to connect \
                     without a password"
                ),
            )),
        },
        None => Ok(None),
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
        config::ConfigError::SshMissingField { alias, field } => (
            format!(
                "config file {}: connection '{alias}' has an [ssh] section but no {field}",
                path.display()
            ),
            format!(
                "set {field} in [connections.{alias}.ssh]: host = \"[user@]bastion[:port]\", \
                 remote = \"db-host:5432\" — both are required for a tunnel"
            ),
        ),
        config::ConfigError::SshWithSqlite { alias } => (
            format!(
                "config file {}: connection '{alias}' is engine = \"sqlite\" but has an [ssh] section",
                path.display()
            ),
            "SSH tunnels forward a TCP port; SQLite is a local file, so ssh does not \
             apply — remove the [ssh] section, or use a server engine (postgres)"
                .to_string(),
        ),
        config::ConfigError::SshInvalid { alias, message } => (
            format!("config file {}: connection '{alias}' has an invalid [ssh] value: {message}", path.display()),
            "fix the [ssh] host/remote/control_persist; host is [user@]hostname[:port] and \
             remote is host:port with safe characters — values that could be read as ssh \
             options (a leading '-', or a ${VAR} that expands to one) are rejected"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_pipe_is_the_only_graceful_write_error() {
        // A gone consumer (closed pipe) is graceful; a full disk (or any
        // other write error) is real output loss and must fail loudly.
        assert!(broken_pipe(&io::Error::from(io::ErrorKind::BrokenPipe)));
        assert!(!broken_pipe(&io::Error::from(io::ErrorKind::Other)));
        // Naming an exit code for the loud path: INTERNAL -> exit 1.
        let f = output_write_failure(io::Error::from(io::ErrorKind::Other));
        assert_eq!(f.code.exit(), 1);
        assert!(!f.hint.is_empty());
    }
}
