//! cli layer: clap, orchestration, all IO, exit codes. The "лапша" lives
//! here and only here; config/resolver/output stay pure.

#![forbid(unsafe_code)]

mod audit;
mod config;
mod engine;
mod guardrail;
mod output;
mod resolver;
mod skill;
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
    /// Show the query plan, the cost estimate and the guardrail verdict —
    /// without running the query
    ///
    /// Examples:
    ///   nyet explain prod "SELECT * FROM orders WHERE org_id = 7"
    ///   nyet explain prod "SELECT count(*) FROM events" --format table
    // verbatim: see the Schema arm — the examples are the point (UX-3).
    #[command(verbatim_doc_comment)]
    Explain {
        /// Connection alias from the config
        alias: String,
        /// The query to plan (read statements only, like `nyet query`)
        query: String,
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
    /// Diagnose a connection's setup honestly (UX-7): connectivity, transport
    /// encryption, whether layer 3 (a read-only role) actually holds, superuser
    /// status, and config-file permissions
    ///
    /// Runs a harmless write probe to prove read-only for real (PostgreSQL: in a
    /// rolled-back transaction; MySQL/MariaDB: create-then-drop, as DDL auto-commits).
    /// Always exits 0 when it ran — the per-check verdicts are in the envelope.
    ///
    /// Examples:
    ///   nyet doctor              # config-file checks + connections available here
    ///   nyet doctor prod         # full per-connection diagnosis
    // verbatim: see the Schema arm — the examples are the point (UX-3).
    #[command(verbatim_doc_comment)]
    Doctor {
        /// Connection alias to diagnose in full (omit for config-level checks)
        alias: Option<String>,
        /// Output format (default: table — doctor is the one human-facing command)
        #[arg(long, value_enum)]
        format: Option<PlainFormat>,
    },
    /// Generate a Claude Code skill (SKILL.md) that teaches an AI agent to use
    /// nyet: how to read databases, inspect schemas and run safe read-only
    /// queries, how to read the JSON envelope and recover from a refusal, plus
    /// the connections available from here
    ///
    /// It needs no database or network — it is local generation. A missing or
    /// broken config is not an error: the instruction is still emitted (its
    /// value is teaching the agent before setup) and the connections section
    /// degrades to a hint. Install it with:
    ///
    ///   nyet agent-setup > .claude/skills/nyet/SKILL.md
    ///
    /// Default output is the raw SKILL.md on stdout (the envelope goes to
    /// stderr, like a data format); `--format json` wraps the whole SKILL.md
    /// in the `skill` field of a JSON envelope on stdout.
    // verbatim: see the Schema arm — the examples are the point (UX-3).
    #[command(verbatim_doc_comment)]
    AgentSetup {
        /// Output format (default: markdown)
        #[arg(long, value_enum)]
        format: Option<SetupFormat>,
    },
}

/// `agent-setup` emits Markdown by default (the SKILL.md a human redirects to a
/// file) and can wrap it in a JSON envelope for programmatic access. Its own
/// tiny enum: the other formats (jsonl/csv/table) are meaningless for a single
/// document, and it does not honor `[defaults].format` (that serves query rows).
#[derive(Clone, Copy, ValueEnum)]
enum SetupFormat {
    Markdown,
    Json,
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
    /// The audit log could not be written (UX-8 fail-closed): the result is NOT
    /// released to the agent. Infrastructure failure of nyet itself, so it maps
    /// to the INTERNAL exit class (1), but keeps its own distinct code.
    AuditFailed,
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
            ErrorCode::AuditFailed => "AUDIT_FAILED",
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
            ErrorCode::NotImplemented | ErrorCode::Internal | ErrorCode::AuditFailed => 1,
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
    /// Only the guardrail refusal fills this: the plan that justified it
    /// travels in the same envelope, so the agent can fix the query without a
    /// second round trip (UX-2). Boxed: every Failure travels by value through
    /// the whole cli, and only this one rare variant carries a plan.
    estimate: Option<Box<output::Estimate>>,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Failure {
            code,
            message: message.into(),
            hint: hint.into(),
            estimate: None,
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
    /// The ONE way rows leave the engine layer — and therefore the one place
    /// net B (PII provenance) is applied. Putting the check here rather than in
    /// a command body means a future rows-returning command cannot inherit the
    /// hole by forgetting to call it (finding 6); `QueryOutcome::PiiRefused`
    /// then forces every caller to handle the refusal.
    async fn execute(
        &self,
        sql: &str,
        fetch_limit: u64,
        guardrail: &guardrail::Guardrail,
        pii: &validator::PiiRules,
    ) -> Result<engine::QueryOutcome, engine::EngineError> {
        let outcome = match self {
            Db::Sqlite(e) => e.execute(sql, fetch_limit, guardrail).await,
            Db::Postgres(e) => e.execute(sql, fetch_limit, guardrail).await,
            Db::Mysql(e) => e.execute(sql, fetch_limit, guardrail).await,
        }?;
        if let engine::QueryOutcome::Ran { result, .. } = &outcome {
            if let Some(refusal) = validator::check_origins(pii, &result.columns, &result.origins) {
                return Ok(engine::QueryOutcome::PiiRefused(Box::new(refusal)));
            }
        }
        Ok(outcome)
    }

    async fn estimate(
        &self,
        sql: &str,
    ) -> Result<Option<guardrail::CostEstimate>, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.estimate(sql).await,
            Db::Postgres(e) => e.estimate(sql).await,
            Db::Mysql(e) => e.estimate(sql).await,
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

    /// Ask the engine for column PROVENANCE on the next query (net B). Only
    /// PostgreSQL pays for it (an extra DESCRIBE round trip), and only when the
    /// connection has a PII policy: MySQL and SQLite report origins on the wire
    /// for free, so they need no switch. Exhaustive match — a future engine must
    /// state its answer rather than silently returning unprovable columns.
    fn resolve_column_origins(&mut self) {
        match self {
            Db::Postgres(pg) => pg.resolve_column_origins = true,
            Db::Mysql(_) | Db::Sqlite(_) => {}
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<output::Schema, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.schema(table).await,
            Db::Postgres(e) => e.schema(table).await,
            Db::Mysql(e) => e.schema(table).await,
        }
    }

    async fn diagnose(&self) -> output::Diagnosis {
        match self {
            Db::Sqlite(e) => e.diagnose().await,
            Db::Postgres(e) => e.diagnose().await,
            Db::Mysql(e) => e.diagnose().await,
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

/// Everything a completed database command needs to hand back: the streams to
/// write AND the facts the audit record needs. Built by each DB-command body,
/// consumed by `audit_finish` (log first, then emit — UX-8 fail-closed).
struct Emitted {
    data: String,
    envelope: String,
    duration_ms: u64,
    /// query only.
    row_count: Option<u64>,
    truncated: Option<bool>,
    warnings: Vec<&'static str>,
    /// The result the agent saw, built only when `[audit] log_responses` is on.
    response: Option<audit::Response>,
}

/// The command-identity fields of an audit record, known once the session is
/// open (so the engine is resolved). Config errors BEFORE this point (unknown
/// alias, directory denied, unsupported engine, missing password) are not
/// logged — there is no database interaction and no engine to name; they behave
/// exactly as before this feature.
struct AuditMeta<'a> {
    command: &'a str,
    alias: &'a str,
    engine: &'a str,
    cwd: &'a str,
    sql: Option<&'a str>,
    table: Option<&'a str>,
}

/// The single seam that enforces UX-8: **write the audit record (durably) BEFORE
/// releasing the result to the agent**. On success the line is committed, then
/// `emit` streams the data; if the audit write fails the result is NOT emitted
/// and the caller gets `AUDIT_FAILED` (exit 1) instead — the human never misses
/// an event the agent acted on. A logical failure (a NYET refusal, a DB error)
/// is logged too (the human sees what the agent TRIED) and its own envelope is
/// still produced by `main`; a failed audit write overrides even that.
///
/// With `[audit] enabled = false` nothing is written and the command behaves
/// byte-for-byte as before.
fn audit_finish(
    cfg: &config::Config,
    meta: AuditMeta,
    format: Format,
    outcome: Result<Emitted, Failure>,
) -> Result<(), Failure> {
    if !cfg.audit_enabled() {
        return match outcome {
            Ok(e) => emit(format, &e.data, &e.envelope).map_err(output_write_failure),
            Err(f) => Err(f),
        };
    }

    let path = audit_path(cfg)?;
    // The log holds the agent's SQL (and rows under log_responses); an existing
    // file with group/other bits leaks it to other local users. Warn like the
    // config file (we warn, never chmod). A file nyet creates is 0600 already.
    warn_loose_permissions(&path, "the audit log");
    let ts = audit_timestamp();
    let event = match &outcome {
        Ok(e) => audit::Event {
            audit_v: audit::AUDIT_V,
            ts: &ts,
            command: meta.command,
            alias: meta.alias,
            engine: meta.engine,
            cwd: meta.cwd,
            sql: meta.sql,
            table: meta.table,
            verdict: "ok",
            reason: None,
            exit_code: 0,
            row_count: e.row_count,
            truncated: e.truncated,
            duration_ms: e.duration_ms,
            warnings: &e.warnings,
            response: e.response.as_ref(),
        },
        Err(f) => {
            // A NYET verdict is a refusal (validator/guardrail); any other code
            // is an error. The reason is the NYET reason or the error.code.
            let (verdict, reason) = match f.code {
                ErrorCode::Nyet(r) => ("refused", r),
                other => ("error", other.as_str()),
            };
            audit::Event {
                audit_v: audit::AUDIT_V,
                ts: &ts,
                command: meta.command,
                alias: meta.alias,
                engine: meta.engine,
                cwd: meta.cwd,
                sql: meta.sql,
                table: meta.table,
                verdict,
                reason: Some(reason),
                exit_code: f.code.exit(),
                row_count: None,
                truncated: None,
                // The failure paths do not thread their wall time through; the
                // forensic signal is verdict + reason + sql, not the timing.
                duration_ms: 0,
                warnings: &[],
                response: None,
            }
        }
    };
    let line = audit::line(&event);
    // Persist (write + flush) BEFORE anything reaches the agent.
    audit::append(&path, &line).map_err(|e| audit_failed(&path, &e))?;

    match outcome {
        Ok(e) => emit(format, &e.data, &e.envelope).map_err(output_write_failure),
        Err(f) => Err(f),
    }
}

/// Resolve the audit-log path: an explicit literal `[audit] path`, else
/// `$XDG_DATA_HOME/nyet/audit.jsonl`, else `~/.local/share/nyet/audit.jsonl`.
/// If none can be formed (no HOME, no XDG) auditing cannot proceed — fail
/// closed rather than silently skip (Д3, no panic).
fn audit_path(cfg: &config::Config) -> Result<PathBuf, Failure> {
    if let Some(p) = &cfg.audit.path {
        return Ok(PathBuf::from(p));
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("nyet/audit.jsonl"));
        }
    }
    match home_dir() {
        Some(h) => Ok(h.join(".local/share/nyet/audit.jsonl")),
        None => Err(Failure::new(
            ErrorCode::AuditFailed,
            "cannot locate the audit log: neither XDG_DATA_HOME nor HOME is set",
            "set [audit] path = \"/absolute/path/audit.jsonl\" in the config, or disable \
             auditing with [audit] enabled = false",
        )),
    }
}

/// A command's structured result as a `Value`, for the audit `response` field
/// (schema/explain/doctor). A serialization that somehow failed degrades to
/// null rather than panicking (Д3) — the record is still written.
fn payload_value<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// ISO 8601 UTC, millisecond precision. chrono comes in through sqlx (already a
/// dependency) — no new crate for a timestamp.
fn audit_timestamp() -> String {
    use sqlx::types::chrono::Utc;
    // Explicit UTC pattern (the value is already UTC), millisecond precision.
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The audit write failed: the result is withheld (UX-8) and the agent is told
/// how to fix or disable auditing (Д10). The path is not a secret.
fn audit_failed(path: &Path, e: &std::io::Error) -> Failure {
    Failure::new(
        ErrorCode::AuditFailed,
        format!("failed to write the audit log at {}: {e}", path.display()),
        "the query ran but its result was withheld because the audit trail could not be \
         recorded (UX-8); fix the path and its permissions so nyet can create and append \
         to it, or disable auditing with [audit] enabled = false in the config",
    )
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2.
    let cli = Cli::parse();
    // Effective format for envelope routing. Before the config is read only
    // the flag is known; run() updates this once [defaults].format applies.
    let mut format = command_format_flag(&cli.command).unwrap_or(default_format(&cli.command));
    match run(cli, &mut format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            let envelope = output::error_json(
                f.code.as_str(),
                f.code.reason(),
                &f.message,
                &f.hint,
                f.estimate.as_deref(),
            );
            // Best-effort: we are already failing, and there is no data to
            // lose (the envelope goes out; its write failing changes nothing).
            let _ = emit(format, "", &envelope);
            ExitCode::from(f.code.exit())
        }
    }
}

fn run(cli: Cli, route_format: &mut Format) -> Result<(), Failure> {
    // agent-setup is local generation (Д9: no runtime, no db, no network) and
    // must survive a missing/broken config (degradation, never exit 3), so it
    // short-circuits before the mandatory config read below.
    if let Command::AgentSetup { format } = &cli.command {
        let format = format.unwrap_or(SetupFormat::Markdown);
        return agent_setup(cli.config, format, route_format);
    }

    let path = config_path(cli.config)?;
    let text = read_config(&path)?;
    warn_loose_permissions(&path, "the config file");

    // Routing format is settled from a raw peek of [defaults].format BEFORE
    // the semantic config parse — so a config error (e.g. row_limit = 0)
    // under [defaults].format = "csv" still routes its envelope by that
    // format (data stream on stdout, envelope on stderr) instead of
    // defaulting to json on stdout.
    let flag = command_format_flag(&cli.command);
    // doctor is the one human-facing command: it defaults to `table` and ignores
    // [defaults].format (set for query row workflows) — only an explicit --format
    // flag (json|table) changes it.
    let format = if matches!(cli.command, Command::Doctor { .. }) {
        flag.unwrap_or(Format::Table)
    } else {
        let resolved = resolve_format(flag, config::peek_defaults_format(&text).as_deref())?;
        // list/schema/explain have no row stream, so a jsonl/csv [defaults].format
        // (set for query workflows) degrades to json for them.
        match (&cli.command, resolved) {
            (
                Command::List { .. } | Command::Schema { .. } | Command::Explain { .. },
                Format::Jsonl | Format::Csv,
            ) => Format::Json,
            (_, f) => f,
        }
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
            let (conn, mut session) = open_session(&cfg, &path, &alias, &cwd, &allowed, timeout)?;
            // Audit identity, captured before the body consumes `query`/`alias`.
            let engine = conn.engine.clone();
            let raw_sql = query.clone();
            let cwd_str = cwd.display().to_string();
            let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
            let redact_db_errors = session.redact_db_errors();
            // The whole command as ONE Result so both success and every failure
            // path (validator/guardrail refusal, DB error) flow through
            // audit_finish — the log is written before the result is released.
            let outcome = (|| -> Result<Emitted, Failure> {
                // Flag > per-connection > [defaults] > built-in, capped by the
                // config owner's max_row_limit (see config::capped).
                let limit = cfg.row_limit(conn, limit);
                // Layer 1: the validator. Any deny -> code NYET + reason, exit 5.
                let (query, is_query, mut warnings) = validate(&query, &session.policy)?;
                // Layer 1.5: the guardrail. Only a plain query can be wrapped in an
                // EXPLAIN; SHOW/DESCRIBE are metadata no planner estimates, so they
                // run unguarded (documented). An EXPLAIN ANALYZE never gets here —
                // the validator refuses it (reason EXPLAIN_ANALYZE).
                let guardrail = match is_query {
                    true => {
                        config::guardrail(&alias, conn).map_err(|e| config_failure(e, &path))?
                    }
                    false => guardrail::Guardrail::OFF,
                };
                // The tunnel is opened AFTER the validator (a refused query exits 5
                // without paying for ssh) and torn down when the guard drops, so
                // forwards never accumulate. Fetch limit+1 to detect truncation
                // without reading everything.
                let _tunnel = open_tunnel(conn, session.timeout_secs, &mut session.db)?;
                let (outcome, duration_ms) = run_db(
                    redact_db_errors,
                    session.db.execute(
                        &query,
                        limit.saturating_add(1),
                        &guardrail,
                        session.policy.pii(),
                    ),
                )?;

                let (mut rs, estimate) = match outcome {
                    // The guardrail refused: nothing ran, and the envelope carries
                    // the plan that justified it (NYET/EXPENSIVE_QUERY, exit 5).
                    engine::QueryOutcome::Refused { estimate, value } => {
                        let (message, hint) = guardrail.refusal(&alias, value);
                        return Err(Failure {
                            code: ErrorCode::Nyet("EXPENSIVE_QUERY"),
                            message,
                            hint,
                            estimate: Some(Box::new(guardrail.describe(estimate))),
                        });
                    }
                    // Planning itself outran the guardrail's budget. Fail closed:
                    // planning time is agent-controllable, so "no plan in time" must
                    // not be a way to switch the guard off. Same reason code — the
                    // verdict is the same, only the evidence differs.
                    engine::QueryOutcome::PlanTooSlow { budget_ms } => {
                        let (message, hint) = guardrail::planning_too_slow(&alias, budget_ms);
                        return Err(Failure {
                            code: ErrorCode::Nyet("EXPENSIVE_QUERY"),
                            message,
                            hint,
                            estimate: None,
                        });
                    }
                    // Net B refused the result: the rows exist but are never
                    // formatted, logged or emitted (the check runs inside
                    // Db::execute, before this match).
                    engine::QueryOutcome::PiiRefused(refusal) => {
                        return Err(refusal_failure(*refusal))
                    }
                    engine::QueryOutcome::Ran { result, estimate } => (result, estimate),
                };
                // The guardrail was on but reached no verdict — the database would
                // not plan the statement (no estimate at all), or the plan carried
                // no number it could judge. Fail open by design (see docs/DEV.md),
                // but never silently: the timeout and the row limit are what is left.
                if guardrail.plans()
                    && estimate.is_none_or(|e| guardrail.check(&e) == guardrail::Check::NoEstimate)
                {
                    warnings.push(guardrail_skipped_warning());
                }

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
                if session.insecure_transport {
                    warnings.push(insecure_transport_warning());
                }
                let meta = output::QueryMeta {
                    row_count: rs.rows.len() as u64,
                    truncated,
                    duration_ms,
                    connection: alias.clone(),
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
                let warning_codes = warnings.iter().map(|w| w.code).collect();
                // The data/envelope strings are built; rs is now free to MOVE
                // into the response (log_responses only) — keeps column order,
                // no clone. Exactly what the agent received, post-truncation.
                let response = log_responses.then_some(audit::Response::Rows {
                    columns: rs.columns,
                    rows: rs.rows,
                });
                Ok(Emitted {
                    data,
                    envelope,
                    duration_ms,
                    row_count: Some(meta.row_count),
                    truncated: Some(truncated),
                    warnings: warning_codes,
                    response,
                })
            })();
            audit_finish(
                &cfg,
                AuditMeta {
                    command: "query",
                    alias: &alias,
                    engine: &engine,
                    cwd: &cwd_str,
                    sql: Some(&raw_sql),
                    table: None,
                },
                format,
                outcome,
            )
        }
        Command::Schema {
            alias,
            table,
            format: _,
        } => {
            // The same setup as query, minus the validator and the guardrail
            // (there is no agent SQL here, and a catalog read has nothing to
            // estimate).
            let (conn, mut session) = open_session(&cfg, &path, &alias, &cwd, &allowed, None)?;
            let engine = conn.engine.clone();
            let cwd_str = cwd.display().to_string();
            let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
            let redact_db_errors = session.redact_db_errors();
            let outcome = (|| -> Result<Emitted, Failure> {
                let _tunnel = open_tunnel(conn, session.timeout_secs, &mut session.db)?;
                let (schema, duration_ms) =
                    run_db(redact_db_errors, session.db.schema(table.as_deref()))?;

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
                if session.insecure_transport {
                    warnings.push(insecure_transport_warning());
                }
                let meta = output::SchemaMeta {
                    table_count: schema.tables.len() as u64,
                    duration_ms,
                    connection: alias.clone(),
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
                let warning_codes = warnings.iter().map(|w| w.code).collect();
                let response =
                    log_responses.then(|| audit::Response::Payload(payload_value(&schema)));
                Ok(Emitted {
                    data,
                    envelope,
                    duration_ms,
                    row_count: None,
                    truncated: None,
                    warnings: warning_codes,
                    response,
                })
            })();
            audit_finish(
                &cfg,
                AuditMeta {
                    command: "schema",
                    alias: &alias,
                    engine: &engine,
                    cwd: &cwd_str,
                    sql: None,
                    table: table.as_deref(),
                },
                format,
                outcome,
            )
        }
        Command::Explain {
            alias,
            query,
            format: _,
        } => {
            // The `query` pipeline up to and including the validator, then the
            // PLAN instead of the execution. Nothing runs: the EXPLAIN is never
            // ANALYZE, so `nyet explain` cannot be a way to execute anything.
            let (conn, mut session) = open_session(&cfg, &path, &alias, &cwd, &allowed, None)?;
            let engine = conn.engine.clone();
            let raw_sql = query.clone();
            let cwd_str = cwd.display().to_string();
            let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
            let redact_db_errors = session.redact_db_errors();
            let outcome = (|| -> Result<Emitted, Failure> {
                // The very same layer 1 as `nyet query` — planning a write is
                // refused (exit 5) before anything is sent to the database.
                let (query, is_query, mut warnings) = validate(&query, &session.policy)?;
                // The verdict is informational here, but it is measured against this
                // connection's own guardrail, so `explain` answers exactly what
                // `query` would decide.
                let guardrail =
                    config::guardrail(&alias, conn).map_err(|e| config_failure(e, &path))?;

                // A metadata statement (SHOW/DESCRIBE, or an EXPLAIN the agent wrote
                // itself) has no plan to ask for: wrapping it in another EXPLAIN
                // would only earn a confusing syntax error from the server. Answer
                // that here — honestly, and without touching the database.
                let (plan, duration_ms) = match is_query {
                    true => {
                        let _tunnel = open_tunnel(conn, session.timeout_secs, &mut session.db)?;
                        run_db(redact_db_errors, session.db.estimate(&query))?
                    }
                    false => {
                        warnings.push(no_plan_warning());
                        (None, 0)
                    }
                };
                // No plan at all: either this was not a query, or planning outran
                // the guardrail's budget — `explain` runs the SAME budget as
                // `query`, so it cannot answer "ok" for a statement `query` would
                // refuse. Either way the verdict is `no_estimate` over an empty plan.
                let empty = plan.is_none();
                let plan = plan.unwrap_or_else(|| {
                    if is_query {
                        warnings.push(planning_too_slow_warning());
                    }
                    guardrail::CostEstimate {
                        plan: serde_json::Value::Array(Vec::new()),
                        cost: None,
                        rows: None,
                        lower_bound: false,
                    }
                });
                // The same honest note the query path gives when a plan carries no
                // number nyet can judge (a recursive CTE, an unreadable shape).
                if is_query
                    && !empty
                    && guardrail.plans()
                    && guardrail.check(&plan) == guardrail::Check::NoEstimate
                {
                    warnings.push(guardrail_skipped_warning());
                }
                let estimate = guardrail.describe(plan);

                if session.insecure_transport {
                    warnings.push(insecure_transport_warning());
                }
                let meta = output::ExplainMeta {
                    duration_ms,
                    connection: alias.clone(),
                };
                let (data, envelope) = match format {
                    Format::Table => (
                        output::explain_text(&estimate),
                        output::explain_meta_json(&meta, &warnings),
                    ),
                    // Only Json remains: jsonl/csv were degraded to json above.
                    _ => (
                        String::new(),
                        output::explain_json(&estimate, &meta, &warnings),
                    ),
                };
                let warning_codes = warnings.iter().map(|w| w.code).collect();
                let response =
                    log_responses.then(|| audit::Response::Payload(payload_value(&estimate)));
                Ok(Emitted {
                    data,
                    envelope,
                    duration_ms,
                    row_count: None,
                    truncated: None,
                    warnings: warning_codes,
                    response,
                })
            })();
            audit_finish(
                &cfg,
                AuditMeta {
                    command: "explain",
                    alias: &alias,
                    engine: &engine,
                    cwd: &cwd_str,
                    sql: Some(&raw_sql),
                    table: None,
                },
                format,
                outcome,
            )
        }
        Command::Doctor { alias, format: _ } => {
            // doctor is the human's setup tool: it exits 0 whenever it ran, with
            // the per-check verdicts in the envelope (a failed connect is a
            // `fail` check, not exit 6 — diagnosing that is the whole point). The
            // only non-zero exits are the config-level ones already handled above
            // (config unreadable / unknown alias -> 3, unsupported engine -> 1).
            let permissions = config_permissions(&path);
            // Only the per-connection path (Some alias) contacts a database, so
            // only it is audited; `nyet doctor` with no alias is config-level
            // (no db) and is not logged. Carries (alias, engine) when auditable.
            let mut audit_id: Option<(String, String)> = None;
            let (checks, meta) = match alias {
                None => {
                    // No alias: config-file permissions plus the connections
                    // reachable from here (directory scoping applies to the
                    // listing only — a named alias is diagnosed regardless).
                    let aliases: Vec<String> = cfg
                        .connections
                        .iter()
                        .filter(|(_, conn)| allowed(conn))
                        .map(|(a, _)| a.clone())
                        .collect();
                    (
                        output::doctor_config_checks(&permissions, &aliases),
                        output::DoctorMeta {
                            connection: None,
                            duration_ms: 0,
                        },
                    )
                }
                Some(alias) => {
                    // A named connection is diagnosed regardless of directory
                    // scoping (the human owns the config and is testing it, quite
                    // possibly not yet in the project dir).
                    let conn = lookup_alias(&cfg, &path, &alias)?;
                    let timeout_secs = cfg.timeout_secs(conn, None);
                    let (mut db, _policy) = build_engine(&alias, conn, timeout_secs)?;
                    audit_id = Some((alias.clone(), conn.engine.clone()));
                    let (mut diagnosis, duration_ms) =
                        diagnose_connection(conn, timeout_secs, &mut db)?;
                    // doctor never goes through run_db/engine_failure, so the
                    // redaction has to be applied to the FACTS it collected:
                    // ConnectFact::Failed and the probe `detail` carry the
                    // driver's verbatim message (finding 8). The promise in
                    // README/DESIGN is unconditional, so it holds here too.
                    if !config::pii(&alias, conn)
                        .map_err(|e| config_failure(e, &path))?
                        .is_empty()
                    {
                        redact_diagnosis(&mut diagnosis);
                    }
                    let input = output::DoctorInput {
                        engine: engine_kind(&conn.engine),
                        diagnosis,
                        transport: doctor_transport(conn),
                        permissions,
                    };
                    (
                        output::doctor_checks(&input),
                        output::DoctorMeta {
                            connection: Some(alias),
                            duration_ms,
                        },
                    )
                }
            };
            let (data, envelope) = match format {
                Format::Table => (
                    output::doctor_text(&checks),
                    output::doctor_meta_json(&meta),
                ),
                // Only Json remains (doctor accepts json|table only).
                _ => (String::new(), output::doctor_json(&checks, &meta)),
            };
            match audit_id {
                Some((alias, engine)) => {
                    let cwd_str = cwd.display().to_string();
                    let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
                    let response =
                        log_responses.then(|| audit::Response::Payload(payload_value(&checks)));
                    let emitted = Emitted {
                        data,
                        envelope,
                        duration_ms: meta.duration_ms,
                        row_count: None,
                        truncated: None,
                        warnings: Vec::new(),
                        response,
                    };
                    audit_finish(
                        &cfg,
                        AuditMeta {
                            command: "doctor",
                            alias: &alias,
                            engine: &engine,
                            cwd: &cwd_str,
                            sql: None,
                            table: None,
                        },
                        format,
                        Ok(emitted),
                    )
                }
                None => emit(format, &data, &envelope).map_err(output_write_failure),
            }
        }
        // Handled by the short-circuit at the top of run() (before the config
        // read), so this arm is dead — it exists only for match exhaustiveness.
        Command::AgentSetup { .. } => unreachable!("agent-setup is short-circuited above"),
    }
}

/// Generate the SKILL.md and emit it (DESIGN §1 stream routing). Markdown is a
/// data format — the document on stdout, the envelope one JSON line on stderr;
/// `--format json` puts the whole SKILL.md in the envelope's `skill` field on
/// stdout. Never fails on config (agent_setup degrades) — only a stdout write
/// failure (Internal, exit 1) can error, like every other command.
fn agent_setup(
    config_flag: Option<PathBuf>,
    format: SetupFormat,
    route_format: &mut Format,
) -> Result<(), Failure> {
    let connections = load_connections(config_flag);
    let text = skill::skill(&connections);
    match format {
        SetupFormat::Markdown => {
            // Markdown routes like the other data formats (table/csv/jsonl):
            // data on stdout, envelope on stderr. Reuse emit — the single owner
            // of stream routing and broken-pipe handling.
            *route_format = Format::Table;
            emit(Format::Table, &text, &output::bare_success()).map_err(output_write_failure)
        }
        SetupFormat::Json => {
            *route_format = Format::Json;
            emit(Format::Json, "", &output::skill_json(&text)).map_err(output_write_failure)
        }
    }
}

/// Best-effort load of the connections reachable from cwd (consistent with
/// `nyet list`), for the skill's dynamic section. Any failure to locate, read
/// or parse the config, or to resolve cwd, degrades to `Unavailable` — a hint,
/// not an exit-3 error: teaching the agent must work before any setup.
fn load_connections(config_flag: Option<PathBuf>) -> skill::Connections {
    let Ok(path) = config_path(config_flag) else {
        return skill::Connections::Unavailable;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return skill::Connections::Unavailable;
    };
    let Ok(cfg) = config::parse(&text, &|name: &str| std::env::var(name)) else {
        return skill::Connections::Unavailable;
    };
    let Ok(cwd) = std::env::current_dir().and_then(|d| d.canonicalize()) else {
        return skill::Connections::Unavailable;
    };
    let home = home_dir();
    let canon = |p: &Path| std::fs::canonicalize(p).ok();
    let conns = cfg
        .connections
        .iter()
        .filter(|(_, conn)| resolver::is_allowed(&cwd, &conn.allowed_dirs, home.as_deref(), &canon))
        .map(|(alias, conn)| skill::Conn {
            alias: alias.clone(),
            engine: conn.engine.clone(),
        })
        .collect();
    skill::Connections::Available(conns)
}

/// Layer 1 for both `query` and `explain`: any deny -> NYET + reason (exit 5),
/// so an EXPLAIN over a write is refused exactly like the write itself
/// (consistently fail closed). Returns the NORMALIZED text — what the validator
/// actually classified; running anything else would reopen the gap Unicode
/// stripping closes — plus whether it is a plain query and its warnings.
fn validate(
    query: &str,
    policy: &validator::Policy,
) -> Result<(String, bool, Vec<output::Warning>), Failure> {
    match validator::validate(query, policy) {
        validator::Verdict::Deny {
            reason,
            message,
            hint,
        } => Err(refusal_failure(validator::Refusal {
            reason,
            message,
            hint,
        })),
        validator::Verdict::Allow {
            sql,
            warnings,
            is_query,
        } => Ok((
            sql,
            is_query,
            warnings
                .into_iter()
                .map(|w| output::Warning {
                    code: w.code,
                    message: w.message,
                })
                .collect(),
        )),
    }
}

/// One validator refusal -> one NYET failure (exit 5).
fn refusal_failure(r: validator::Refusal) -> Failure {
    Failure::new(ErrorCode::Nyet(r.reason.as_str()), r.message, r.hint)
}

/// The guardrail asked for a plan and got nothing it could judge. Д10 — what
/// happened, why, what to do instead. Shared by `query` (which then ran the
/// query unguarded) and `explain` (whose verdict is `no_estimate` for the very
/// same reason), so the agent is never left guessing why there is no number.
fn guardrail_skipped_warning() -> output::Warning {
    output::Warning {
        code: "GUARDRAIL_SKIPPED",
        message: "the guardrail has no estimate it can trust for this query: the planner \
                  does not bound a recursive CTE (its cost/rows are a LOWER bound, so only \
                  a plan already over the limit can be refused), and some plan shapes are \
                  unreadable — so this query was not checked against the connection's \
                  limit; bound it yourself with WHERE/LIMIT or a smaller --timeout"
            .to_string(),
    }
}

/// `nyet explain` could not get a plan inside the guardrail's budget. The same
/// code as the other "no verdict" cases (the contract list is closed), a
/// different story — and it says what `nyet query` would do with this statement.
fn planning_too_slow_warning() -> output::Warning {
    output::Warning {
        code: "GUARDRAIL_SKIPPED",
        message: "planning this statement outran the guardrail's budget, so there is no plan \
                  to show and no verdict to give — nyet query would refuse it for exactly \
                  that reason (EXPENSIVE_QUERY); simplify the statement (fewer joins, fewer \
                  computed expressions)"
            .to_string(),
    }
}

/// `nyet explain` was handed something that is not a query.
fn no_plan_warning() -> output::Warning {
    output::Warning {
        code: "NO_PLAN",
        message: "SHOW/DESCRIBE and an EXPLAIN you wrote yourself are metadata statements, \
                  not queries: there is no plan to estimate, so nothing was asked of the \
                  database — run the statement with nyet query <alias> <statement> to get \
                  its result"
            .to_string(),
    }
}

/// What the three database commands set up identically, in the order tests pin:
/// alias -> directory scoping -> engine support / connection config. Scoping
/// answers before the validator (a denied directory gets exit 4, not a SQL
/// lecture), and so does engine support (an unsupported engine gets
/// NOT_IMPLEMENTED, not a NYET with a misleading SQL hint).
struct Session {
    db: Db,
    /// The engine's validator policy; `schema` ignores it (no agent SQL).
    policy: validator::Policy,
    /// Flag > per-connection > [defaults] > built-in. Resolved before the engine
    /// because Postgres feeds it into the server-side statement_timeout at
    /// connect time.
    timeout_secs: u64,
    insecure_transport: bool,
}

impl Session {
    /// The ONE answer to "may this connection show raw database error text?".
    /// It used to be re-derived in each command body, and `doctor` — which
    /// builds its engine without a Session — simply missed it (finding 8).
    fn redact_db_errors(&self) -> bool {
        !self.policy.pii().is_empty()
    }
}

fn open_session<'a>(
    cfg: &'a config::Config,
    path: &Path,
    alias: &str,
    cwd: &Path,
    allowed: &dyn Fn(&config::Connection) -> bool,
    timeout_flag: Option<u64>,
) -> Result<(&'a config::Connection, Session), Failure> {
    let conn = lookup_alias(cfg, path, alias)?;
    check_scope(alias, conn, cwd, allowed(conn))?;
    let timeout_secs = cfg.timeout_secs(conn, timeout_flag);
    let (mut db, policy) = build_engine(alias, conn, timeout_secs)?;
    // The PII policy is resolved here (once) and lives inside the validator
    // Policy: net A reads it during validation, and the cli reads it back for
    // net B and for the database-error redaction.
    let pii = config::pii(alias, conn).map_err(|e| config_failure(e, path))?;
    if !pii.is_empty() {
        db.resolve_column_origins();
    }
    Ok((
        conn,
        Session {
            db,
            policy: policy.with_pii(pii),
            timeout_secs,
            insecure_transport: insecure_transport(conn),
        },
    ))
}

/// Run one database operation on the lazily built runtime and report the wall
/// time it took (`meta.duration_ms` — the whole database phase, the guardrail's
/// EXPLAIN included).
///
/// The engine owns BOTH of its deadlines internally: a hung/slow CONNECT is
/// bounded by its own generous one (-> exit 6) and only the query phase by the
/// effective per-query timeout (-> exit 8), which keeps the exit code
/// deterministic even when `--timeout` is smaller than a legitimate connect.
fn run_db<T>(
    redact_db_errors: bool,
    operation: impl std::future::Future<Output = Result<T, engine::EngineError>>,
) -> Result<(T, u64), Failure> {
    let rt = runtime()?;
    let started = Instant::now();
    let result = rt.block_on(operation);
    // After a query timeout the sqlite worker may still be grinding; a
    // background shutdown lets the process exit instead of joining it.
    rt.shutdown_background();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok((
        result.map_err(|e| engine_failure(e, redact_db_errors))?,
        duration_ms,
    ))
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
                    // Turned on by open_session when the connection has a PII
                    // policy; off here so a connection without one pays nothing.
                    resolve_column_origins: false,
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
fn engine_failure(e: engine::EngineError, redact_db_errors: bool) -> Failure {
    match e {
        engine::EngineError::Connect { message, hint } => {
            Failure::new(ErrorCode::ConnectionFailed, message, hint)
        }
        engine::EngineError::Db { .. } if redact_db_errors => db_error_withheld(),
        engine::EngineError::Db { message, hint } => {
            Failure::new(ErrorCode::DbError, message, hint)
        }
        engine::EngineError::Timeout { message, hint } => {
            Failure::new(ErrorCode::Timeout, message, hint)
        }
    }
}

/// The `doctor` twin of `db_error_withheld`: replace the verbatim server text
/// in the facts that were produced by RUNNING A STATEMENT. The VERDICTS are
/// untouched — which check failed, and whether the role is read-only, is
/// diagnosis, not data.
///
/// `ConnectFact::Failed` is deliberately LEFT ALONE, for symmetry with
/// `engine_failure`, which also passes `EngineError::Connect` through verbatim
/// on a PII connection: a refused handshake ("password authentication failed
/// for user ...") happens before any row exists and cannot quote a cell, while
/// doctor's whole job is telling the human honestly why the connection is
/// broken. Only the write PROBE runs a statement against real data, so only its
/// `detail` can carry a server message about values.
fn redact_diagnosis(diagnosis: &mut output::Diagnosis) {
    const WITHHELD: &str = "details withheld by this connection's PII policy (a database \
                            message can quote cell values); see the database's own log";
    if let Some(server) = &mut diagnosis.server {
        match &mut server.probe {
            output::ProbeFact::Blocked { detail, .. } | output::ProbeFact::Unknown { detail } => {
                *detail = WITHHELD.to_string()
            }
            output::ProbeFact::Wrote { .. } => {}
        }
    }
}

/// A connection with a PII policy never hands the RAW database error text to the
/// agent. PostgreSQL and MySQL quote the offending CELL VALUE in their messages
/// — `SELECT email::int FROM users` answers *invalid input syntax for type
/// integer: "alice@example.com"* — which is an exfiltration channel one cell per
/// query, straight past every filter on the result. Filtering the text with
/// patterns would be theatre (UX-7): the whole message is withheld, and the
/// agent is told where the real one lives (Д10). Connections without a PII
/// policy are untouched — they keep the verbatim, actionable error.
fn db_error_withheld() -> Failure {
    Failure::new(
        ErrorCode::DbError,
        "the database rejected this query; its error text is withheld because this \
         connection has a PII policy, and a database error message can quote the very \
         cell values that caused it",
        "check the query against the real schema with `nyet schema <alias>` (types and \
         column names are not withheld), and simplify it one clause at a time to find \
         what the database dislikes; the full server message is in the database's own \
         log — ask whoever owns this connection if you need it",
    )
}

/// The flag the user passed on `--format` (if any), normalized to `Format`.
fn command_format_flag(command: &Command) -> Option<Format> {
    match command {
        Command::List { format } => format.map(PlainFormat::as_format),
        Command::Schema { format, .. }
        | Command::Explain { format, .. }
        | Command::Doctor { format, .. } => format.map(PlainFormat::as_format),
        Command::Query { format, .. } => *format,
        // agent-setup has its own format enum and sets its routing itself; the
        // value here is unused (it short-circuits run() before any error path).
        Command::AgentSetup { .. } => None,
    }
}

/// The default output format per command: `table` for `doctor` (the one
/// human-facing command), `json` for everything else (the agent contract).
fn default_format(command: &Command) -> Format {
    match command {
        Command::Doctor { .. } => Format::Table,
        // Markdown default routes like a data format (stderr envelope);
        // agent_setup overrides this before any error path anyway.
        Command::AgentSetup { .. } => Format::Table,
        _ => Format::Json,
    }
}

/// The `engine` string -> the pure doctor `EngineKind`. Called only after
/// `build_engine` succeeded, so the value is one of the four supported engines.
fn engine_kind(engine: &str) -> output::EngineKind {
    match engine {
        "sqlite" => output::EngineKind::Sqlite,
        "postgres" => output::EngineKind::Postgres,
        // mysql | mariadb — one driver, one dialect.
        _ => output::EngineKind::Mysql,
    }
}

/// The transport guarantee for doctor, from config + url only (no round-trip):
/// an ssh tunnel encrypts the hop, a direct url at `require`+ enforces TLS,
/// anything below that is not guaranteed encrypted, and SQLite has no transport.
fn doctor_transport(conn: &config::Connection) -> output::Transport {
    if conn.engine == "sqlite" {
        return output::Transport::Na;
    }
    if conn.ssh.is_some() {
        return output::Transport::Tunnel;
    }
    if insecure_transport(conn) {
        output::Transport::InsecureDirect
    } else {
        output::Transport::TlsDirect
    }
}

/// The config-file permission fact for doctor, from the file mode (unix only).
fn config_permissions(path: &Path) -> output::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path) {
            Ok(md) => match config::permissions_warning(md.mode(), "the config file") {
                Some(message) => output::Permissions::Loose(message),
                None => output::Permissions::Secure,
            },
            Err(_) => output::Permissions::Na,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        output::Permissions::Na
    }
}

/// Open the tunnel (if any) and run the engine's diagnosis, returning the facts
/// and the wall time. A tunnel failure is captured as a connectivity FACT (a
/// `fail` check, exit 0) — not exit 6 — because doctor exists to diagnose a
/// broken connection.
fn diagnose_connection(
    conn: &config::Connection,
    timeout_secs: u64,
    db: &mut Db,
) -> Result<(output::Diagnosis, u64), Failure> {
    let started = Instant::now();
    let elapsed =
        |started: Instant| u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let _tunnel = match open_tunnel(conn, timeout_secs, db) {
        Ok(tunnel) => tunnel,
        Err(f) => {
            return Ok((
                output::Diagnosis {
                    connect: output::ConnectFact::Failed {
                        message: f.message,
                        hint: f.hint,
                    },
                    server: None,
                },
                elapsed(started),
            ));
        }
    };
    let rt = runtime()?;
    let diagnosis = rt.block_on(db.diagnose());
    // A slow/abandoned probe future must not join a busy worker on exit.
    rt.shutdown_background();
    Ok((diagnosis, elapsed(started)))
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
        config::ConfigError::EnvVarInPolicy { alias, key, value } => (
            format!(
                "config file {}: {key} value \"{value}\" for connection '{alias}' uses \
                 ${{VAR}} substitution",
                path.display()
            ),
            format!(
                "{key} must be a literal value; ${{VAR}} substitution is not allowed in \
                 policy settings (allowed_dirs, validator.allow_functions / deny_functions, \
                 guardrail.mode, pii.columns) because the environment is controlled by the \
                 calling agent — it could otherwise widen its own scope, un-deny a function, \
                 switch the guardrail off or unprotect a PII column"
            ),
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
        config::ConfigError::GuardrailInvalid { alias, message } => (
            format!(
                "config file {}: connection '{alias}' has an invalid [guardrail] section: {message}",
                path.display()
            ),
            format!(
                "set [connections.{alias}.guardrail] mode to \"cost\", \"rows\" or \"off\" \
                 (which modes an engine supports depends on what its planner publishes — \
                 see the README), with max_cost / max_rows as positive numbers"
            ),
        ),
        config::ConfigError::SshInvalid { alias, message } => (
            format!("config file {}: connection '{alias}' has an invalid [ssh] value: {message}", path.display()),
            "fix the [ssh] host/remote/control_persist; host is [user@]hostname[:port] and \
             remote is host:port with safe characters — values that could be read as ssh \
             options (a leading '-', or a ${VAR} that expands to one) are rejected"
                .to_string(),
        ),
        config::ConfigError::PiiRuleInvalid { alias, message } => (
            format!(
                "config file {}: connection '{alias}' has an invalid [pii] rule: {message}",
                path.display()
            ),
            format!(
                "each entry of [connections.{alias}.pii] columns names one column as \
                 \"table.column\" (or \"schema.table.column\"), e.g. \
                 columns = [\"users.email\", \"users.phone\"]; matching is \
                 case-insensitive and any schema qualifier is ignored"
            ),
        ),
        config::ConfigError::AuditPathEnvVar { value } => (
            format!(
                "config file {}: [audit] path \"{value}\" uses ${{VAR}} substitution",
                path.display()
            ),
            "audit.path must be a literal value; ${VAR} substitution is not allowed because \
             the environment is controlled by the calling agent — it could otherwise redirect \
             or silence its own audit trail. Write the absolute path literally (the default \
             ~/.local/share/nyet/audit.jsonl resolves from the agent-controlled \
             XDG_DATA_HOME/HOME, so an explicit literal path is what an agent cannot redirect)"
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

/// A file readable by group/others -> human warning on stderr (not a refusal).
/// Shared by the config file and the audit log (both may hold credentials/the
/// agent's SQL); like the config, we WARN, we do not chmod. Only an EXISTING
/// loose file warns — one nyet creates itself is 0600 from birth.
fn warn_loose_permissions(path: &Path, what: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata(path) {
            if let Some(warning) = config::permissions_warning(md.mode(), what) {
                let _ = writeln!(std::io::stderr(), "warning: {}: {warning}", path.display());
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, what);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round 2, finding H: the PII redaction covers the fact a STATEMENT
    /// produced (the write probe's server message) and deliberately leaves the
    /// connect diagnosis alone — a refused handshake cannot quote a cell, and
    /// doctor's whole job is saying honestly why the connection is broken.
    #[test]
    fn redact_diagnosis_hides_probe_detail_but_not_the_connect_reason() {
        let mut d = output::Diagnosis {
            connect: output::ConnectFact::Failed {
                message: "password authentication failed for user \"nyet_ro\"".to_string(),
                hint: "h".to_string(),
            },
            server: None,
        };
        redact_diagnosis(&mut d);
        match &d.connect {
            output::ConnectFact::Failed { message, .. } => {
                assert!(message.contains("authentication"), "{message}")
            }
            _ => panic!("connect fact replaced"),
        }
        // The probe DOES run a statement against real data, so its detail goes.
        let mut d = output::Diagnosis {
            connect: output::ConnectFact::Ok { via_tunnel: false },
            server: Some(output::ServerFacts {
                read_only_note: None,
                probe: output::ProbeFact::Unknown {
                    detail: "value \"alice@example.com\" out of range".to_string(),
                },
                superuser: output::SuperuserFact::Unknown("x".to_string()),
            }),
        };
        redact_diagnosis(&mut d);
        let Some(server) = &d.server else {
            panic!("server facts dropped")
        };
        match &server.probe {
            output::ProbeFact::Unknown { detail } => {
                assert!(detail.contains("withheld"), "{detail}");
                assert!(!detail.contains("alice@example.com"), "{detail}");
            }
            _ => panic!("probe fact replaced"),
        }
    }

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
