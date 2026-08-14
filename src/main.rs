//! cli layer: clap, orchestration, all IO, exit codes. The "лапша" lives
//! here and only here; config/resolver/output stay pure.

#![forbid(unsafe_code)]

// The modules live in the lib target (src/lib.rs) so the fuzz targets can link
// against them; this binary is just their cli layer.
use nyetdb::{
    audit, config, engine, guardrail, mongo, output, resolver, sample, secret, skill, tunnel,
    validator,
};

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
    /// Path to config file (the human who owns the setup knows where it lives)
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
    /// Show a few rows of one table, to see what the data actually looks like
    ///
    /// Sugar over `nyet query`: nyet writes the statement itself (a random draw
    /// of 10 rows) and runs it through the very same pipeline, so the validator,
    /// the guardrail and the PII policy judge it exactly as they would judge
    /// your own SQL. If the guardrail refuses the random draw as too expensive,
    /// nyet retries with the first N rows and says so (warning SAMPLE_FALLBACK).
    ///
    /// Examples:
    ///   nyet sample prod users               # 10 rows, drawn at random
    ///   nyet sample prod users --limit 3
    ///   nyet sample prod sales.orders        # PostgreSQL: outside the public schema
    ///   nyet sample events users             # MongoDB: a collection, same command
    // verbatim: see the Schema arm — the examples are the point (UX-3).
    #[command(verbatim_doc_comment)]
    Sample {
        /// Connection alias from the config
        alias: String,
        /// The table, view or collection to sample (PostgreSQL: `schema.table`
        /// outside public)
        table: String,
        /// Output format (default: [defaults].format from the config, then json)
        #[arg(long, value_enum)]
        format: Option<Format>,
        /// Max rows to return (default: 10, at most 1000000 — ask for a table,
        /// not a sample, with `nyet query`)
        // A sample is a handful of rows by definition, and the number lands in
        // the statement nyet writes: without a ceiling here, `--limit
        // 9223372036854775807` reaches the database as a LIMIT it cannot read
        // and comes back as a DB_ERROR about text the agent never wrote (Д10).
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..=1_000_000))]
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

    /// Store a secret in the macOS Keychain so that only nyet can read it
    ///
    /// The value is read from stdin (the terminal does not echo it) and stored
    /// under the name a connection refers to:
    ///
    ///   password = { keychain = "prod-db" }
    ///
    /// nyet stores the item ITSELF on purpose: the application that creates a
    /// keychain item is the one its ACL trusts, so an item made with
    /// `security` or Keychain Access would be readable by those tools — and by
    /// anything else running as you, the agent included.
    ///
    /// Run it again after installing a new nyet: the item trusts the exact
    /// binary that created it, and a fresh build is a different one. macOS
    /// asks for your keychain password when handing the item over, which is
    /// the barrier an agent cannot pass.
    #[command(verbatim_doc_comment)]
    SecretSet {
        /// Item name, as written in the connection's `{ keychain = "..." }`
        item: String,
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
    Mongo(engine::Mongo),
}

impl Db {
    /// Which layer 1 applies. MongoDB is not SQL: it has its own pure
    /// parser+allowlist (`src/mongo.rs`), so the cli picks the validator by
    /// engine rather than handing mongosh text to sqlparser.
    fn is_mongo(&self) -> bool {
        matches!(self, Db::Mongo(_))
    }

    /// The connection url as it will actually be dialed — resolved, since it
    /// may have come from a keychain item rather than the config text. SQLite
    /// has none (it is a local file).
    fn url(&self) -> &str {
        match self {
            Db::Sqlite(_) => "",
            Db::Postgres(pg) => &pg.url,
            Db::Mysql(my) => &my.url,
            Db::Mongo(mg) => &mg.url,
        }
    }

    /// The ONE way rows leave the engine layer — and therefore the one place
    /// net B (PII provenance) is applied, refusal AND masking alike. Putting it
    /// here rather than in a command body means a future rows-returning command
    /// cannot inherit the hole by forgetting to call it (finding 6);
    /// `QueryOutcome::PiiRefused` then forces every caller to handle the
    /// refusal, and the masked names it returns are the material for the
    /// `PII_MASKED` warning (the agent must know it is looking at a mask, UX-2).
    ///
    /// The rows are redacted HERE, before anything downstream exists: the
    /// formatters, the audit response and `meta` all read the same masked
    /// `ResultSet`, so no path can serialize a raw protected value.
    async fn execute(
        &self,
        sql: &str,
        fetch_limit: u64,
        guardrail: &guardrail::Guardrail,
        pii: &validator::PiiRules,
        pii_exempt: &[usize],
    ) -> Result<(engine::QueryOutcome, Vec<String>), engine::EngineError> {
        let mut outcome = match self {
            Db::Sqlite(e) => e.execute(sql, fetch_limit, guardrail).await,
            Db::Postgres(e) => e.execute(sql, fetch_limit, guardrail).await,
            Db::Mysql(e) => e.execute(sql, fetch_limit, guardrail).await,
            Db::Mongo(e) => e.execute(sql, fetch_limit, guardrail).await,
        }?;
        let mut masked = Vec::new();
        if let engine::QueryOutcome::Ran { result, .. } = &mut outcome {
            if self.is_mongo() {
                // MongoDB's net B is a scan of the documents themselves (they
                // are self-describing; there is no provenance to ask for, and
                // `check_origins` on all-Unknown origins would refuse
                // everything). See mongo::scan_reply.
                if !pii.is_empty() {
                    match mongo::scan_reply(sql, pii, &result.columns, &mut result.rows) {
                        Err(r) => {
                            return Ok((
                                engine::QueryOutcome::PiiRefused(Box::new(mongo_pii_refusal(r))),
                                Vec::new(),
                            ))
                        }
                        Ok(fields) => masked = fields,
                    }
                }
            } else {
                match validator::check_origins(pii, &result.columns, &result.origins, pii_exempt) {
                    Err(refusal) => {
                        return Ok((
                            engine::QueryOutcome::PiiRefused(Box::new(refusal)),
                            Vec::new(),
                        ))
                    }
                    Ok(indexes) => {
                        masked = indexes
                            .iter()
                            .map(|i| result.columns[*i].clone())
                            .collect::<Vec<_>>();
                        output::redact(&mut result.rows, &indexes);
                    }
                }
            }
        }
        Ok((outcome, masked))
    }

    async fn estimate(
        &self,
        sql: &str,
    ) -> Result<Option<guardrail::CostEstimate>, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.estimate(sql).await,
            Db::Postgres(e) => e.estimate(sql).await,
            Db::Mysql(e) => e.estimate(sql).await,
            Db::Mongo(e) => e.estimate(sql).await,
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
            // MongoDB also forces `directConnection` from this: without it the
            // driver would discover the replica set's real members and go
            // straight to them, around the bastion (see engine::Mongo::open).
            Db::Mongo(mg) => mg.host_override = Some(over),
            Db::Sqlite(_) => {}
        }
    }

    /// Shrink the per-query budget for the NEXT statement — `sample`'s fallback
    /// runs on what its refused first attempt left of the owner's timeout, not
    /// on a fresh one. Server-side and in-process bounds move together, since
    /// both engines that have a fallback arm the server at connect time and
    /// `execute` connects per statement — through the engines' OWN clamps, so
    /// what a server will not accept is refused in one place, not two (a raw
    /// `statement_timeout` past INT_MAX makes the retry fail to connect at all).
    /// Exhaustive: a future engine that keeps a budget of its own must say so.
    fn set_query_timeout_ms(&mut self, ms: u64) {
        match self {
            Db::Sqlite(e) => e.query_timeout_ms = ms,
            Db::Postgres(e) => {
                e.query_timeout_ms = ms;
                e.statement_timeout_ms = engine::Postgres::clamp_statement_timeout(ms);
            }
            Db::Mysql(e) => {
                e.query_timeout_ms = ms;
                e.statement_timeout_ms = engine::Mysql::clamp_statement_timeout(ms);
            }
            Db::Mongo(e) => e.query_timeout_ms = ms,
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
            // MongoDB needs no origins: its net B scans the self-describing
            // result documents instead (see mongo::scan_reply in Db::execute).
            Db::Mysql(_) | Db::Sqlite(_) | Db::Mongo(_) => {}
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<output::Schema, engine::EngineError> {
        match self {
            Db::Sqlite(e) => e.schema(table).await,
            Db::Postgres(e) => e.schema(table).await,
            Db::Mysql(e) => e.schema(table).await,
            Db::Mongo(e) => e.schema(table).await,
        }
    }

    async fn diagnose(&self, pii: &[(String, String)]) -> output::Diagnosis {
        match self {
            Db::Sqlite(e) => e.diagnose(pii).await,
            Db::Postgres(e) => e.diagnose(pii).await,
            Db::Mysql(e) => e.diagnose(pii).await,
            Db::Mongo(e) => e.diagnose(pii).await,
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
    // Same reasoning: storing a secret is about the keychain, not about any
    // connection, so it must work before (and independently of) a config.
    if let Command::SecretSet { item } = &cli.command {
        return secret_set(item);
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

    let cfg = config::parse(&text, &|name: &str| std::env::var(name)).map_err(config_failure)?;

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
        } => rows_command(
            &cfg,
            &cwd,
            &allowed,
            RowsRequest {
                alias,
                source: RowSource::Query(query),
                format,
                limit,
                timeout,
            },
        ),
        Command::Sample {
            alias,
            table,
            format: _,
            limit,
            timeout,
        } => rows_command(
            &cfg,
            &cwd,
            &allowed,
            RowsRequest {
                alias,
                source: RowSource::Sample(table),
                format,
                limit,
                timeout,
            },
        ),
        Command::Schema {
            alias,
            table,
            format: _,
        } => {
            // The same setup as query, minus the validator and the guardrail
            // (there is no agent SQL here, and a catalog read has nothing to
            // estimate).
            let (conn, mut session) = open_session(&cfg, &alias, &cwd, &allowed, None)?;
            let is_mongo = session.db.is_mongo();
            let engine = conn.engine.clone();
            let cwd_str = cwd.display().to_string();
            let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
            let redact_db_errors = session.redact_db_errors();
            let outcome = (|| -> Result<Emitted, Failure> {
                let _tunnel = open_tunnel(conn, session.timeout_secs, &mut session.db)?;
                let (mut schema, duration_ms) =
                    run_db(redact_db_errors, session.db.schema(table.as_deref()))?;
                // The policy is config, so the marking happens here and not in
                // the engines: they only report what the catalog (already
                // privilege-filtered) holds. MongoDB's rules protect a field
                // NAME at any depth, so a dotted path is marked when any of its
                // segments is protected — the same match nets A and B apply.
                let pii = session.policy.pii();
                if !pii.is_empty() {
                    output::mark_pii(&mut schema, pii.mode().as_str(), |t, c| match is_mongo {
                        // MongoDB's rule protects a field NAME at any depth, so
                        // a dotted path is marked when any segment is protected.
                        true => c.split('.').any(|segment| pii.protects(t, segment)),
                        false => pii.protects(t, c),
                    })
                }

                // An explicit [table] that matched nothing: the catalog answered,
                // the object simply is not there. DB_ERROR (exit 7) with the way
                // out (Д10) — no new error code for it.
                if let Some(name) = &table {
                    if schema.tables.is_empty() {
                        let what = if is_mongo { "collection" } else { "table" };
                        // MongoDB answers `listCollections` per ROLE: a name
                        // the role may not see comes back exactly like a name
                        // that does not exist, and nyet must not claim to know
                        // which (UX-7 — the SQL catalogs are privilege-filtered
                        // the same way, but there `nyet schema` is the only
                        // reader and the distinction never came up).
                        let missing = match is_mongo {
                            true => format!(
                                "collection '{name}' not found in {alias} (or not visible to \
                                 this connection's role)"
                            ),
                            false => format!("table '{name}' not found in {alias}"),
                        };
                        return Err(Failure::new(
                            ErrorCode::DbError,
                            missing,
                            format!("run nyet schema {alias} to list available {what}s"),
                        ));
                    }
                }

                let mut warnings: Vec<output::Warning> = Vec::new();
                if schema.is_listing() {
                    warnings.push(match is_mongo {
                        // Not a truncation for the same reason: MongoDB cannot
                        // describe a collection without sampling it, so the
                        // listing lists (one round trip) and the agent asks
                        // about the one it cares about. Same contract code —
                        // "you got names only" is what it means (Д7).
                        true => output::Warning {
                            code: "SCHEMA_TRUNCATED",
                            message: format!(
                                "names and kinds only: MongoDB has no schema to list, so \
                                 describing a collection means SAMPLING it — run nyet schema \
                                 {alias} <collection> for one collection's fields, indexes and \
                                 document count"
                            ),
                        },
                        false => output::Warning {
                            code: "SCHEMA_TRUNCATED",
                            message: format!(
                                "schema listing truncated to names: {} objects exceed the {}-object \
                                 detail limit; run nyet schema {alias} <table> for one table's details",
                                schema.tables.len(),
                                output::DETAIL_LIMIT
                            ),
                        },
                    });
                }
                // The provenance marker is not decoration: everything a
                // MongoDB answer says about FIELDS is either the collection's
                // own declared validator or nyet's guess from a sample, and an
                // agent that reads a guess as a schema will write queries
                // against fields that most documents do not have (UX-1/UX-7).
                if let Some(sampled) = schema.tables.first().and_then(|t| t.sampled) {
                    warnings.push(sampled_schema_warning(sampled));
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
            let (conn, mut session) = open_session(&cfg, &alias, &cwd, &allowed, None)?;
            let is_mongo = session.db.is_mongo();
            let engine = conn.engine.clone();
            let raw_sql = query.clone();
            let cwd_str = cwd.display().to_string();
            let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
            let redact_db_errors = session.redact_db_errors();
            let outcome = (|| -> Result<Emitted, Failure> {
                // The very same layer 1 as `nyet query` — planning a write is
                // refused (exit 5) before anything is sent to the database.
                // `explain` returns a plan and no rows, so net B never runs and
                // the mask promise is irrelevant here (net A alone applies).
                // MongoDB brings its own layer 1 here too — `explain` must not
                // be the way past the allowlist, so the very same parser and
                // allowlist that refuse `db.c.aggregate([{$out: ...}])` for
                // `query` refuse it here, before any connect (exit 5).
                let (query, is_query, mut warnings, _) = match is_mongo {
                    true => validate_mongo(&query, session.policy.pii())?,
                    false => validate(&query, &session.policy)?,
                };
                // The verdict is informational here, but it is measured against this
                // connection's own guardrail, so `explain` answers exactly what
                // `query` would decide.
                let guardrail = config::guardrail(&alias, conn).map_err(config_failure)?;
                // `validate_mongo` answers `is_query = false` (the guardrail is
                // `off` for MongoDB and there is nothing to estimate), but a
                // MongoDB read DOES have a plan to show — one without a cost or
                // a row count, which is exactly what its `estimate` returns.
                let is_query = is_query || is_mongo;

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
                    let conn = lookup_alias(&cfg, &alias)?;
                    let timeout_secs = cfg.timeout_secs(conn, None);
                    let (mut db, _policy) = build_engine(&alias, conn, timeout_secs)?;
                    audit_id = Some((alias.clone(), conn.engine.clone()));
                    // The policy is needed twice here: the engine asks the
                    // server about these very columns, and the redaction below
                    // keys on "has a policy at all".
                    let pii = config::pii(&alias, conn).map_err(config_failure)?;
                    let pii_pairs: Vec<(String, String)> = pii
                        .pairs()
                        .map(|(t, c)| (t.to_string(), c.to_string()))
                        .collect();
                    let (mut diagnosis, duration_ms, forward) =
                        diagnose_connection(conn, timeout_secs, &mut db, &pii_pairs)?;
                    // doctor never goes through run_db/engine_failure, so the
                    // redaction has to be applied to the FACTS it collected:
                    // ConnectFact::Failed and the probe `detail` carry the
                    // driver's verbatim message (finding 8). The promise in
                    // README/DESIGN is unconditional, so it holds here too.
                    if !pii.is_empty() {
                        redact_diagnosis(&mut diagnosis);
                    }
                    let input = output::DoctorInput {
                        secret: conn.password.as_ref().map(secret_fact),
                        engine: engine_kind(&conn.engine),
                        diagnosis,
                        transport: doctor_transport(conn, db.url()),
                        forward,
                        permissions,
                        pii_mode: (!pii.is_empty()).then(|| pii.mode().as_str()),
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
        Command::SecretSet { .. } => unreachable!("secret-set is short-circuited above"),
    }
}

/// Where the statement of a rows-returning command comes from.
enum RowSource {
    /// `query`: the agent's own text, run exactly as written.
    Query(String),
    /// `sample`: the raw `[table]` argument. nyet writes the statement itself
    /// (`src/sample.rs`) and then runs it as if the agent had written it —
    /// which is the entire difference between the two commands.
    Sample(String),
}

/// What `query` and `sample` hand to the shared pipeline.
struct RowsRequest {
    alias: String,
    source: RowSource,
    format: Format,
    limit: Option<u64>,
    timeout: Option<u64>,
}

/// The rows-returning pipeline, shared by `query` and `sample`: layer 1, the
/// guardrail, the engine (net B inside `Db::execute`), the row limit, the
/// formatters, and ONE audit record written before anything is released
/// (UX-8).
///
/// `sample` differs in exactly four places, all of them here: the statement is
/// nyet's own, its default limit is small, a guardrail refusal earns one
/// cheaper second attempt, and the texts that would otherwise say "fix your
/// SQL" (the `TRUNCATED` warning, the `DB_ERROR`/`TIMEOUT`/`EXPENSIVE_QUERY`
/// hints) are rewritten for an agent that never wrote the statement.
/// Everything else is byte-for-byte the `query` path — the point of the
/// command is that no layer is skipped or repeated for it.
fn rows_command(
    cfg: &config::Config,
    cwd: &Path,
    allowed: &dyn Fn(&config::Connection) -> bool,
    req: RowsRequest,
) -> Result<(), Failure> {
    let RowsRequest {
        alias,
        source,
        format,
        limit,
        timeout,
    } = req;
    let (conn, mut session) = open_session(cfg, &alias, cwd, allowed, timeout)?;
    // Audit identity, captured before the body borrows everything.
    let engine = conn.engine.clone();
    let cwd_str = cwd.display().to_string();
    let log_responses = cfg.audit_enabled() && cfg.audit_log_responses();
    let is_sample = matches!(source, RowSource::Sample(_));
    // Flag > per-connection > [defaults] > built-in, capped by the config
    // owner's max_row_limit (see config::capped). `sample` brings its own small
    // built-in and enters it at the FLAG position: a handful of rows is the
    // whole point of the command, so a connection's `row_limit` (set for real
    // queries) must not inflate it — while `max_row_limit` still clamps it,
    // silently, exactly like everywhere else.
    let limit = match is_sample {
        true => cfg.row_limit(conn, Some(limit.unwrap_or(sample::DEFAULT_ROWS))),
        false => cfg.row_limit(conn, limit),
    };
    // `max_row_limit` clamps silently, so a `sample` sitting ON the ceiling must
    // not be told to raise `--limit` — that is the one thing that cannot work,
    // and an agent that tries it tries it forever (Д10). Asking for the ceiling
    // is how the ceiling is read back: without one, nothing caps u64::MAX.
    let clamped = is_sample && limit >= cfg.row_limit(conn, Some(u64::MAX));
    // Fetch limit+1 to detect truncation without reading everything: the
    // statement asks for the same one row over the limit that the engine does,
    // so `rows.len() > limit` means "there are more" and nothing else.
    let (first, cheap) = statements(&source, &session.db, limit.saturating_add(1));
    // What the audit record names: the statement nyet actually SENT. After a
    // fallback that is the cheap one — the refused random draw never ran, only
    // its EXPLAIN did. It is replaced below by the text as the database saw it;
    // this initial value is what a statement that never ran is logged as.
    let mut executed = first.clone();
    // The ssh forward, opened by whichever attempt gets past the validator and
    // held until this function returns: a fallback must not tear the tunnel
    // down and build it again (with `reuse_forward = false` that is a second
    // bastion login, 2FA included) to ask the same connection one more question.
    let mut tunnel = None;
    // The whole command as ONE Result so both success and every failure path
    // (validator/guardrail refusal, DB error) flow through audit_finish — the
    // log is written before the result is released.
    let outcome = (|| -> Result<Emitted, Failure> {
        let started = Instant::now();
        let mut attempt = run_attempt(&alias, conn, &mut session, &mut tunnel, &first, limit);
        // A refused attempt keeps no duration of its own (a `Failure` carries
        // none), so the wall time of this one is taken here — it is only ever
        // read on the fallback path below.
        let first_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // The ONE thing `sample` retries. A guardrail refusal here is about the
        // random ORDER BY (sorting the whole table), not about the table, so
        // nyet asks the cheap question instead of handing the agent a refusal
        // it did not cause and cannot fix. Every other outcome — a PII refusal,
        // a DB error, a timeout — IS the answer, and a retry would only repeat
        // it; a fallback that is refused too is likewise final (no third try).
        // The retry is a full second pass over the same open tunnel — but NOT
        // over a fresh timeout: the two passes share the one budget the config
        // owner granted, or `sample` would be handing itself twice the ceiling
        // nobody else can raise.
        let expensive =
            matches!(&attempt, Err(f) if matches!(f.code, ErrorCode::Nyet("EXPENSIVE_QUERY")));
        let mut fell_back = false;
        if expensive {
            if let (Some(cheap), Some(left)) =
                (&cheap, fallback_budget_ms(session.timeout_secs, first_ms))
            {
                session.db.set_query_timeout_ms(left);
                executed = cheap.clone();
                attempt = run_attempt(&alias, conn, &mut session, &mut tunnel, cheap, limit);
                fell_back = true;
            }
        }
        let attempt = attempt.map_err(|f| match is_sample {
            true => sample_failure_hint(
                f,
                &SampleFailure {
                    alias: &alias,
                    engine: &engine,
                    fell_back,
                    withheld: session.redact_db_errors(),
                },
            ),
            false => f,
        })?;
        let Attempt {
            rows: mut rs,
            mut warnings,
            sql: sent,
            mut duration_ms,
        } = attempt;
        // The text that actually reached the database — the validator's Unicode
        // normalization included, since a name with hidden characters is sent
        // stripped. The raw ask is not lost: it is the audit record's `table`.
        if is_sample {
            executed = sent;
        }
        if fell_back {
            // The refused draw cost real time (its EXPLAIN ran to a verdict, or
            // to the planning budget); reporting only the second pass would
            // hide most of the wait from the agent AND from the audit log.
            duration_ms = duration_ms.saturating_add(first_ms);
            // The suggestion is the very draw that was refused, spelled with
            // the agent's own limit (no truncation probe row) so it can be run
            // as printed.
            let suggestion = statements(&source, &session.db, limit).0;
            warnings.insert(0, sample_fallback_warning(&alias, &suggestion));
        }

        // Two ways an answer can fall short of the whole truth: nyet
        // fetched limit+1 and cut it, or the ENGINE was cut off before
        // it got there (MongoDB's 16 MiB reply cap stops a batch before
        // the row limit). Either one must reach the agent as
        // `truncated` — a partial answer that reads as complete is the
        // worst failure a read tool has (UX-1).
        // The server stopped early on its own (MongoDB's 16 MiB
        // reply cap), which the row count cannot show — the answer is
        // SHORTER than the limit and still incomplete.
        let server_cut = rs.truncated;
        let over_limit = rs.rows.len() as u64 > limit;
        let truncated = over_limit || server_cut;
        if over_limit {
            rs.rows
                .truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        if truncated {
            warnings.push(output::Warning {
                code: "TRUNCATED",
                message: match (over_limit, is_sample) {
                    // `sample` wrote the statement, so "add WHERE/LIMIT" would
                    // be advice about SQL the agent never saw (Д10): the two
                    // things it can actually do are ask for more rows, or go
                    // read the table itself. Unless the ceiling already cut the
                    // ask — then "raise --limit" is the one advice that cannot
                    // work, and saying it sends the agent round the loop again.
                    (true, true) if clamped => format!(
                        "this is a sample of {limit} rows, not the table: there ARE more rows, \
                         and {limit} is the max_row_limit the owner of this connection set — a \
                         bigger --limit returns no more. To read further, say what you need \
                         with nyet query {} \"<your own SELECT>\"",
                        skill::shell_quote(&alias)
                    ),
                    (true, true) => format!(
                        "this is a sample of {limit} rows, not the table: there ARE more rows \
                         — raise --limit for a bigger sample, or read the table itself with \
                         nyet query {} \"<your own SELECT>\"",
                        skill::shell_quote(&alias)
                    ),
                    (true, false) => format!(
                        "result truncated to {limit} rows; add WHERE/LIMIT or raise --limit"
                    ),
                    // The rows are big, not many — so "narrow the query" is
                    // again advice about a statement the agent never wrote
                    // (Д10); what it holds is a SMALLER --limit and the choice
                    // of fields.
                    (false, true) => format!(
                        "the database cut this answer off at {} rows on its own reply-size \
                         limit (16 MiB) — these rows are large, and there ARE more in the \
                         table. Ask for fewer (--limit N), or take only the fields you need \
                         with nyet query {} \"<your own query, projecting the fields>\"",
                        rs.rows.len(),
                        skill::shell_quote(&alias)
                    ),
                    // Telling the agent to raise --limit here would be
                    // wrong: the limit was never reached (Д10).
                    (false, false) => format!(
                        "result truncated to {} rows by the database's own reply-size \
                         limit (16 MiB), reached before the {limit}-row limit: there \
                         ARE more rows — narrow the query, project away large fields, \
                         or page through it",
                        rs.rows.len()
                    ),
                },
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
    let (command, table) = match &source {
        RowSource::Query(_) => ("query", None),
        // The RAW argument, not the statement built from it: the human reading
        // the log wants to see what the agent asked for.
        RowSource::Sample(table) => ("sample", Some(table.as_str())),
    };
    audit_finish(
        cfg,
        AuditMeta {
            command,
            alias: &alias,
            engine: &engine,
            cwd: &cwd_str,
            sql: Some(&executed),
            table,
        },
        format,
        outcome,
    )
}

/// What one pass of the pipeline produced. The guardrail's own verdicts are
/// already spent by the time this exists — a refusal is an `Err`, not a field.
struct Attempt {
    rows: engine::ResultSet,
    warnings: Vec<output::Warning>,
    /// The text as the database saw it — the validator's normalization applied
    /// — so the audit log can name what actually ran rather than what was built.
    sql: String,
    duration_ms: u64,
}

/// One full pass over ONE statement: layer 1, the guardrail, the engine (net B
/// lives inside `Db::execute`). Every refusal on the way comes back as a
/// `Failure`, and the caller decides whether that is the answer or — for
/// `sample`'s cheap retry — grounds for one more pass.
fn run_attempt(
    alias: &str,
    conn: &config::Connection,
    session: &mut Session,
    tunnel: &mut Option<tunnel::Tunnel>,
    sql: &str,
    limit: u64,
) -> Result<Attempt, Failure> {
    // Layer 1. Any deny -> code NYET + reason, exit 5. Which layer 1
    // runs is decided by the engine: MongoDB has its own parser and
    // allowlist (mongosh text is not SQL and sqlparser must never
    // see it), everything else goes through the SQL validator.
    let (sql, is_query, mut warnings, pii_exempt) = match session.db.is_mongo() {
        true => validate_mongo(sql, session.policy.pii())?,
        false => validate(sql, &session.policy)?,
    };
    // Layer 1.5: the guardrail. Only a plain query can be wrapped in an
    // EXPLAIN; SHOW/DESCRIBE are metadata no planner estimates, so they
    // run unguarded (documented). An EXPLAIN ANALYZE never gets here —
    // the validator refuses it (reason EXPLAIN_ANALYZE).
    let guardrail = match is_query {
        true => config::guardrail(alias, conn).map_err(config_failure)?,
        false => guardrail::Guardrail::OFF,
    };
    // The tunnel is opened AFTER the validator (a refused query exits 5
    // without paying for ssh); the guard is the CALLER's, and lives across a
    // fallback retry, so the second pass finds it already open. What its drop
    // does (keep the forward for the next run or remove it) is tunnel.rs's
    // business.
    // Fetch limit+1 to detect truncation without reading everything.
    if tunnel.is_none() {
        *tunnel = open_tunnel(conn, session.timeout_secs, &mut session.db)?;
    }
    let ((outcome, masked), duration_ms) = run_db(
        session.redact_db_errors(),
        session.db.execute(
            &sql,
            limit.saturating_add(1),
            &guardrail,
            session.policy.pii(),
            &pii_exempt,
        ),
    )?;
    if !masked.is_empty() {
        warnings.push(pii_masked_warning(&masked));
    }

    let (rows, estimate) = match outcome {
        // The guardrail refused: nothing ran, and the envelope carries
        // the plan that justified it (NYET/EXPENSIVE_QUERY, exit 5).
        engine::QueryOutcome::Refused { estimate, value } => {
            let (message, hint) = guardrail.refusal(alias, value);
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
            let (message, hint) = guardrail::planning_too_slow(alias, budget_ms);
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
        engine::QueryOutcome::PiiRefused(refusal) => return Err(refusal_failure(*refusal)),
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
    Ok(Attempt {
        rows,
        warnings,
        sql,
        duration_ms,
    })
}

/// The statement(s) to run, in attempt order. `query` has exactly one — the
/// agent's own text. `sample` gets nyet's own: the random draw it tries first,
/// plus the cheap `LIMIT`-only spelling to fall back on when the guardrail
/// refuses the sort. `rows` is the FETCH count (the row limit plus the one
/// extra row that proves truncation), so the statement asks for exactly what
/// the engine will read.
///
/// A fallback exists only where a guardrail can actually fire: PostgreSQL and
/// MySQL/MariaDB. SQLite and MongoDB accept `off` and nothing else
/// (`guardrail::engine_modes`), so a second statement for them would be text
/// that can never run.
fn statements(source: &RowSource, db: &Db, rows: u64) -> (String, Option<String>) {
    match source {
        RowSource::Query(sql) => (sql.clone(), None),
        RowSource::Sample(table) => match db {
            Db::Sqlite(_) => (sample::sqlite(table, rows), None),
            Db::Postgres(_) => (
                sample::postgres(table, rows, true),
                Some(sample::postgres(table, rows, false)),
            ),
            Db::Mysql(_) => (
                sample::mysql(table, rows, true),
                Some(sample::mysql(table, rows, false)),
            ),
            Db::Mongo(_) => (sample::mongo(table, rows), None),
        },
    }
}

/// `sample` asked for a random draw and the guardrail refused the sort, so what
/// came back is whatever the database returned first. The agent MUST be told
/// (UX-2): a biased handful read as representative is precisely the wrong
/// conclusion to take from a sample, and the way to a real random draw is a
/// deliberate `query` — which the guardrail judges again, that time with an
/// estimate in the refusal the agent can act on.
///
/// The invocation is printed to be RUN, so both arguments are shell-quoted: the
/// statement carries `"` on PostgreSQL/SQLite and backticks on MySQL, and a
/// backtick inside a double-quoted shell word is command substitution. A hint
/// that cannot be pasted is a hint that lies (Д10); one that runs something
/// else entirely is worse.
fn sample_fallback_warning(alias: &str, suggestion: &str) -> output::Warning {
    output::Warning {
        code: "SAMPLE_FALLBACK",
        message: format!(
            "a random sample of this table was refused by this connection's guardrail as too \
             expensive (drawing at random means sorting the whole table), so these are the \
             FIRST rows the database returned, in its own storage order — typically the \
             oldest or lowest-key ones. Do not read them as representative of the table. To \
             insist on a real random draw, ask for it yourself: nyet query {} {}",
            skill::shell_quote(alias),
            skill::shell_quote(suggestion)
        ),
    }
}

/// What the `sample` texts have to know about the run that failed. The advice
/// only holds if it names what THIS run did: which engine answered, whether the
/// random sort was still in the statement, and whether the server's own words
/// reached the agent at all.
struct SampleFailure<'a> {
    alias: &'a str,
    /// `postgres` | `mysql` | `mariadb` | `sqlite` | `mongodb`.
    engine: &'a str,
    /// The guardrail refused the random draw and the plain `LIMIT` ran instead,
    /// so the sort is no longer anything to blame.
    fell_back: bool,
    /// This connection's PII policy withholds the database's error text — and
    /// with it the advice that came attached, which is about editing a
    /// statement the agent did not write.
    withheld: bool,
}

/// A `sample` failure is read by an agent that never wrote the statement, so
/// every hint that says "narrow your query" is a dead end here (Д10): what the
/// agent actually chose is the NAME, `--limit`, `--timeout` — and the option of
/// writing the query itself. Only the outcomes it can act on are rewritten, and
/// the original hint is KEPT wherever it still carries something these texts
/// cannot know: a permission error's own advice, the guardrail's config key.
fn sample_failure_hint(mut f: Failure, ctx: &SampleFailure) -> Failure {
    let alias = skill::shell_quote(ctx.alias);
    match f.code {
        // A name is the likeliest cause and the cheapest to check, but it is
        // not the only one: "permission denied" arrives here too, and sending
        // that agent renaming tables costs it the whole recovery.
        ErrorCode::DbError => {
            // Only PostgreSQL has a search_path to fall outside of; on the
            // others the argument is one name and qualifying it is nonsense.
            let qualify = match ctx.engine {
                "postgres" => " (qualify it as schema.table when it is outside the search_path)",
                _ => "",
            };
            // MongoDB has no tables or views to list, and telling an agent to
            // look for one is a hint about somebody else's database.
            let objects = match ctx.engine {
                "mongodb" => "collections",
                _ => "tables and views",
            };
            // The withheld hint's own advice — check the schema, simplify the
            // query clause by clause — is either already said here or about a
            // statement nyet wrote; what still holds is that the SCHEMA is not
            // withheld, and that the real message is in the server's log.
            let otherwise = match ctx.withheld {
                true => "this connection's PII policy withheld the database's own message \
                         (types and column names are not withheld, so `nyet schema` still \
                         answers in full), and the full error text is in the database's log \
                         — ask whoever owns this connection for it"
                    .to_string(),
                false => f.hint.clone(),
            };
            f.hint = format!(
                "check the name first: nyet schema {alias} lists the {objects} this \
                 connection can read{qualify}. If the name is right, the failure is about \
                 something else — {otherwise}"
            );
        }
        // The statement is nyet's own, so "add a WHERE clause" would be about
        // text the agent has never seen; what it holds are the two flags.
        ErrorCode::Timeout => {
            let cause = match ctx.fell_back {
                // The sort was already refused by the guardrail — what timed
                // out is a plain read, and blaming the sort would send the
                // agent after something that did not run. The seconds in the
                // engine's own message are the REMAINDER this second attempt
                // ran on, not the timeout anyone configured (both attempts
                // share one budget), so say that rather than let the number
                // read as the connection's setting.
                true => {
                    "the random draw was refused as too expensive and even a plain read of \
                         this table did not finish in what the refused attempt left of the \
                         timeout (both attempts of a sample share one budget)"
                }
                false => "a random draw sorts the whole table, which is what takes the time",
            };
            f.hint = format!(
                "{cause}: ask for fewer rows (--limit N), give it longer (--timeout SECS), \
                 or read the table on your own terms with a filtered nyet query {alias} \
                 \"<your own SELECT>\""
            );
        }
        ErrorCode::Nyet("EXPENSIVE_QUERY") => {
            let what = match ctx.fell_back {
                true => {
                    "nyet already retried without the random sort and the guardrail \
                         refused that too, so a plain read of this table is what it considers \
                         expensive"
                }
                // No retry happened: either the engine has no cheaper spelling,
                // or the first attempt had already spent the timeout budget.
                false => {
                    "this connection's guardrail refused the random draw, which has to \
                          sort the whole table"
                }
            };
            // The guardrail's own hint already says HOW to narrow a query (and
            // names the plan and the config key); this only has to say that
            // writing one is the way out of a command that cannot.
            f.hint = format!(
                "{what}, and nyet sample has no narrower form to offer — write the read \
                 yourself: nyet query {alias} \"<your own SELECT>\", and {}",
                f.hint
            );
        }
        // The likeliest refusal of all: `sample` is a `SELECT *`, which a
        // protected column refuses in BOTH modes. Every hint on that road says
        // "name the columns instead" — true, and impossible with this command.
        ErrorCode::Nyet("PII_COLUMN" | "PII_UNPROVABLE") => {
            f.hint = format!(
                "{} — and nyet sample cannot do that for you: it always writes SELECT *. Name \
                 the columns yourself: nyet query {alias} \"SELECT <the columns you need> FROM \
                 <table> LIMIT 10\"",
                f.hint.trim_end_matches('.')
            );
        }
        _ => {}
    }
    f
}

/// How long `sample`'s second pass may take: what is LEFT of the one budget the
/// config owner granted, never a fresh one — an agent that cannot raise its own
/// timeout must not get two of them by being refused once. `None` when what
/// remains is under a second, which is both useless and below the floor the
/// engines' own EXPLAIN budget assumes: then the guardrail's refusal stands as
/// the answer, hint included.
fn fallback_budget_ms(timeout_secs: u64, spent_ms: u64) -> Option<u64> {
    let left = timeout_secs.saturating_mul(1000).saturating_sub(spent_ms);
    (left >= 1000).then_some(left)
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
) -> Result<(String, bool, Vec<output::Warning>, Vec<usize>), Failure> {
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
            pii_exempt,
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
            pii_exempt,
        )),
    }
}

/// Layer 1 for MongoDB, in the shape the query arm expects. The parsed request
/// is deliberately DROPPED: `mongo::check` is pure, so the engine re-runs it on
/// the same text and executes exactly what was classified here — one
/// representation, no drift, and the refusal still happens before anything
/// touches the network.
///
/// `is_query = false`: there is no plan to estimate (MongoDB's guardrail modes
/// are `off` only, enforced at config parse), so the guardrail is skipped the
/// same way it is for a `SHOW`. No unicode normalization either: the SQL
/// stripping exists to stop zero-width characters from hiding a keyword, while
/// here every operator is matched literally (an invisible character inside
/// `$where` simply makes it an unknown key -> deny) and stripping would corrupt
/// filter VALUES, which are data.
fn validate_mongo(
    query: &str,
    pii: &validator::PiiRules,
) -> Result<(String, bool, Vec<output::Warning>, Vec<usize>), Failure> {
    match mongo::check_with_pii(query, pii) {
        Ok(_request) => Ok((query.to_string(), false, Vec::new(), Vec::new())),
        Err(r) => Err(Failure::new(ErrorCode::Nyet(r.reason), r.message, r.hint)),
    }
}

/// One validator refusal -> one NYET failure (exit 5).
fn refusal_failure(r: validator::Refusal) -> Failure {
    Failure::new(ErrorCode::Nyet(r.reason.as_str()), r.message, r.hint)
}

/// A mongo-layer PII refusal in the validator's shape, so `PiiRefused` carries
/// one type whatever the engine. The reasons share their spellings on purpose
/// (pinned by a unit test in mongo.rs). Anything that is NOT one of the two
/// PII reasons — scan_reply re-parses the executed text, so in principle it
/// can fail to parse what the cli just validated — is an internal
/// inconsistency and must say so, not masquerade as "the result carried a
/// protected field" and send the agent rewriting a fine query.
fn mongo_pii_refusal(r: mongo::Refusal) -> validator::Refusal {
    validator::Refusal {
        reason: match r.reason {
            mongo::PII_COLUMN => validator::DenyReason::PiiColumn,
            mongo::PII_UNPROVABLE => validator::DenyReason::PiiUnprovable,
            _ => validator::DenyReason::InternalError,
        },
        message: r.message,
        hint: r.hint,
    }
}

/// The guardrail asked for a plan and got nothing it could judge. Д10 — what
/// happened, why, what to do instead. Shared by `query` (which then ran the
/// query unguarded) and `explain` (whose verdict is `no_estimate` for the very
/// same reason), so the agent is never left guessing why there is no number.
/// `mode = "mask"`: the agent MUST be told which columns it is looking at a mask
/// of, or it will read `[REDACTED]` as data and reason on it (UX-2/UX-4). Names
/// only — never a value, and never how many rows were affected (every row of the
/// column is replaced, so there is nothing to count).
fn pii_masked_warning(columns: &[String]) -> output::Warning {
    output::Warning {
        code: "PII_MASKED",
        message: format!(
            "column(s) {} are protected by this connection's PII policy (mode = \"mask\"): \
             every value in them was replaced with \"{}\" before you saw it — the real \
             values, their type and their length are not in this answer, so do not treat \
             them as data, compare them or report them as such",
            columns
                .iter()
                .map(|c| format!("'{c}'"))
                .collect::<Vec<_>>()
                .join(", "),
            output::REDACTED
        ),
    }
}

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
    alias: &str,
    cwd: &Path,
    allowed: &dyn Fn(&config::Connection) -> bool,
    timeout_flag: Option<u64>,
) -> Result<(&'a config::Connection, Session), Failure> {
    let conn = lookup_alias(cfg, alias)?;
    check_scope(alias, conn, cwd, allowed(conn))?;
    let timeout_secs = cfg.timeout_secs(conn, timeout_flag);
    let (mut db, policy) = build_engine(alias, conn, timeout_secs)?;
    // The PII policy is resolved here (once) and lives inside the validator
    // Policy: net A reads it during validation, and the cli reads it back for
    // net B and for the database-error redaction.
    let pii = config::pii(alias, conn).map_err(config_failure)?;
    if !pii.is_empty() {
        db.resolve_column_origins();
    }
    let insecure_transport = insecure_transport(conn, db.url());
    Ok((
        conn,
        Session {
            db,
            policy: policy.with_pii(pii),
            timeout_secs,
            insecure_transport,
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
    alias: &str,
) -> Result<&'a config::Connection, Failure> {
    cfg.connections.get(alias).ok_or_else(|| {
        let known: Vec<&str> = cfg.connections.keys().map(String::as_str).collect();
        Failure::new(
            ErrorCode::ConfigInvalid,
            format!("unknown connection alias '{alias}': not defined in the config"),
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
            let url = resolve_secret(alias, "url", url)?;
            let password = read_password(alias, conn)?;
            Ok((
                Db::Postgres(engine::Postgres {
                    url,
                    password,
                    statement_timeout_ms: engine::Postgres::clamp_statement_timeout(
                        timeout_secs.saturating_mul(1000),
                    ),
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
        // MariaDB is dialect- and protocol-identical to MySQL here; the label
        // only tells the engine which of the two mutually exclusive
        // server-timeout variables to try FIRST. A wrong label costs one round
        // trip per connection, never the cap itself (see `TimeoutVar`).
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
            let url = resolve_secret(alias, "url", url)?;
            let password = read_password(alias, conn)?;
            Ok((
                Db::Mysql(engine::Mysql {
                    url,
                    password,
                    statement_timeout_ms: engine::Mysql::clamp_statement_timeout(
                        timeout_secs.saturating_mul(1000),
                    ),
                    // The in-process query-phase deadline (unclamped): the
                    // full per-query wall budget, backstopping the server
                    // max_execution_time/max_statement_time above.
                    query_timeout_ms: timeout_secs.saturating_mul(1000),
                    // Filled in by open_tunnel once the SSH tunnel (if any) is up.
                    host_override: None,
                    // Production: the generous connect_deadline floor.
                    connect_timeout_ms: None,
                    // A hint for the first SET, not a promise: a mislabelled
                    // server is still capped, one round trip later.
                    mariadb: conn.engine == "mariadb",
                }),
                validator::Policy::mysql(v_allow, v_deny),
            ))
        }
        // MongoDB is not SQL, so it brings its own layer 1 (`src/mongo.rs`) and
        // an empty SQL policy: `Policy` is still built because `Session` holds
        // one, but nothing ever hands mongosh text to sqlparser.
        "mongodb" => {
            let Some(url) = &conn.url else {
                return Err(Failure::new(
                    ErrorCode::ConfigInvalid,
                    format!("connection '{alias}' has engine = \"mongodb\" but no `url`"),
                    "add url = \"mongodb://user@host:27017/dbname\" to this connection in \
                     the config; the database name is required (nyet never switches \
                     databases on its own)",
                ));
            };
            let url = resolve_secret(alias, "url", url)?;
            // The `[ssh]` rules judge the url that will actually be dialed;
            // config::parse could only check it when it was written literally.
            if conn.ssh.is_some() {
                config::mongo_tunnel(alias, Some(&url)).map_err(config_failure)?;
            }
            let password = read_password(alias, conn)?;
            Ok((
                Db::Mongo(engine::Mongo {
                    url,
                    password,
                    // One value for both halves of the bound: the server-side
                    // maxTimeMS and the in-process deadline that backstops it.
                    query_timeout_ms: timeout_secs.saturating_mul(1000),
                    host_override: None,
                    connect_timeout_ms: None,
                }),
                validator::Policy::sqlite(v_allow, v_deny),
            ))
        }
        other => Err(Failure::new(
            ErrorCode::NotImplemented,
            format!("engine \"{other}\" of connection '{alias}' is not supported yet"),
            "supported engines: sqlite, postgres, mysql, mariadb, mongodb; others arrive in \
             later releases",
        )),
    }
}

/// Open the SSH tunnel (if the connection has one) and point the engine at its
/// local end. A tunnel failure is CONNECTION_FAILED (exit 6). sqlite + ssh was
/// already rejected at config parse, so only the server engines reach here.
/// The caller holds the returned guard for the whole database operation; what
/// its drop does (keep the forward for the next run, cancel it, kill the child)
/// is tunnel.rs's business.
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
    // Default on: reuse is the whole point (it removes two ssh spawns per call),
    // the forward's life is already bounded by ControlPersist, and doctor shows
    // it plus the command that kills it. `reuse_forward = false` opts out.
    let reuse_forward = ssh.reuse_forward.unwrap_or(true);
    let tunnel = tunnel::open(host, remote, control_persist, timeout_secs, reuse_forward)
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
            // MongoDB's grants carry action and resource NAMES only — never a
            // value from a document — so there is nothing to withhold.
            output::ProbeFact::Wrote { .. } | output::ProbeFact::Grants(_) => {}
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
        Command::Query { format, .. } | Command::Sample { format, .. } => *format,
        // agent-setup has its own format enum and sets its routing itself; the
        // value here is unused (it short-circuits run() before any error path).
        Command::AgentSetup { .. } => None,
        // secret-set writes one line to stderr and no envelope; like
        // agent-setup it never reaches the format-routed error paths.
        Command::SecretSet { .. } => None,
    }
}

/// The default output format per command: `table` for `doctor` (the one
/// human-facing command), `json` for everything else (the agent contract).
fn default_format(command: &Command) -> Format {
    match command {
        Command::Doctor { .. } => Format::Table,
        // Markdown default routes like a data format (stderr envelope);
        // agent_setup overrides this before any error path anyway.
        Command::AgentSetup { .. } | Command::SecretSet { .. } => Format::Table,
        _ => Format::Json,
    }
}

/// The `engine` string -> the pure doctor `EngineKind`. Called only after
/// `build_engine` succeeded, so the value is one of the four supported engines.
fn engine_kind(engine: &str) -> output::EngineKind {
    match engine {
        "sqlite" => output::EngineKind::Sqlite,
        "postgres" => output::EngineKind::Postgres,
        "mongodb" => output::EngineKind::Mongo,
        // mysql | mariadb — one driver, one dialect.
        _ => output::EngineKind::Mysql,
    }
}

/// The transport guarantee for doctor, from config + url only (no round-trip):
/// an ssh tunnel encrypts the hop, a direct url at `require`+ enforces TLS,
/// anything below that is not guaranteed encrypted, and SQLite has no transport.
fn doctor_transport(conn: &config::Connection, url: &str) -> output::Transport {
    if conn.engine == "sqlite" {
        return output::Transport::Na;
    }
    if conn.ssh.is_some() {
        return output::Transport::Tunnel;
    }
    if insecure_transport(conn, url) {
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
    pii: &[(String, String)],
) -> Result<(output::Diagnosis, u64, Option<output::ForwardFact>), Failure> {
    let started = Instant::now();
    let elapsed =
        |started: Instant| u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let _tunnel = match open_tunnel(conn, timeout_secs, db) {
        Ok(tunnel) => tunnel,
        Err(f) => {
            return Ok((
                output::Diagnosis {
                    pii_views: None,
                    connect: output::ConnectFact::Failed {
                        message: f.message,
                        hint: f.hint,
                    },
                    server: None,
                    pii: Vec::new(),
                },
                elapsed(started),
                None,
            ));
        }
    };
    // Read the forward's facts while the guard is alive; doctor reports them so
    // a forward that outlives the process is visible and killable, not folklore.
    let forward = _tunnel.as_ref().map(|t| output::ForwardFact {
        local_port: t.local_port,
        reused: t.reused,
        age_secs: t.age_secs,
        kill_command: t.kill_command.clone(),
    });
    let rt = runtime()?;
    let diagnosis = rt.block_on(db.diagnose(pii));
    // A slow/abandoned probe future must not join a busy worker on exit.
    rt.shutdown_background();
    Ok((diagnosis, elapsed(started), forward))
}

/// Static transport check for the INSECURE_TRANSPORT warning: a direct (no ssh)
/// server connection whose url sslmode is below require gives no
/// encryption/verification guarantee. Computed from config + url only (no
/// server round-trip).
fn insecure_transport(conn: &config::Connection, url: &str) -> bool {
    conn.ssh.is_none() && engine::transport_below_require(&conn.engine, url)
}

/// Security signal (not a refusal), shared by query and schema: the transport
/// gave no encryption guarantee. `Warning` has no hint field, so the remedy is
/// folded into the message.
fn insecure_transport_warning() -> output::Warning {
    output::Warning {
        code: "INSECURE_TRANSPORT",
        message: "this connection's transport is not guaranteed encrypted or \
                  verified (sslmode/ssl-mode/tls below require and no ssh tunnel); \
                  set sslmode=verify-full (Postgres), ssl-mode=VERIFY_IDENTITY \
                  (MySQL) or tls=true (MongoDB) in the url, or route through an \
                  ssh tunnel"
            .to_string(),
    }
}

/// MongoDB `schema`: the answer contains an INFERENCE, and the agent has to be
/// told in the same breath (UX-1/UX-7). New contract code `SCHEMA_SAMPLED`,
/// append-only (Д7) — it means "part of this schema payload is a guess", which
/// no existing code says.
fn sampled_schema_warning(sampled: u32) -> output::Warning {
    output::Warning {
        code: "SCHEMA_SAMPLED",
        message: format!(
            "MongoDB has no schema: every field marked source=\"sample\" below was inferred \
             from {sampled} document(s) drawn at random ($sample), and `seen` says in how many \
             of them it appeared — a field absent from the sample is missing from this answer \
             entirely, and a field in it may be absent from the rest of the collection. Only \
             source=\"validator\" is a real rule the server enforces; nyet can report one only \
             when the role may read the collection's options, so its absence does not mean \
             there is none. At most {} inferred fields are listed, rarest dropped first, and \
             paths go at most 3 levels deep",
            mongo::meta::MAX_FIELDS
        ),
    }
}

/// Read the password for a server connection. The config holds WHERE it lives, never
/// an env var; its value is read here and never printed. A named-but-unset var
/// is a hard config error (like a missing `${VAR}`). Shared by the postgres and
/// mysql/mariadb engines.
/// config -> doctor's view of where a password lives. The mapping is the
/// threat model in one line: only a source that checks WHO is asking keeps the
/// secret away from another process of this user.
fn secret_fact(password: &config::Secret) -> output::SecretFact {
    match password.source() {
        config::Source::Config => output::SecretFact::InConfig,
        config::Source::CallerVerified => output::SecretFact::CallerVerified,
        config::Source::Unguarded => output::SecretFact::Unguarded,
    }
}

/// `nyet secret-set <item>`: read the value from stdin and hand it to the
/// keychain. Deliberately does NOT take the value as an argument — argv is
/// visible in `ps` and lands in the shell history, which is the opposite of
/// the point.
fn secret_set(item: &str) -> Result<(), Failure> {
    let value = read_secret_from_stdin()?;
    if value.is_empty() {
        return Err(Failure::new(
            ErrorCode::ConfigInvalid,
            "no value was given on stdin",
            "run `nyet secret-set <item>` and type the secret, or pipe it in: \
             `printf %s \"$PASSWORD\" | nyet secret-set <item>`",
        ));
    }
    secret::store_in_keychain(item, &value).map_err(|e| match e {
        secret::SecretError::KeychainUnsupported => Failure::new(
            ErrorCode::NotImplemented,
            "storing secrets in a keychain is macOS-only",
            "on this platform a connection can use { env = \"VAR\" } or \
             { command = \"...\" } — both readable by any process of this user, \
             the agent included",
        ),
        secret::SecretError::KeychainNotOurs { item } => Failure::new(
            ErrorCode::ConfigInvalid,
            format!("the keychain refused to overwrite the item \"{item}\""),
            "the item belongs to the binary that created it — macOS asks for your \
             keychain password to hand it over, and that prompt has to be answered \
             (Deny, or no answer, leaves the old item untouched)",
        ),
        other => Failure::new(
            ErrorCode::Internal,
            format!("the secret could not be stored: {other:?}"),
            "check the item in Keychain Access and try again",
        ),
    })?;
    let _ = writeln!(
        io::stderr(),
        "stored \"{item}\" in the login keychain, readable by this build of nyet only"
    );
    Ok(())
}

/// One line from stdin, without echoing it when stdin is a terminal. `stty` is
/// the whole implementation on purpose: a crate for this would be a
/// dependency, and the fallback (echo stays on) is honest rather than fatal.
fn read_secret_from_stdin() -> Result<String, Failure> {
    let interactive = std::io::IsTerminal::is_terminal(&io::stdin());
    let hushed = interactive && stty(&["-echo"]);
    if interactive {
        let _ = write!(io::stderr(), "Secret (not echoed): ");
        let _ = io::stderr().flush();
    }
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line);
    if hushed {
        stty(&["echo"]);
        let _ = writeln!(io::stderr());
    }
    read.map_err(|e| {
        Failure::new(
            ErrorCode::Internal,
            format!("stdin could not be read: {e}"),
            "pipe the value in instead: `printf %s \"$PASSWORD\" | nyet secret-set <item>`",
        )
    })?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn stty(args: &[&str]) -> bool {
    std::process::Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn read_password(alias: &str, conn: &config::Connection) -> Result<Option<String>, Failure> {
    match &conn.password {
        Some(secret) => resolve_secret(alias, "password", secret).map(Some),
        None => Ok(None),
    }
}

/// One `config::Secret` -> its value, with every failure turned into advice
/// aimed at the HUMAN who owns the config. The agent reads these too, so none
/// of them names the config file or quotes the secret.
fn resolve_secret(alias: &str, key: &str, secret: &config::Secret) -> Result<String, Failure> {
    use secret::SecretError;
    secret::resolve(secret).map_err(|e| {
        let (message, hint) = match e {
            SecretError::MissingEnvVar { var, not_unicode } => (
                match not_unicode {
                    true => format!(
                        "connection '{alias}' reads its {key} from ${var}, but that \
                         environment variable is not valid UTF-8"
                    ),
                    false => format!(
                        "connection '{alias}' reads its {key} from ${var}, but that \
                         environment variable is not set"
                    ),
                },
                format!("export {var}=... before running nyet"),
            ),
            SecretError::CommandFailed { message } => (
                format!(
                    "the command providing the {key} of connection '{alias}' failed: {message}"
                ),
                "run that command yourself to see why it failed — nyet deliberately does not \
                 pass its stderr through, because the agent reads nyet's output"
                    .to_string(),
            ),
            SecretError::Empty { source } => (
                format!(
                    "the {source} providing the {key} of connection '{alias}' gave an empty value"
                ),
                "an empty secret would travel on as \"no password\" and fail three layers \
                 later; store the real value, or drop the setting if this connection needs \
                 no password"
                    .to_string(),
            ),
            SecretError::KeychainUnsupported => (
                format!(
                    "connection '{alias}' takes its {key} from a keychain item, which \
                         only exists on macOS"
                ),
                "on this platform use { env = \"VAR\" } or { command = \"...\" } — but note \
                 that both are readable by any process of this user, the agent included"
                    .to_string(),
            ),
            SecretError::KeychainNotFound { item } => (
                format!(
                    "connection '{alias}' takes its {key} from the keychain item \
                         \"{item}\", which does not exist"
                ),
                format!("store it with `nyet secret-set {item}`"),
            ),
            // The measured symptom of an updated binary: the item is there,
            // its ACL names the nyet that created it, and this one is a
            // different build.
            SecretError::KeychainNotOurs { item } => (
                format!(
                    "the keychain item \"{item}\" exists but is not readable by this \
                         build of nyet"
                ),
                format!(
                    "the item trusts the exact binary that created it, and installing nyet \
                     builds a new one — run `nyet secret-set {item}` to hand it over (macOS \
                     will ask for your keychain password, which is exactly the barrier an \
                     agent cannot pass)"
                ),
            ),
            SecretError::KeychainFailed { message } => (
                format!(
                    "the {key} of connection '{alias}' could not be read from the \
                         keychain: {message}"
                ),
                "check the item in Keychain Access, or store it again with \
                 `nyet secret-set <item>`"
                    .to_string(),
            ),
        };
        Failure::new(ErrorCode::ConfigInvalid, message, hint)
    })
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

fn config_failure(e: config::ConfigError) -> Failure {
    let (message, hint) = match e {
        config::ConfigError::Invalid(msg) => (
            format!("the config file is invalid: {msg}"),
            "fix the config file; see README for a full annotated example".to_string(),
        ),
        config::ConfigError::MissingEnvVar(name) => (
            format!(
                "the config file references ${{{name}}} but that environment variable is not set"
            ),
            format!("export {name}=... before running nyet, or remove the reference"),
        ),
        config::ConfigError::NotUnicodeEnvVar(name) => (
            format!(
                "the config file references ${{{name}}} but that environment variable \
                 is set to a value that is not valid UTF-8"
            ),
            format!("re-export {name} with a valid UTF-8 value, or remove the reference"),
        ),
        config::ConfigError::EnvVarInPolicy { alias, key, value } => (
            format!(
                "the config file: {key} value \"{value}\" for connection '{alias}' uses \
                 ${{VAR}} substitution"
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
                "the config file: allowed_dirs entry \"{dir}\" for connection '{alias}' \
                 is not a valid scoping path"
            ),
            "entries must be absolute or ~/relative; relative entries, \"~//...\" \
             and \"..\" components are rejected because they would widen the scope — \
             write the resolved absolute path instead"
                .to_string(),
        ),
        config::ConfigError::SecretNotOneSource { alias, key } => (
            format!(
                "the config file: {key} of connection '{alias}' must name exactly one place \
                 the value comes from"
            ),
            format!(
                "write {key} = \"...\" to keep it in the config, or exactly one of \
                 {{ keychain = \"item\" }} (macOS; only nyet can read it), \
                 {{ env = \"VAR\" }} or {{ command = \"...\" }} — the last two are readable \
                 by any process of this user, the agent included"
            ),
        ),
        config::ConfigError::ZeroValue { key } => (
            format!("the config file: {key} is 0"),
            "row_limit and timeout_secs must be at least 1; to use the built-in \
             default, omit the key"
                .to_string(),
        ),
        config::ConfigError::SshMissingField { alias, field } => (
            format!(
                "the config file: connection '{alias}' has an [ssh] section but no {field}"
            ),
            format!(
                "set {field} in [connections.{alias}.ssh]: host = \"[user@]bastion[:port]\", \
                 remote = \"db-host:5432\" — both are required for a tunnel"
            ),
        ),
        config::ConfigError::SshWithSqlite { alias } => (
            format!(
                "the config file: connection '{alias}' is engine = \"sqlite\" but has an [ssh] section"
            ),
            "SSH tunnels forward a TCP port; SQLite is a local file, so ssh does not \
             apply — remove the [ssh] section, or use a server engine (postgres)"
                .to_string(),
        ),
        config::ConfigError::GuardrailInvalid { alias, message } => (
            format!(
                "the config file: connection '{alias}' has an invalid [guardrail] section: {message}"
            ),
            format!(
                "set [connections.{alias}.guardrail] mode to \"cost\", \"rows\" or \"off\" \
                 (which modes an engine supports depends on what its planner publishes — \
                 see the README), with max_cost / max_rows as positive numbers"
            ),
        ),
        config::ConfigError::SshInvalid { alias, message } => (
            format!("the config file: connection '{alias}' has an invalid [ssh] value: {message}"),
            "fix the [ssh] host/remote/control_persist; host is [user@]hostname[:port] and \
             remote is host:port with safe characters — values that could be read as ssh \
             options (a leading '-', or a ${VAR} that expands to one) are rejected"
                .to_string(),
        ),
        config::ConfigError::PiiRuleInvalid { alias, message } => (
            format!(
                "the config file: connection '{alias}' has an invalid [pii] rule: {message}"
            ),
            format!(
                "each entry of [connections.{alias}.pii] columns names one column as \
                 \"table.column\" (or \"schema.table.column\"), e.g. \
                 columns = [\"users.email\", \"users.phone\"]; matching is \
                 case-insensitive and any schema qualifier is ignored"
            ),
        ),
        config::ConfigError::MongoTunnelInvalid { alias, message } => (
            format!(
                "the config file: connection '{alias}' combines an [ssh] tunnel with a \
                 MongoDB url nyet cannot keep inside it: {message}"
            ),
            format!(
                "point `url` at ONE member through the tunnel — \
                 url = \"mongodb://user@127.0.0.1:27017/dbname\" with \
                 [connections.{alias}.ssh] remote = \"<that member>:27017\" — and let nyet \
                 add directConnection itself, without tls=true (the ssh hop is what \
                 encrypts that leg); a tunnel that the driver can route around, or a TLS \
                 setting nyet would have to ignore, is worse than an honest error"
            ),
        ),
        config::ConfigError::AuditPathEnvVar { value } => (
            format!(
                "the config file: [audit] path \"{value}\" uses ${{VAR}} substitution"
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

/// The config's LOCATION never reaches the output — not the resolved path, not
/// the default one. It is the map to the credentials, and the agent reads every
/// error nyet prints: an agent that hits "config not found" should ask its human,
/// not learn where to go looking (see SECURITY.md). The human owning the setup
/// knows where the file is; the README says where it goes.
fn read_config(path: &Path) -> Result<String, Failure> {
    std::fs::read_to_string(path).map_err(|e| {
        let (message, hint) = match e.kind() {
            std::io::ErrorKind::NotFound => (
                "the config file does not exist".to_string(),
                "ask the human who owns this setup to create a nyet config \
                 (the nyet README has an annotated example)"
                    .to_string(),
            ),
            std::io::ErrorKind::InvalidData => (
                "the config file is not valid UTF-8".to_string(),
                "re-save the file with UTF-8 encoding".to_string(),
            ),
            _ => (
                format!("cannot read the config file: {e}"),
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
                // `warning` already names the file ("the config file", "the
                // audit log") — the path itself stays out: stderr is read by
                // the agent too, and neither location is its business.
                let _ = writeln!(std::io::stderr(), "warning: {warning}");
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
            pii_views: None,
            pii: Vec::new(),
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
            pii_views: None,
            pii: Vec::new(),
            connect: output::ConnectFact::Ok { via_tunnel: false },
            server: Some(output::ServerFacts {
                js: None,
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

    /// The cli half of the same policy: a caught validator panic must travel the
    /// ordinary refusal road — NYET, exit 5 — because that is exactly what makes
    /// `audit_finish` write it as a "refused" record instead of an error (or, if
    /// the panic had escaped, nothing at all).
    ///
    /// The refusal is built here rather than provoked with the validator's
    /// `__nyet_test_panic__` hook: that hook is `#[cfg(test)]` inside the lib
    /// target, which is compiled WITHOUT `cfg(test)` for this binary's tests.
    /// The other half of the chain — a real panic producing exactly this
    /// `InternalError` refusal — is pinned in `validator.rs` and `mongo.rs`,
    /// where the hook does compile in. Splitting the chain is safe only because
    /// both links between the halves are reason-AGNOSTIC — `validate`'s `Deny`
    /// arm hands the reason straight to `refusal_failure`, and `audit_finish`
    /// matches `ErrorCode::Nyet(r)` without looking at `r` — so no reason can
    /// take a different road; a refactor that starts matching on the reason in
    /// either place breaks that assumption and owes this test an end-to-end
    /// replacement.
    #[test]
    fn a_validator_panic_refuses_with_the_ordinary_nyet_exit_code() {
        let f = refusal_failure(validator::Refusal {
            reason: validator::DenyReason::InternalError,
            message: "internal error".to_string(),
            hint: "report it".to_string(),
        });
        assert_eq!(f.code.as_str(), "NYET");
        assert_eq!(f.code.reason(), Some("INTERNAL_ERROR"));
        assert_eq!(f.code.exit(), 5);
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

    /// Ask a REAL shell to split the tail of a printed invocation into words.
    /// Nothing weaker proves the claim: the danger is precisely what `sh` does
    /// to a string nyet composed (`` ` ``, `$( )`, quote stripping), so `sh`
    /// has to be the judge.
    #[cfg(unix)]
    fn shell_words(command: &str) -> Vec<String> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "for w in {command}; do printf '%s\\n' \"$w\"; done"
            ))
            .output()
            .expect("sh");
        assert!(out.status.success(), "sh refused: {command}");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The `SAMPLE_FALLBACK` warning prints an invocation to be RUN, and both of
    /// its arguments are agent-influenced: the alias comes from the config, the
    /// statement embeds the `<table>` argument. A shell must read them back as
    /// exactly two words — the table name is nyet's own quoting all the way to
    /// the database, and a paste that runs `$(...)` on the human's machine is
    /// the injection that skipped the database entirely.
    #[cfg(unix)]
    #[test]
    fn the_fallback_suggestion_survives_a_real_shell_verbatim() {
        for table in [
            "users",
            "we`ird",
            "$(touch /tmp/nyet_pwned)",
            "`touch /tmp/nyet_pwned`",
            r#"we"ird"#,
            "two words",
            "it's",
            "a;b|c&d",
        ] {
            for suggestion in [
                sample::sqlite(table, 10),
                sample::postgres(table, 10, true),
                sample::mysql(table, 10, true),
            ] {
                let w = sample_fallback_warning("prod db", &suggestion);
                let (_, command) = w.message.rsplit_once("nyet query ").expect("the example");
                assert_eq!(
                    shell_words(&format!("nyet query {command}")),
                    vec![
                        "nyet".to_string(),
                        "query".to_string(),
                        "prod db".to_string(),
                        suggestion.clone()
                    ],
                    "{suggestion}"
                );
            }
        }
    }

    /// The `sample` run these tests describe unless they say otherwise: a
    /// PostgreSQL connection that answered in full, on its first attempt.
    fn pg_sample() -> SampleFailure<'static> {
        SampleFailure {
            alias: "prod",
            engine: "postgres",
            fell_back: false,
            withheld: false,
        }
    }

    /// Д10: the hint of a `sample` failure must point at something the agent can
    /// do — and must not throw away what the original hint knew. The withheld
    /// database error is the case that matters: its hint is the ONLY place the
    /// agent learns the real message is in the server's log.
    #[test]
    fn a_sample_failure_keeps_the_original_hint_and_adds_its_own() {
        let withheld = sample_failure_hint(
            db_error_withheld(),
            &SampleFailure {
                withheld: true,
                ..pg_sample()
            },
        );
        assert!(
            withheld.hint.contains("nyet schema prod"),
            "{}",
            withheld.hint
        );
        assert!(
            withheld.hint.contains("the database's log"),
            "{}",
            withheld.hint
        );
        // ...and the other half of what the withheld hint knew: the schema is
        // not part of the secret, so `nyet schema` is still worth running.
        assert!(
            withheld.hint.contains("types and column names"),
            "{}",
            withheld.hint
        );
        // ...without the withheld hint's own advice, which repeats the schema
        // instruction (with an unsubstituted alias) and talks about editing a
        // statement nyet wrote.
        assert!(
            !withheld.hint.contains("<alias>") && !withheld.hint.contains("one clause at a time"),
            "{}",
            withheld.hint
        );
        // A server that DID speak keeps its own words — "permission denied" is
        // not a misspelled table.
        let spoke = sample_failure_hint(
            Failure::new(ErrorCode::DbError, "permission denied", "ask for a GRANT"),
            &pg_sample(),
        );
        assert!(spoke.hint.contains("ask for a GRANT"), "{}", spoke.hint);
        // The search_path belongs to PostgreSQL alone.
        assert!(spoke.hint.contains("search_path"), "{}", spoke.hint);
        // ...and so does the vocabulary: MongoDB has collections, not tables.
        for (engine, objects) in [
            ("sqlite", "tables and views"),
            ("mysql", "tables and views"),
            ("mariadb", "tables and views"),
            ("mongodb", "collections"),
        ] {
            let f = sample_failure_hint(
                Failure::new(ErrorCode::DbError, "m", "h"),
                &SampleFailure {
                    engine,
                    ..pg_sample()
                },
            );
            assert!(!f.hint.contains("search_path"), "{engine}: {}", f.hint);
            assert!(f.hint.contains(objects), "{engine}: {}", f.hint);
        }

        // A timeout is about the flags and about writing your own query — never
        // about editing SQL the agent never saw. And it must not blame a sort
        // that the guardrail already refused.
        let engine_hint = "narrow the query (WHERE / LIMIT)";
        let timeout = sample_failure_hint(
            Failure::new(ErrorCode::Timeout, "m", engine_hint),
            &pg_sample(),
        );
        assert!(timeout.hint.contains("--limit"), "{}", timeout.hint);
        assert!(timeout.hint.contains("--timeout"), "{}", timeout.hint);
        assert!(
            !timeout.hint.contains("narrow the query"),
            "{}",
            timeout.hint
        );
        assert!(
            timeout.hint.contains("sorts the whole table"),
            "{}",
            timeout.hint
        );
        let after_fallback = sample_failure_hint(
            Failure::new(ErrorCode::Timeout, "m", engine_hint),
            &SampleFailure {
                fell_back: true,
                ..pg_sample()
            },
        );
        assert!(
            !after_fallback.hint.contains("sorts the whole table"),
            "{}",
            after_fallback.hint
        );
        assert!(
            after_fallback.hint.contains("plain read"),
            "{}",
            after_fallback.hint
        );
        // The engine's message names the REMAINDER the retry ran on; the hint
        // has to say so, or that number reads as the configured timeout.
        assert!(
            after_fallback.hint.contains("share one budget"),
            "{}",
            after_fallback.hint
        );

        let refused = sample_failure_hint(
            Failure::new(ErrorCode::Nyet("EXPENSIVE_QUERY"), "m", "raise max_cost"),
            &SampleFailure {
                fell_back: true,
                ..pg_sample()
            },
        );
        assert!(refused.hint.contains("nyet query prod"), "{}", refused.hint);
        assert!(refused.hint.contains("raise max_cost"), "{}", refused.hint);
        // No retry ran (no budget left, or no cheaper spelling): claiming one
        // did would be a lie about what happened.
        let no_retry = sample_failure_hint(
            Failure::new(ErrorCode::Nyet("EXPENSIVE_QUERY"), "m", "raise max_cost"),
            &pg_sample(),
        );
        assert!(
            !no_retry.hint.contains("already retried"),
            "{}",
            no_retry.hint
        );

        // The likeliest refusal of all: SELECT * over a protected column. Every
        // PII hint says "name the columns instead", which `sample` cannot do.
        for reason in ["PII_COLUMN", "PII_UNPROVABLE"] {
            let pii = sample_failure_hint(
                Failure::new(ErrorCode::Nyet(reason), "m", "select the other columns."),
                &pg_sample(),
            );
            assert!(pii.hint.contains("select the other columns"), "{reason}");
            assert!(
                pii.hint.contains("nyet query prod"),
                "{reason}: {}",
                pii.hint
            );
        }
    }

    /// One budget for the whole `sample`, not one per attempt: the fallback gets
    /// what the refused draw left, and nothing at all when that is under a
    /// second.
    #[test]
    fn the_fallback_runs_on_what_is_left_of_the_owners_timeout() {
        assert_eq!(fallback_budget_ms(30, 0), Some(30_000));
        assert_eq!(fallback_budget_ms(30, 4_500), Some(25_500));
        assert_eq!(fallback_budget_ms(5, 4_000), Some(1_000));
        // Under a second left -> no second attempt at all.
        assert_eq!(fallback_budget_ms(5, 4_001), None);
        assert_eq!(fallback_budget_ms(5, 9_999), None);
        assert_eq!(fallback_budget_ms(1, 0), Some(1_000));
        // Neither end overflows. The budget stays the honest wall clock — what
        // a SERVER will accept as its own timeout is clamped where it is
        // applied, not here (see the test below).
        assert_eq!(fallback_budget_ms(u64::MAX, 0), Some(u64::MAX));
        assert_eq!(fallback_budget_ms(1, u64::MAX), None);
    }

    /// Shrinking the budget must not smuggle a value the server rejects: a
    /// `statement_timeout` past INT_MAX makes PostgreSQL refuse the CONNECT, so
    /// the retry would fail to reach the database at all — a worse answer than
    /// the refusal it was retrying. The clamps live with the engines, so both
    /// the build and this path get them.
    #[test]
    fn shrinking_the_budget_keeps_each_engine_inside_what_it_accepts() {
        // Past both ceilings (`--timeout 5000000` reaches exactly this).
        let huge = 5_000_000_000_u64;
        let mut pg = Db::Postgres(engine::Postgres {
            url: String::new(),
            password: None,
            statement_timeout_ms: 0,
            query_timeout_ms: 0,
            host_override: None,
            connect_timeout_ms: None,
            resolve_column_origins: false,
        });
        pg.set_query_timeout_ms(huge);
        let Db::Postgres(pg) = &pg else {
            unreachable!()
        };
        assert_eq!(pg.statement_timeout_ms, i32::MAX as u64);
        // The in-process deadline is nobody's protocol field: it keeps the
        // whole budget, and backstops the clamped server one.
        assert_eq!(pg.query_timeout_ms, huge);

        let mut my = Db::Mysql(engine::Mysql {
            url: String::new(),
            password: None,
            statement_timeout_ms: 0,
            query_timeout_ms: 0,
            host_override: None,
            connect_timeout_ms: None,
            mariadb: false,
        });
        my.set_query_timeout_ms(huge);
        let Db::Mysql(my) = &my else { unreachable!() };
        assert_eq!(my.statement_timeout_ms, u32::MAX as u64);
        assert_eq!(my.query_timeout_ms, huge);

        // A budget under the ceilings passes through untouched.
        let mut pg = Db::Postgres(engine::Postgres {
            url: String::new(),
            password: None,
            statement_timeout_ms: 0,
            query_timeout_ms: 0,
            host_override: None,
            connect_timeout_ms: None,
            resolve_column_origins: false,
        });
        pg.set_query_timeout_ms(25_500);
        let Db::Postgres(pg) = &pg else {
            unreachable!()
        };
        assert_eq!(pg.statement_timeout_ms, 25_500);
    }
}
