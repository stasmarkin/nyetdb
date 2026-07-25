//! Engines: IO adapters behind the `Engine` trait (Д2). Engines know their
//! drivers (sqlx) and nothing about clap; the cli layer maps `EngineError` onto
//! contract codes and wraps execution in a timeout. The one thing they take
//! from `output` is the pure `schema` model (`Schema`/`SchemaTable`/... plus
//! `build_table`, which owns the pk/unique presentation rules) — the contract
//! shape they fill in, so the three engines cannot drift.

use crate::output::{
    build_table, KeyPart, Schema, SchemaColumn, SchemaFk, SchemaIndex, SchemaTable,
};
use futures_util::TryStreamExt;
use serde_json::Value;
use sqlx::mysql::{MySqlConnectOptions, MySqlRow, MySqlSslMode};
use sqlx::postgres::{PgConnectOptions, PgRow, PgSslMode};
use sqlx::sqlite::{SqliteConnectOptions, SqliteRow};
use sqlx::{Column, ConnectOptions, Connection, Row, TypeInfo, ValueRef};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

// Debug: test assertions unwrap on it; the fields are curated messages/hints
// with no secrets (never the password or the url).
#[derive(Debug)]
pub enum EngineError {
    /// The database could not be reached/opened (-> CONNECTION_FAILED, exit 6).
    Connect { message: String, hint: String },
    /// The database accepted the connection but rejected the query
    /// (-> DB_ERROR, exit 7).
    Db { message: String, hint: String },
    /// The server aborted the query on its own timeout (-> TIMEOUT, exit 8).
    /// Kept distinct from `Db` so a server-side statement_timeout and the
    /// cli's own tokio timeout both map to exit 8 (deterministic exit code).
    Timeout { message: String, hint: String },
}

/// Floor below which the connect handshake is never cut.
const CONNECT_DEADLINE_FLOOR_MS: u64 = 10_000;

/// Deadline for the TCP+TLS+auth handshake of a server engine, shared by
/// Postgres and MySQL so the two never drift. Its ONLY job is to bound a HUNG
/// connect (blackhole / dropped SYN) so nyet does not hang for the full outer
/// timeout — it is deliberately NOT the query timeout. A legitimate connect over
/// WAN/TLS/auth can take seconds, so we never cut below a 10s floor: a small
/// query timeout (e.g. `--timeout 1`, or the server-timeout tests' 300ms) must
/// still be able to connect — the SERVER's statement_timeout cancels the heavy
/// query on its own. For a large query timeout we stay a hair under it so a hung
/// connect is still classified CONNECTION_FAILED (exit 6), not the outer TIMEOUT.
fn connect_deadline(statement_timeout_ms: u64) -> Duration {
    Duration::from_millis(
        statement_timeout_ms
            .saturating_sub(250)
            .max(CONNECT_DEADLINE_FLOOR_MS),
    )
}

/// Client-side query-phase timeout: the query ran past the effective per-query
/// budget (the in-process tokio timer that wraps the fetch loop, AFTER a
/// successful connect). Distinct from a server-cancelled query only in wording;
/// both are `EngineError::Timeout` (exit 8). For SQLite this is the ONLY query
/// bound (no server timeout); for Postgres/MySQL it backstops the server-side
/// statement_timeout so the exit code is deterministic whichever fires.
fn client_timeout(query_timeout_ms: u64) -> EngineError {
    EngineError::Timeout {
        message: format!(
            "the query did not finish within the {}s timeout",
            query_timeout_ms / 1000
        ),
        hint: "narrow the query (WHERE / LIMIT), or raise --timeout or timeout_secs \
               in the config"
            .to_string(),
    }
}

/// The one planned abstraction of the project (Д5). Fetches at most
/// `fetch_limit` rows; the caller passes limit+1 to detect truncation.
pub trait Engine {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError>;

    /// Introspect the schema through the same read-only session as a query.
    /// `table` is the agent's `[table]` argument: `Some` selects one object
    /// (empty result = not found, the cli turns that into DB_ERROR), `None`
    /// lists everything — with details only while the object count stays
    /// within `output::DETAIL_LIMIT`.
    async fn schema(&self, table: Option<&str>) -> Result<Schema, EngineError>;
}

/// Per-object accumulator while catalog rows (one query per aspect) are
/// grouped back together by table.
struct TableParts {
    kind: &'static str,
    columns: Vec<SchemaColumn>,
    pk: Vec<String>,
    indexes: Vec<SchemaIndex>,
    fks: Vec<SchemaFk>,
    /// False when the server may have withheld columns (a column-level GRANT),
    /// which makes `build_table` drop every key touching an invisible column.
    full_columns: bool,
}

impl TableParts {
    fn new(kind: &'static str, full_columns: bool) -> Self {
        TableParts {
            kind,
            columns: Vec::new(),
            pk: Vec::new(),
            indexes: Vec::new(),
            fks: Vec::new(),
            full_columns,
        }
    }
}

/// Do we answer with names only? Past the limit an unfiltered listing would
/// burn the agent's context; naming a table always gets full detail.
fn over_detail_limit(table: Option<&str>, count: usize) -> bool {
    table.is_none() && count > crate::output::DETAIL_LIMIT
}

/// The names-only answer past the detail limit.
fn listing(objects: Vec<(String, TableParts)>) -> Schema {
    sorted(
        objects
            .into_iter()
            .map(|(name, p)| SchemaTable {
                name,
                kind: p.kind,
                columns: None,
                indexes: Vec::new(),
                fks: Vec::new(),
            })
            .collect(),
    )
}

/// The full answer: the collected parts through the shared presentation rules.
fn assemble(objects: Vec<(String, TableParts)>) -> Schema {
    sorted(
        objects
            .into_iter()
            .map(|(name, p)| {
                build_table(
                    name,
                    p.kind,
                    p.columns,
                    &p.pk,
                    p.indexes,
                    p.fks,
                    p.full_columns,
                )
            })
            .collect(),
    )
}

/// Tables are ordered by their display name — the contract's deterministic
/// order (snapshot-testable), which is NOT the catalog's grouping key for
/// PostgreSQL (that one is schema-first).
fn sorted(mut tables: Vec<SchemaTable>) -> Schema {
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    Schema { tables }
}

/// SQLite via sqlx, opened with `mode=ro` (file-level read-only — layer 2:
/// even a write that slipped past the validator fails in the database).
pub struct Sqlite {
    pub path: PathBuf,
    /// The effective per-query wall budget in ms. SQLite has no server-side
    /// timeout, so this in-process deadline (wrapping the fetch) is the only
    /// query bound — the cli no longer wraps `execute` in an outer timeout.
    pub query_timeout_ms: u64,
}

impl Sqlite {
    /// Open the file read-only (layer 2), with the pre-check that turns
    /// sqlite's opaque "unable to open database file" into a real reason.
    /// Shared by `execute` and `schema`.
    async fn open(&self) -> Result<sqlx::SqliteConnection, EngineError> {
        // Explicit pre-check: sqlite's own "unable to open database file"
        // (code 14) does not say why. Relative paths resolve against the
        // process cwd (documented in README). Off the async thread: a
        // synchronous stat on a hung filesystem (NFS) would block the
        // single-threaded runtime and defeat the caller's timeout.
        let stat_path = self.path.clone();
        let metadata = tokio::task::spawn_blocking(move || std::fs::metadata(&stat_path))
            .await
            .map_err(|e| EngineError::Connect {
                message: format!("cannot open SQLite database {}: {e}", self.path.display()),
                hint: "check `path` for this connection in the config".to_string(),
            })?;
        match metadata {
            Err(e) => {
                return Err(EngineError::Connect {
                    message: format!("cannot open SQLite database {}: {e}", self.path.display()),
                    hint: "check `path` for this connection in the config; a relative \
                           path resolves against the current directory"
                        .to_string(),
                })
            }
            Ok(md) if md.is_dir() => {
                return Err(EngineError::Connect {
                    message: format!(
                        "cannot open SQLite database {}: it is a directory",
                        self.path.display()
                    ),
                    hint: "point `path` in the config at the database file itself".to_string(),
                })
            }
            Ok(_) => {}
        }
        SqliteConnectOptions::new()
            .filename(&self.path)
            .read_only(true)
            .connect()
            .await
            .map_err(|e| EngineError::Connect {
                message: format!(
                    "cannot open SQLite database {}: {}",
                    self.path.display(),
                    error_text(&e)
                ),
                hint: "check that the file is a readable SQLite database".to_string(),
            })
    }
}

impl Engine for Sqlite {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError> {
        let mut conn = self.open().await?;
        // Bound the QUERY phase (not the local file open above) on the effective
        // per-query budget: sqlite has no server-side timeout, so this in-process
        // deadline is the only query bound. On expiry the fetch future is dropped
        // and we report Timeout (exit 8); the sqlite worker thread may keep
        // grinding until the process exits (the cli calls shutdown_background),
        // so on the timeout path we do NOT await the connection afterwards.
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, async move {
            let mut columns: Vec<String> = Vec::new();
            let mut rows: Vec<Vec<Value>> = Vec::new();
            {
                // AssertSqlSafe is sqlx's marker for "audited dynamic SQL":
                // running caller-supplied SQL is nyet's whole job, and the audit
                // is the validator + the read-only open mode.
                let mut stream = sqlx::query(sqlx::AssertSqlSafe(sql.to_string())).fetch(&mut conn);
                while (rows.len() as u64) < fetch_limit {
                    match stream.try_next().await.map_err(db_error)? {
                        Some(row) => {
                            if columns.is_empty() {
                                columns =
                                    row.columns().iter().map(|c| c.name().to_string()).collect();
                            }
                            rows.push(decode_row(&row)?);
                        }
                        None => break,
                    }
                }
            }
            // No rows -> no column names from the stream; ask the prepared
            // statement so table output can still print a header. Best effort:
            // a prepare failure leaves columns empty.
            if rows.is_empty() && columns.is_empty() {
                use sqlx::{Executor, SqlSafeStr, Statement};
                let sql_str = sqlx::AssertSqlSafe(sql.to_string()).into_sql_str();
                if let Ok(statement) = conn.prepare(sql_str).await {
                    columns = statement
                        .columns()
                        .iter()
                        .map(|c| c.name().to_string())
                        .collect();
                }
            }
            let _ = conn.close().await;
            Ok::<ResultSet, EngineError>(ResultSet { columns, rows })
        })
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<Schema, EngineError> {
        let mut conn = self.open().await?;
        let deadline = Duration::from_millis(self.query_timeout_ms);
        // Same shape as execute: on expiry the future is dropped and the
        // connection is NOT awaited (the worker may still be busy).
        match tokio::time::timeout(deadline, sqlite_schema(&mut conn, table)).await {
            Ok(r) => {
                let _ = conn.close().await;
                r
            }
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }
}

/// SQLite introspection: `sqlite_master` for the object list, then the
/// table-valued pragmas for the details.
///
/// **The `[table]` argument never reaches SQL.** It is compared in Rust against
/// the names the catalog returned, and every pragma below is called with the
/// name that came BACK from the catalog, passed as a bound parameter — so
/// neither `users; DROP TABLE x` nor `users'--` can be anything but a name that
/// matches nothing. (`pragma_table_xinfo(?)` is the table-valued form of
/// `PRAGMA table_xinfo`; unlike the statement form it takes bind parameters,
/// which is why it is used here.)
async fn sqlite_schema(
    conn: &mut sqlx::SqliteConnection,
    table: Option<&str>,
) -> Result<Schema, EngineError> {
    let rows = sqlx::query("SELECT name, type FROM sqlite_master WHERE type IN ('table','view')")
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?;
    let mut objects: Vec<(String, TableParts)> = Vec::new();
    for row in rows {
        let name: String = row.try_get("name").map_err(db_error)?;
        let kind: String = row.try_get("type").map_err(db_error)?;
        // sqlite_sequence / sqlite_stat1 / autoindexes: engine bookkeeping.
        if name.starts_with("sqlite_") {
            continue;
        }
        // SQLite resolves identifiers ASCII-case-insensitively, so `nyet schema
        // db USERS` must find `users` — exactly like `SELECT * FROM USERS`.
        if table.is_some_and(|t| !t.eq_ignore_ascii_case(&name)) {
            continue;
        }
        objects.push((
            name,
            // SQLite has no privileges: the pragma always lists every column.
            TableParts::new(if kind == "view" { "view" } else { "table" }, true),
        ));
    }
    if over_detail_limit(table, objects.len()) {
        return Ok(listing(objects));
    }
    for (name, parts) in &mut objects {
        let (columns, pk) = sqlite_columns(conn, name).await?;
        parts.columns = columns;
        parts.pk = pk;
        // A view has no indexes or foreign keys.
        if parts.kind == "table" {
            parts.indexes = sqlite_indexes(conn, name).await?;
            parts.fks = sqlite_fks(conn, name).await?;
        }
    }
    Ok(assemble(objects))
}

/// Columns in ordinal order + the primary-key column names in key order.
/// `type` is the declared type, verbatim (empty for an untyped column).
///
/// `table_xinfo`, not `table_info`: the latter hides GENERATED columns, which
/// are perfectly readable columns an agent must know about. Its `hidden` marks
/// them (2 = VIRTUAL, 3 = STORED, 0 = ordinary); only `1` — a virtual-table
/// hidden column, not selectable by name — is dropped.
async fn sqlite_columns(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
) -> Result<(Vec<SchemaColumn>, Vec<String>), EngineError> {
    let rows = sqlx::query(
        "SELECT name, type, \"notnull\", dflt_value, pk, hidden \
         FROM pragma_table_xinfo(?) ORDER BY cid",
    )
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_error)?;
    let mut columns = Vec::new();
    let mut pk: Vec<(i64, String)> = Vec::new();
    for row in rows {
        let name: String = row.try_get("name").map_err(db_error)?;
        // Lenient on the rest: a pragma column nyet cannot decode must not
        // fail the whole introspection (Д3 — no panics, no dead ends).
        let ty: String = row.try_get("type").unwrap_or_default();
        let notnull: i64 = row.try_get("notnull").unwrap_or(0);
        let default: Option<String> = row.try_get("dflt_value").unwrap_or(None);
        let position: i64 = row.try_get("pk").unwrap_or(0);
        if row.try_get::<i64, _>("hidden").unwrap_or(0) == 1 {
            continue;
        }
        if position > 0 {
            pk.push((position, name.clone()));
        }
        columns.push(SchemaColumn {
            name,
            ty,
            // As declared: SQLite's rowid-alias PRIMARY KEY (`id INTEGER
            // PRIMARY KEY`) carries no NOT NULL, so it reads back nullable
            // here — build_table normalizes a pk column to false so the three
            // engines agree (see docs/DEV.md).
            nullable: notnull == 0,
            pk: false,
            unique: false,
            default,
        });
    }
    pk.sort_by_key(|(position, _)| *position);
    Ok((columns, pk.into_iter().map(|(_, name)| name).collect()))
}

async fn sqlite_indexes(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
) -> Result<Vec<SchemaIndex>, EngineError> {
    let rows = sqlx::query(
        "SELECT name, \"unique\", origin, \"partial\" FROM pragma_index_list(?) ORDER BY seq",
    )
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_error)?;
    let mut indexes = Vec::new();
    for row in rows {
        let name: String = row.try_get("name").map_err(db_error)?;
        let unique: i64 = row.try_get("unique").unwrap_or(0);
        let origin: String = row.try_get("origin").unwrap_or_default();
        // A partial index (`CREATE UNIQUE INDEX ... WHERE ...`) enforces
        // uniqueness only over the rows its predicate matches, so it is
        // reported as an ordinary index — claiming `unique` would promise the
        // agent a key that does not hold for the whole table.
        let partial: i64 = row.try_get("partial").unwrap_or(0);
        // origin 'pk' backs the PRIMARY KEY: redundant with the pk flags.
        if origin == "pk" {
            continue;
        }
        let parts = sqlx::query("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
            .bind(&name)
            .fetch_all(&mut *conn)
            .await
            .map_err(db_error)?;
        // NULL for an expression key (`CREATE INDEX ... (lower(x))`): kept as an
        // Expression part so the key arity survives (the pragma has no text for
        // it, hence None).
        let columns: Vec<KeyPart> = parts
            .iter()
            .map(|r| match r.try_get::<Option<String>, _>("name") {
                Ok(Some(name)) => KeyPart::Named(name),
                _ => KeyPart::Expression(None),
            })
            .collect();
        if columns.is_empty() {
            continue;
        }
        indexes.push(SchemaIndex {
            name,
            columns,
            unique: unique != 0 && partial == 0,
        });
    }
    Ok(indexes)
}

async fn sqlite_fks(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
) -> Result<Vec<SchemaFk>, EngineError> {
    let rows = sqlx::query(
        "SELECT id, \"table\", \"from\", \"to\" FROM pragma_foreign_key_list(?) ORDER BY id, seq",
    )
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_error)?;
    // Rows are one column each, grouped by `id` (a composite key spans several).
    let mut fks: Vec<(i64, SchemaFk)> = Vec::new();
    for row in rows {
        let id: i64 = row.try_get("id").map_err(db_error)?;
        let ref_table: String = row.try_get("table").map_err(db_error)?;
        let from: String = row.try_get("from").map_err(db_error)?;
        let to: Option<String> = row.try_get("to").unwrap_or(None);
        match fks.last_mut() {
            Some((last, fk)) if *last == id => {
                fk.columns.push(from);
                fk.ref_columns.extend(to);
            }
            _ => fks.push((
                id,
                SchemaFk {
                    columns: vec![from],
                    ref_table,
                    ref_columns: to.into_iter().collect(),
                },
            )),
        }
    }
    // `REFERENCES orgs` without a column list points at the parent's primary
    // key; SQLite reports those columns as NULL, so resolve them. A parent
    // with no declared primary key (an implicit rowid reference, or a parent
    // that does not exist) leaves `ref_columns` empty — reported as-is and
    // documented, not invented.
    for (_, fk) in &mut fks {
        if fk.ref_columns.is_empty() {
            fk.ref_columns = sqlite_columns(conn, &fk.ref_table).await?.1;
        }
    }
    Ok(fks.into_iter().map(|(_, fk)| fk).collect())
}

/// PostgreSQL via sqlx. Layer 2 (DESIGN §3) is server-enforced: the
/// connection is opened with `-c default_transaction_read_only=on -c
/// statement_timeout=<ms>` and every read runs inside an explicit
/// `BEGIN READ ONLY` transaction — a write that slipped past the validator is
/// refused by the database itself (SQLSTATE 25006), and a runaway query is
/// killed by the server timeout (57014 -> EngineError::Timeout).
pub struct Postgres {
    /// The `url` from the config (no password embedded by convention).
    pub url: String,
    /// Read from `password_env` by the cli; never logged/printed.
    pub password: Option<String>,
    /// Server-side statement_timeout, from the effective per-query timeout.
    pub statement_timeout_ms: u64,
    /// The effective per-query wall budget in ms: the in-process deadline that
    /// wraps the query phase (AFTER connect), backstopping the server-side
    /// statement_timeout so a runaway query is TIMEOUT (exit 8) whichever fires.
    pub query_timeout_ms: u64,
    /// When an SSH tunnel is up, `(127.0.0.1, local_port)` to connect through
    /// instead of the url's host/port. User/dbname/params from the url stay.
    pub host_override: Option<(String, u16)>,
    /// Test-only override for the connect handshake deadline (ms). Production
    /// (the cli) passes `None` -> `connect_deadline(statement_timeout_ms)`; the
    /// hung-connect tests pass `Some(short)` so they finish fast without the 10s
    /// production floor.
    pub connect_timeout_ms: Option<u64>,
}

/// Redirect host+port to the tunnel's local end while keeping every other
/// connect option (user, dbname, params, password) from the url. Overriding
/// `PgConnectOptions` is more robust than rewriting the url string. Pure — no
/// IO — so it is unit-tested without a database.
///
/// Also forces `sslmode=disable` on the tunnel leg: the hop to 127.0.0.1 is
/// already encrypted by the ssh tunnel, and TLS verification against the
/// loopback address would fail anyway (the server cert names the real host, not
/// 127.0.0.1). The DIRECT path (`None`) is left untouched, so the `sslmode` from
/// the url is honored by sqlx's rustls backend (prefer/require/verify-ca/
/// verify-full all work).
fn apply_host_override(
    opts: PgConnectOptions,
    host_override: &Option<(String, u16)>,
) -> PgConnectOptions {
    match host_override {
        Some((host, port)) => opts.host(host).port(*port).ssl_mode(PgSslMode::Disable),
        None => opts,
    }
}

impl Postgres {
    /// Build the connect options (layer 2 + the tunnel override) and run the
    /// handshake under its own generous deadline. Shared by `execute` and
    /// `schema`, so introspection gets the same read-only, timeout-capped
    /// session as a query.
    async fn connect(&self) -> Result<sqlx::PgConnection, EngineError> {
        // Never echo the url on a parse error: it may embed credentials.
        let opts: PgConnectOptions = self.url.parse().map_err(|_| EngineError::Connect {
            message: "the `url` for this connection is not a valid PostgreSQL URL".to_string(),
            hint: "use the form postgres://user@host:port/dbname; put the password in the \
                   env var named by password_env, not in the url"
                .to_string(),
        })?;
        // Layer 2: the SERVER enforces read-only and the timeout, independent
        // of the client. `.options()` becomes libpq `-c key=value` startup
        // options (statement_timeout in bare milliseconds).
        let opts = opts
            .options([
                ("default_transaction_read_only", "on".to_string()),
                ("statement_timeout", self.statement_timeout_ms.to_string()),
            ])
            .application_name("nyet");
        let opts = match &self.password {
            Some(pw) => opts.password(pw),
            // No password_env: try trust/peer auth (local dev). An auth
            // failure surfaces as CONNECTION_FAILED with a hint below.
            None => opts,
        };
        // If a tunnel is up, connect to its local end (127.0.0.1:<port>)
        // instead of the url's host — everything else from the url is kept.
        let opts = apply_host_override(opts, &self.host_override);
        // Bound connect on its OWN generous deadline so a hung TCP handshake
        // (firewall blackhole: SYN accepted, handshake never completes) is
        // CONNECTION_FAILED (exit 6) instead of hanging — see connect_deadline
        // (it is NOT the query timeout; a legit connect may take seconds).
        let deadline = self
            .connect_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| connect_deadline(self.statement_timeout_ms));
        match tokio::time::timeout(deadline, opts.connect()).await {
            Ok(r) => r.map_err(pg_connect_error),
            Err(_elapsed) => Err(EngineError::Connect {
                message: "the connection to the PostgreSQL database did not complete in time"
                    .to_string(),
                hint: "check the host/port in `url` and that the server is reachable \
                       (a firewall may be dropping the connection)"
                    .to_string(),
            }),
        }
    }
}

impl Engine for Postgres {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError> {
        let mut conn = self.connect().await?;

        // Bound the QUERY phase on the effective per-query budget (connect above
        // has its OWN generous deadline). Keeping the two timers separate means a
        // slow/hung connect is always CONNECTION_FAILED (exit 6) and only a slow
        // QUERY is TIMEOUT (exit 8), deterministic regardless of --timeout size.
        // Complements the server statement_timeout (57014); whichever fires, 8.
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, async move {
            if let Err(e) = Postgres::begin_read_only(&mut conn).await {
                let _ = conn.close().await;
                return Err(e);
            }

            let mut columns: Vec<String> = Vec::new();
            let mut rows: Vec<Vec<Value>> = Vec::new();
            let fetched = {
                let mut stream = sqlx::query(sqlx::AssertSqlSafe(sql.to_string())).fetch(&mut conn);
                loop {
                    if (rows.len() as u64) >= fetch_limit {
                        break Ok(());
                    }
                    match stream.try_next().await {
                        Ok(Some(row)) => {
                            if columns.is_empty() {
                                columns =
                                    row.columns().iter().map(|c| c.name().to_string()).collect();
                            }
                            match decode_pg_row(&row) {
                                Ok(r) => rows.push(r),
                                Err(e) => break Err(e),
                            }
                        }
                        Ok(None) => break Ok(()),
                        Err(e) => break Err(pg_error(e)),
                    }
                }
            };
            // Empty result -> no columns from the stream; ask the prepared
            // statement so table/csv output still has a header (best effort).
            if fetched.is_ok() && rows.is_empty() && columns.is_empty() {
                use sqlx::{Executor, SqlSafeStr, Statement};
                let sql_str = sqlx::AssertSqlSafe(sql.to_string()).into_sql_str();
                if let Ok(statement) = conn.prepare(sql_str).await {
                    columns = statement
                        .columns()
                        .iter()
                        .map(|c| c.name().to_string())
                        .collect();
                }
            }
            pg_close_read_only(conn).await;
            fetched?;
            Ok::<ResultSet, EngineError>(ResultSet { columns, rows })
        })
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<Schema, EngineError> {
        let mut conn = self.connect().await?;
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, async move {
            if let Err(e) = Postgres::begin_read_only(&mut conn).await {
                let _ = conn.close().await;
                return Err(e);
            }
            let schema = pg_schema(&mut conn, table).await;
            pg_close_read_only(conn).await;
            schema
        })
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }
}

impl Postgres {
    /// Layer 2, client half: an explicit read-only transaction (belt and
    /// suspenders over the connection's `default_transaction_read_only`) — the
    /// read runs inside it, a smuggled write fails. Shared by execute/schema,
    /// mirroring `Mysql::begin_read_only`.
    async fn begin_read_only(conn: &mut sqlx::PgConnection) -> Result<(), EngineError> {
        use sqlx::Executor;
        conn.execute("BEGIN READ ONLY").await.map_err(pg_error)?;
        Ok(())
    }
}

/// Read-only: nothing to persist, so rollback (cheaper than commit) and close
/// the connection gracefully. Best effort — the answer is already in hand.
async fn pg_close_read_only(mut conn: sqlx::PgConnection) {
    use sqlx::Executor;
    let _ = conn.execute("ROLLBACK").await;
    let _ = conn.close().await;
}

/// The shared WHERE tail of the four pg_catalog queries. No agent text: the
/// `[table]` argument arrives as the bound `$1`/`$2` (name / schema), and the
/// system schemas are excluded by literals. `'pg\_%'` escapes the LIKE
/// wildcard, so it means the literal prefix `pg_` (pg_catalog, pg_toast,
/// pg_temp_*) — user schemas cannot start with `pg_` (reserved).
///
/// **The privilege checks are the security half (SECURITY).** pg_catalog is
/// world-readable, so without them `nyet schema` would hand the agent every
/// table of every schema the role cannot even see — including DEFAULT
/// expressions, which are literal data (secrets get parked in defaults). With
/// them the answer matches what the role could actually SELECT, the way
/// MySQL's information_schema already filters itself. `has_any_column_privilege`,
/// not `has_table_privilege`: a `GRANT SELECT (col) ON t` makes `SELECT col
/// FROM t` work, so the table must be introspectable too (the columns query
/// then hides the columns that were not granted).
///
/// A bare `[table]` also matches its lowercase form: PostgreSQL folds
/// unquoted identifiers to lowercase, so `nyet schema pg ORGS` must find
/// `orgs` — as `SELECT * FROM ORGS` would. (If both `ORGS` and `orgs` exist,
/// both are returned; qualify or quote to pin one down.)
const PG_FILTER: &str = "n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_%' \
     AND has_schema_privilege(n.oid, 'USAGE') AND has_any_column_privilege(c.oid, 'SELECT') \
     AND ($1::text IS NULL OR c.relname = $1 OR c.relname = lower($1)) \
     AND ($2::text IS NULL OR n.nspname = $2 OR n.nspname = lower($2))";

/// Ordinary + partitioned + foreign tables, views and materialized views. A
/// foreign table reads like a table (it just lives elsewhere), so a role with
/// SELECT on one must find it here. (information_schema cannot answer this: it
/// has no index catalog — hence pg_catalog throughout.)
const PG_RELKINDS: &str = "c.relkind IN ('r','p','f','v','m')";

/// `public` is on the default search_path, so its objects read as bare names;
/// everything else is schema-qualified — which is also the form the `[table]`
/// argument accepts back.
fn pg_display(schema: &str, name: &str) -> String {
    if schema == "public" {
        name.to_string()
    } else {
        format!("{schema}.{name}")
    }
}

/// Split the agent's `[table]` argument into `(schema, name)`. Both halves are
/// bound as parameters, never interpolated; an unqualified name matches in
/// every non-system schema.
fn split_qualified(table: &str) -> (Option<&str>, &str) {
    match table.split_once('.') {
        Some((schema, name)) => (Some(schema), name),
        None => (None, table),
    }
}

/// PostgreSQL introspection: four pg_catalog queries (objects, columns,
/// constraints, indexes) grouped back together by table. Every one of them is a
/// constant string plus the two bound filter parameters.
async fn pg_schema(
    conn: &mut sqlx::PgConnection,
    table: Option<&str>,
) -> Result<Schema, EngineError> {
    let (schema_filter, name_filter) = match table {
        Some(t) => {
            let (schema, name) = split_qualified(t);
            (schema, Some(name))
        }
        None => (None, None),
    };
    // AssertSqlSafe: the SQL below is entirely nyet's own constant text (the
    // agent's argument travels as bind parameters), it is dynamic only because
    // the shared WHERE tail is composed with format!.
    let objects = sqlx::query(sqlx::AssertSqlSafe(format!(
        // full_sel: table-wide SELECT, so the columns query cannot have held
        // anything back. Without it the role got in through a column-level
        // GRANT and every key over an invisible column must be dropped.
        "SELECT n.nspname::text AS schema, c.relname::text AS name, c.relkind::text AS kind, \
         has_table_privilege(c.oid, 'SELECT') AS full_sel \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE {PG_RELKINDS} AND {PG_FILTER} ORDER BY 1, 2"
    )))
    .bind(name_filter)
    .bind(schema_filter)
    .fetch_all(&mut *conn)
    .await
    .map_err(pg_error)?;

    // Keyed by (schema, name), NOT by display name: `public."a.b"` and table
    // `b` in schema `a` share a display name and would otherwise merge into one
    // object. The display name is applied only on the way out (pg_objects).
    let mut parts: BTreeMap<(String, String), TableParts> = BTreeMap::new();
    for row in &objects {
        let kind: String = row.try_get("kind").map_err(pg_error)?;
        let kind = if kind == "v" || kind == "m" {
            "view"
        } else {
            "table"
        };
        let full_sel: bool = row.try_get("full_sel").unwrap_or(false);
        parts.insert(pg_key(row)?, TableParts::new(kind, full_sel));
    }
    if over_detail_limit(table, parts.len()) {
        return Ok(listing(pg_objects(parts)));
    }

    let columns = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT n.nspname::text AS schema, c.relname::text AS name, a.attname::text AS column, \
         format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull AS notnull, \
         COALESCE(pg_get_expr(d.adbin, d.adrelid), \
                  CASE WHEN a.attidentity <> '' THEN 'generated as identity' END) AS \"default\" \
         FROM pg_attribute a \
         JOIN pg_class c ON c.oid = a.attrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
         WHERE a.attnum > 0 AND NOT a.attisdropped \
         AND has_column_privilege(c.oid, a.attnum, 'SELECT') \
         AND {PG_RELKINDS} AND {PG_FILTER} \
         ORDER BY 1, 2, a.attnum"
    )))
    .bind(name_filter)
    .bind(schema_filter)
    .fetch_all(&mut *conn)
    .await
    .map_err(pg_error)?;
    for row in &columns {
        let Some(entry) = parts.get_mut(&pg_key(row)?) else {
            continue;
        };
        entry.columns.push(SchemaColumn {
            name: row.try_get("column").map_err(pg_error)?,
            ty: row.try_get("type").map_err(pg_error)?,
            nullable: !row.try_get::<bool, _>("notnull").map_err(pg_error)?,
            pk: false,
            unique: false,
            default: row.try_get("default").map_err(pg_error)?,
        });
    }

    // Primary keys and foreign keys in one pass over pg_constraint; the column
    // names come back as ordered arrays (conkey/confkey are attnum vectors).
    let constraints = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT n.nspname::text AS schema, c.relname::text AS name, con.contype::text AS contype, \
         (SELECT array_agg(att.attname::text ORDER BY u.ord) \
            FROM unnest(con.conkey) WITH ORDINALITY AS u(attnum, ord) \
            JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = u.attnum) AS cols, \
         fns.nspname::text AS ref_schema, ft.relname::text AS ref_table, \
         (SELECT array_agg(att.attname::text ORDER BY u.ord) \
            FROM unnest(con.confkey) WITH ORDINALITY AS u(attnum, ord) \
            JOIN pg_attribute att ON att.attrelid = con.confrelid AND att.attnum = u.attnum) AS ref_cols \
         FROM pg_constraint con \
         JOIN pg_class c ON c.oid = con.conrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         LEFT JOIN pg_class ft ON ft.oid = con.confrelid \
         LEFT JOIN pg_namespace fns ON fns.oid = ft.relnamespace \
         WHERE con.contype IN ('p','f') AND {PG_FILTER} ORDER BY 1, 2, con.conname"
    )))
    .bind(name_filter)
    .bind(schema_filter)
    .fetch_all(&mut *conn)
    .await
    .map_err(pg_error)?;
    for row in &constraints {
        let Some(entry) = parts.get_mut(&pg_key(row)?) else {
            continue;
        };
        let contype: String = row.try_get("contype").map_err(pg_error)?;
        let cols: Vec<String> = row
            .try_get::<Option<Vec<String>>, _>("cols")
            .ok()
            .flatten()
            .unwrap_or_default();
        if contype == "p" {
            entry.pk = cols;
            continue;
        }
        let (Ok(ref_schema), Ok(ref_table)) = (
            row.try_get::<String, _>("ref_schema"),
            row.try_get::<String, _>("ref_table"),
        ) else {
            continue;
        };
        entry.fks.push(SchemaFk {
            columns: cols,
            ref_table: pg_display(&ref_schema, &ref_table),
            ref_columns: row
                .try_get::<Option<Vec<String>>, _>("ref_cols")
                .ok()
                .flatten()
                .unwrap_or_default(),
        });
    }

    // Indexes, one row per key column, for real tables only (a materialized
    // view is reported as a view, and a view never carries indexes on any
    // engine). The PRIMARY KEY index is skipped (the pk flags carry it); a
    // unique index over a single column is folded into that column's `unique`
    // flag by build_table. Expression keys have attnum 0, so pg_get_indexdef
    // supplies their text. `unique` is claimed only for a valid, unconditional
    // index: a partial one (indpred) holds for its predicate rows only, and an
    // invalid one (a failed CREATE INDEX CONCURRENTLY) enforces nothing.
    let indexes = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT n.nspname::text AS schema, c.relname::text AS name, i.relname::text AS idx, \
         (ix.indisunique AND ix.indpred IS NULL AND ix.indisvalid) AS is_unique, \
         a.attname::text AS col, \
         pg_get_indexdef(ix.indexrelid, k.ord::int, true) AS expr \
         FROM pg_index ix \
         JOIN pg_class c ON c.oid = ix.indrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_class i ON i.oid = ix.indexrelid \
         CROSS JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) \
         LEFT JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum \
         WHERE NOT ix.indisprimary AND k.ord <= ix.indnkeyatts \
         AND c.relkind IN ('r','p') AND {PG_FILTER} \
         ORDER BY 1, 2, 3, k.ord"
    )))
    .bind(name_filter)
    .bind(schema_filter)
    .fetch_all(&mut *conn)
    .await
    .map_err(pg_error)?;
    for row in &indexes {
        let Some(entry) = parts.get_mut(&pg_key(row)?) else {
            continue;
        };
        let index_name: String = row.try_get("idx").map_err(pg_error)?;
        // attnum 0 -> no column, an expression: pg_get_indexdef spells it out.
        let part = match row.try_get::<Option<String>, _>("col").map_err(pg_error)? {
            Some(name) => KeyPart::Named(name),
            None => KeyPart::Expression(Some(row.try_get("expr").map_err(pg_error)?)),
        };
        let unique: bool = row.try_get("is_unique").map_err(pg_error)?;
        push_index_column(&mut entry.indexes, index_name, part, unique);
    }

    Ok(assemble(pg_objects(parts)))
}

/// The catalog grouping key of a row: (schema, name).
fn pg_key(row: &PgRow) -> Result<(String, String), EngineError> {
    Ok((
        row.try_get("schema").map_err(pg_error)?,
        row.try_get("name").map_err(pg_error)?,
    ))
}

/// Grouped parts -> the display names the contract shows.
fn pg_objects(parts: BTreeMap<(String, String), TableParts>) -> Vec<(String, TableParts)> {
    parts
        .into_iter()
        .map(|((schema, name), p)| (pg_display(&schema, &name), p))
        .collect()
}

/// Catalog rows arrive one key column at a time, ordered by index name — so a
/// row either extends the index being built or starts a new one. Shared by the
/// Postgres and MySQL introspection (both group the same way).
fn push_index_column(indexes: &mut Vec<SchemaIndex>, name: String, part: KeyPart, unique: bool) {
    match indexes.last_mut() {
        Some(last) if last.name == name => last.columns.push(part),
        _ => indexes.push(SchemaIndex {
            name,
            columns: vec![part],
            unique,
        }),
    }
}

fn decode_pg_row(row: &PgRow) -> Result<Vec<Value>, EngineError> {
    (0..row.len()).map(|i| decode_pg_column(row, i)).collect()
}

/// Decode one PostgreSQL cell into JSON by its wire type. Types real tables
/// are full of are handled explicitly; anything else falls back to a text
/// decode and, failing that, a clear DB_ERROR (never a panic — Д3).
///
/// Representation choices (DEV.md): numeric -> string (exact, no f64
/// rounding), timestamp/date/time -> ISO-ish string, uuid -> string,
/// json/jsonb -> structured JSON as-is, bytea -> lowercase hex (as SQLite
/// BLOB), NULL -> null.
fn decode_pg_column(row: &PgRow, i: usize) -> Result<Value, EngineError> {
    let raw = row.try_get_raw(i).map_err(pg_error)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let ty = raw.type_info().name().to_string();
    use sqlx::types::chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
    use sqlx::types::{BigDecimal, Uuid};
    // None => no typed decoder for this type (text family / exotic). Some(Err)
    // => a typed decoder that could not represent the value ('NaN'::numeric has
    // no BigDecimal, 'infinity'::timestamptz has no chrono value). Both go to
    // the text fallback: a text decode recovers text-compatible types, and
    // anything else gets a "::text-cast" DB_ERROR — never pg_error's misleading
    // "check the schema" hint (the schema is fine; the value just isn't JSON-able).
    let typed: Option<Result<Value, sqlx::Error>> = match ty.as_str() {
        "BOOL" => Some(row.try_get::<bool, _>(i).map(Value::from)),
        "INT2" => Some(row.try_get::<i16, _>(i).map(|v| Value::from(v as i64))),
        "INT4" => Some(row.try_get::<i32, _>(i).map(|v| Value::from(v as i64))),
        "INT8" => Some(row.try_get::<i64, _>(i).map(Value::from)),
        "FLOAT4" => Some(row.try_get::<f32, _>(i).map(|v| number_or_string(v as f64))),
        "FLOAT8" => Some(row.try_get::<f64, _>(i).map(number_or_string)),
        "NUMERIC" => Some(
            row.try_get::<BigDecimal, _>(i)
                .map(|d| Value::String(d.to_string())),
        ),
        "UUID" => Some(
            row.try_get::<Uuid, _>(i)
                .map(|u| Value::String(u.to_string())),
        ),
        "JSON" | "JSONB" => Some(row.try_get::<Value, _>(i)),
        "TIMESTAMP" => Some(
            row.try_get::<NaiveDateTime, _>(i)
                .map(|t| Value::String(t.to_string())),
        ),
        "TIMESTAMPTZ" => Some(
            row.try_get::<DateTime<Utc>, _>(i)
                .map(|t| Value::String(t.to_rfc3339())),
        ),
        "DATE" => Some(
            row.try_get::<NaiveDate, _>(i)
                .map(|d| Value::String(d.to_string())),
        ),
        "TIME" => Some(
            row.try_get::<NaiveTime, _>(i)
                .map(|t| Value::String(t.to_string())),
        ),
        // ponytail: bytea -> hex string; dedicated binary handling can land if
        // agents actually query blobs. Same convention as the SQLite engine.
        "BYTEA" => Some(row.try_get::<Vec<u8>, _>(i).map(|b| Value::String(hex(&b)))),
        // Text family (TEXT/VARCHAR/CHAR/NAME/UNKNOWN) and everything exotic
        // (arrays, inet, ranges, ...): straight to the text fallback. ponytail:
        // arrays and exotic types come back only when text-decodable; otherwise
        // the query gets a ::text-cast DB_ERROR — add per-type arms if agents
        // need them structured.
        _ => None,
    };
    match typed {
        Some(Ok(v)) => Ok(v),
        _ => decode_pg_text_fallback(row, i, &ty),
    }
}

fn decode_pg_text_fallback(row: &PgRow, i: usize, ty: &str) -> Result<Value, EngineError> {
    match row.try_get::<String, _>(i) {
        Ok(s) => Ok(Value::String(s)),
        Err(_) => Err(EngineError::Db {
            message: format!("nyet cannot serialize a value of PostgreSQL type {ty} to JSON"),
            hint: "cast the column to text in the query (e.g. col::text) and retry".to_string(),
        }),
    }
}

/// JSON has no NaN/Infinity; fall back to a string for non-finite floats.
fn number_or_string(x: f64) -> Value {
    serde_json::Number::from_f64(x)
        .map(Value::Number)
        .unwrap_or_else(|| Value::String(x.to_string()))
}

/// Connection/auth failures -> CONNECTION_FAILED (exit 6). The driver's
/// message names the failing user on auth errors but never the password. A TLS
/// handshake/cert failure gets a TLS-specific hint (pointing at sslmode and the
/// server certificate) instead of the misleading "check host/creds" one.
fn pg_connect_error(e: sqlx::Error) -> EngineError {
    EngineError::Connect {
        message: format!(
            "cannot connect to the PostgreSQL database: {}",
            error_text(&e)
        ),
        hint: if is_tls_error(&e) {
            tls_hint()
        } else {
            "check the host/port in `url` and the credentials; set password_env to the \
             env var holding the password for this connection"
                .to_string()
        },
    }
}

/// True when a DIRECT server connection's transport is NOT guaranteed encrypted
/// and verified: the url's `sslmode`/`ssl-mode` is below `require`/`REQUIRED`
/// (absent -> the sqlx default `prefer`/`preferred`, which uses TLS only if the
/// server offers it and otherwise silently falls back to plaintext). Static —
/// it parses the url only, no server round-trip — so over-warning against a
/// server that happens to negotiate TLS is accepted: we report the *guarantee*,
/// not the runtime outcome. SQLite and unparseable urls -> false (the cli gates
/// this on a server engine, and a bad url fails later at connect anyway).
pub fn transport_below_require(engine: &str, url: &str) -> bool {
    match engine {
        "postgres" => url.parse::<PgConnectOptions>().is_ok_and(|o| {
            matches!(
                o.get_ssl_mode(),
                PgSslMode::Disable | PgSslMode::Allow | PgSslMode::Prefer
            )
        }),
        "mysql" | "mariadb" => url.parse::<MySqlConnectOptions>().is_ok_and(|o| {
            matches!(
                o.get_ssl_mode(),
                MySqlSslMode::Disabled | MySqlSslMode::Preferred
            )
        }),
        _ => false,
    }
}

/// A TLS handshake / certificate-verification failure (`sqlx::Error::Tls`).
/// Its Display describes the cert/handshake problem and never carries the url
/// or password, so it is safe to surface via `error_text`.
fn is_tls_error(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Tls(_))
}

/// Shared hint for a TLS failure on the direct (non-tunnelled) leg. Neutral by
/// design: `sqlx::Error::Tls` covers BOTH "the server does not support TLS" (so
/// require/verify-* cannot be satisfied) and "the certificate failed
/// verification" — without reliably distinguishing them, so the hint names both
/// causes rather than always advising to relax the mode.
fn tls_hint() -> String {
    "TLS could not be established: the server may not support TLS, or its certificate \
     failed verification — check the server's TLS config and the sslmode/ssl-mode in `url` \
     (for a private CA point sslrootcert=/ssl-ca= at its certificate)"
        .to_string()
}

/// Query-time errors. The server's own statement_timeout (57014) maps to
/// TIMEOUT (exit 8), matching the cli's tokio timeout, so the exit code is
/// deterministic regardless of which fires. 57014 is query_canceled generally,
/// so a MANUAL cancel from another session (pg_cancel_backend) also lands here
/// as TIMEOUT — expected case is our statement_timeout, the manual cancel is
/// rare and TIMEOUT is a reasonable classification for it. Everything else is
/// DB_ERROR.
fn pg_error(e: sqlx::Error) -> EngineError {
    if let sqlx::Error::Database(db) = &e {
        if db.code().as_deref() == Some("57014") {
            return EngineError::Timeout {
                message: "the query exceeded the timeout and was cancelled by the server"
                    .to_string(),
                hint: "narrow the query (WHERE / LIMIT), or raise --timeout or timeout_secs \
                       in the config"
                    .to_string(),
            };
        }
    }
    EngineError::Db {
        message: format!("the database returned an error: {}", error_text(&e)),
        hint: "check the query against the actual schema, e.g. SELECT table_name FROM \
               information_schema.tables WHERE table_schema = 'public'"
            .to_string(),
    }
}

/// MySQL/MariaDB via sqlx. Layer 2 (DESIGN §3): each read runs inside an
/// explicit `START TRANSACTION READ ONLY`, so a write that slipped past the
/// validator is refused by the database (ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION),
/// and a server-side statement timeout cancels a runaway query.
///
/// The server timeout variable differs by flavor and the two are mutually
/// exclusive (each server rejects the other's name with ER_UNKNOWN_SYSTEM_VARIABLE
/// 1193): MySQL uses `max_execution_time` (milliseconds, SELECT-only), MariaDB
/// uses `max_statement_time` (seconds). We set BOTH and swallow the wrong-flavor
/// 1193 on each, so the real server always gets a server-side cap regardless of
/// the config `engine` label — the tokio timeout only bounds the client, it does
/// not stop a runaway server scan. Both timeout SQLSTATEs (3024 / 1969) map to
/// EngineError::Timeout so the exit code is deterministic (like Postgres 57014).
pub struct Mysql {
    /// The `url` from the config (no password embedded by convention).
    pub url: String,
    /// Read from `password_env` by the cli; never logged/printed.
    pub password: Option<String>,
    /// The per-query wall budget in ms (MySQL `max_execution_time`; the MariaDB
    /// `max_statement_time` is the same budget in seconds).
    pub statement_timeout_ms: u64,
    /// The effective per-query wall budget in ms: the in-process deadline that
    /// wraps the query phase (AFTER connect), backstopping the server-side
    /// max_execution_time/max_statement_time so a runaway query is TIMEOUT
    /// (exit 8) whichever fires.
    pub query_timeout_ms: u64,
    /// When an SSH tunnel is up, `(127.0.0.1, local_port)` to connect through.
    pub host_override: Option<(String, u16)>,
    /// Test-only override for the connect handshake deadline (ms); see the same
    /// field on `Postgres`. Production passes `None`.
    pub connect_timeout_ms: Option<u64>,
}

/// Redirect host+port to the tunnel's local end while keeping user/db/params
/// from the url; force `ssl_mode=Disabled` on the tunnel leg (the ssh hop
/// already encrypts, and TLS verification against 127.0.0.1 would fail against a
/// cert naming the real host). The DIRECT path (`None`) is left untouched, so
/// the `ssl-mode` from the url is honored by sqlx's rustls backend. Pure —
/// unit-tested.
fn apply_mysql_host_override(
    opts: MySqlConnectOptions,
    host_override: &Option<(String, u16)>,
) -> MySqlConnectOptions {
    match host_override {
        Some((host, port)) => opts.host(host).port(*port).ssl_mode(MySqlSslMode::Disabled),
        None => opts,
    }
}

impl Mysql {
    /// Connect options (password + tunnel override) and the handshake under its
    /// own generous deadline. Shared by `execute` and `schema`.
    async fn connect(&self) -> Result<sqlx::MySqlConnection, EngineError> {
        // Never echo the url on a parse error: it may embed credentials.
        let opts: MySqlConnectOptions = self.url.parse().map_err(|_| EngineError::Connect {
            message: "the `url` for this connection is not a valid MySQL URL".to_string(),
            hint: "use the form mysql://user@host:port/dbname; put the password in the \
                   env var named by password_env, not in the url"
                .to_string(),
        })?;
        let opts = match &self.password {
            Some(pw) => opts.password(pw),
            None => opts,
        };
        let opts = apply_mysql_host_override(opts, &self.host_override);
        // Bound connect on its own generous deadline so a hung TCP handshake is
        // CONNECTION_FAILED (exit 6) instead of hanging — same as Postgres (see
        // connect_deadline; it is NOT the query timeout).
        let deadline = self
            .connect_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| connect_deadline(self.statement_timeout_ms));
        match tokio::time::timeout(deadline, opts.connect()).await {
            Ok(r) => r.map_err(mysql_connect_error),
            Err(_elapsed) => Err(EngineError::Connect {
                message: "the connection to the MySQL database did not complete in time"
                    .to_string(),
                hint: "check the host/port in `url` and that the server is reachable \
                       (a firewall may be dropping the connection)"
                    .to_string(),
            }),
        }
    }

    /// Layer 2 for MySQL/MariaDB: the server-side statement timeout plus an
    /// explicit read-only transaction. Shared by `execute` and `schema`.
    ///
    /// MySQL and MariaDB use different, mutually exclusive timeout variables
    /// (ms vs seconds), so set BOTH and swallow the wrong-flavor
    /// ER_UNKNOWN_SYSTEM_VARIABLE (1193) on each independently — the real server
    /// always ends up capped regardless of the config label.
    async fn begin_read_only(&self, conn: &mut sqlx::MySqlConnection) -> Result<(), EngineError> {
        use sqlx::Executor;
        let secs = (self.statement_timeout_ms / 1000).max(1);
        for stmt in [
            // MySQL milliseconds; MariaDB seconds. (>= 1; 0 = "no limit".)
            format!(
                "SET SESSION max_execution_time = {}",
                self.statement_timeout_ms.max(1)
            ),
            format!("SET SESSION max_statement_time = {secs}"),
        ] {
            if let Err(e) = conn.execute(sqlx::AssertSqlSafe(stmt)).await {
                if !is_unknown_var(&e) {
                    // The caller closes the connection on this path (it owns it).
                    return Err(mysql_error(e));
                }
            }
        }
        conn.execute("START TRANSACTION READ ONLY")
            .await
            .map_err(mysql_error)?;
        Ok(())
    }
}

/// Read-only: rollback (nothing to persist) and close gracefully — a proper
/// COM_QUIT rather than a dropped socket. Best effort, like the Postgres twin.
async fn mysql_close_read_only(mut conn: sqlx::MySqlConnection) {
    use sqlx::Executor;
    let _ = conn.execute("ROLLBACK").await;
    let _ = conn.close().await;
}

impl Engine for Mysql {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError> {
        let mut conn = self.connect().await?;

        // Bound the QUERY phase (everything below, after a successful connect)
        // on the effective per-query budget; connect above has its own generous
        // deadline. Split timers => a slow/hung connect is CONNECTION_FAILED
        // (exit 6) and only a slow QUERY is TIMEOUT (exit 8), deterministic
        // regardless of --timeout size. Backstops the server-side
        // max_execution_time/max_statement_time; whichever fires, exit 8.
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, async move {
            if let Err(e) = self.begin_read_only(&mut conn).await {
                let _ = conn.close().await;
                return Err(e);
            }

            // ponytail: the fetch loop / empty-columns-via-prepare / rollback+close
            // tail below is structurally the same as Postgres's (only the
            // row-decode and error-map fns differ). Extract a shared `stream_rows`
            // helper if a third server engine lands — two copies isn't worth a
            // generic yet.
            let mut columns: Vec<String> = Vec::new();
            let mut rows: Vec<Vec<Value>> = Vec::new();
            let fetched = {
                let mut stream = sqlx::query(sqlx::AssertSqlSafe(sql.to_string())).fetch(&mut conn);
                loop {
                    if (rows.len() as u64) >= fetch_limit {
                        break Ok(());
                    }
                    match stream.try_next().await {
                        Ok(Some(row)) => {
                            if columns.is_empty() {
                                columns =
                                    row.columns().iter().map(|c| c.name().to_string()).collect();
                            }
                            match decode_mysql_row(&row) {
                                Ok(r) => rows.push(r),
                                Err(e) => break Err(e),
                            }
                        }
                        Ok(None) => break Ok(()),
                        Err(e) => break Err(mysql_error(e)),
                    }
                }
            };
            // Empty result -> ask the prepared statement for columns (best effort).
            if fetched.is_ok() && rows.is_empty() && columns.is_empty() {
                use sqlx::{Executor, SqlSafeStr, Statement};
                let sql_str = sqlx::AssertSqlSafe(sql.to_string()).into_sql_str();
                if let Ok(statement) = conn.prepare(sql_str).await {
                    columns = statement
                        .columns()
                        .iter()
                        .map(|c| c.name().to_string())
                        .collect();
                }
            }
            mysql_close_read_only(conn).await;
            fetched?;
            Ok::<ResultSet, EngineError>(ResultSet { columns, rows })
        })
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }

    async fn schema(&self, table: Option<&str>) -> Result<Schema, EngineError> {
        let mut conn = self.connect().await?;
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, async move {
            if let Err(e) = self.begin_read_only(&mut conn).await {
                let _ = conn.close().await;
                return Err(e);
            }
            let schema = mysql_schema(&mut conn, table).await;
            mysql_close_read_only(conn).await;
            schema
        })
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
        }
    }
}

/// MySQL/MariaDB introspection: four information_schema queries scoped to the
/// connection's own database (`DATABASE()`), grouped back together by table.
/// The `[table]` argument is bound (`?`), never interpolated — it is bound
/// twice because MySQL placeholders are positional.
async fn mysql_schema(
    conn: &mut sqlx::MySqlConnection,
    table: Option<&str>,
) -> Result<Schema, EngineError> {
    let objects = sqlx::query(
        "SELECT TABLE_NAME AS name, TABLE_TYPE AS kind FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND (? IS NULL OR TABLE_NAME = ?) ORDER BY TABLE_NAME",
    )
    .bind(table)
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(mysql_error)?;
    let mut parts: BTreeMap<String, TableParts> = BTreeMap::new();
    for row in &objects {
        let name: String = row.try_get("name").map_err(mysql_error)?;
        let kind: String = row.try_get("kind").map_err(mysql_error)?;
        let kind = match kind.as_str() {
            "BASE TABLE" => "table",
            "VIEW" => "view",
            // SYSTEM VIEW / SEQUENCE / anything else: not a readable relation
            // the agent asked about.
            _ => continue,
        };
        // information_schema.COLUMNS is privilege-filtered by the server, but
        // it never says WHETHER it withheld anything — so the key filter always
        // runs. With full privileges every named part is visible and nothing is
        // dropped; the cost is only paid by a column-granted account.
        parts.insert(name, TableParts::new(kind, false));
    }
    if over_detail_limit(table, parts.len()) {
        return Ok(listing(parts.into_iter().collect()));
    }

    let columns = sqlx::query(
        "SELECT TABLE_NAME AS name, COLUMN_NAME AS col, COLUMN_TYPE AS type, \
         IS_NULLABLE AS nullable, COLUMN_DEFAULT AS def, EXTRA AS extra \
         FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND (? IS NULL OR TABLE_NAME = ?) \
         ORDER BY TABLE_NAME, ORDINAL_POSITION",
    )
    .bind(table)
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(mysql_error)?;
    for row in &columns {
        let key: String = row.try_get("name").map_err(mysql_error)?;
        let Some(entry) = parts.get_mut(&key) else {
            continue;
        };
        let extra: String = row.try_get("extra").unwrap_or_default();
        let default: Option<String> = row.try_get("def").unwrap_or(None);
        entry.columns.push(SchemaColumn {
            name: row.try_get("col").map_err(mysql_error)?,
            ty: row.try_get("type").map_err(mysql_error)?,
            nullable: row.try_get::<String, _>("nullable").unwrap_or_default() != "NO",
            pk: false,
            unique: false,
            // MySQL reports auto-increment in EXTRA, not COLUMN_DEFAULT; surface
            // it as the default so the agent sees the column is auto-assigned.
            default: default.or_else(|| {
                extra
                    .to_lowercase()
                    .contains("auto_increment")
                    .then(|| "auto_increment".to_string())
            }),
        });
    }

    let indexes = sqlx::query(
        "SELECT TABLE_NAME AS name, INDEX_NAME AS idx, NON_UNIQUE AS non_unique, \
         COLUMN_NAME AS col FROM information_schema.STATISTICS \
         WHERE TABLE_SCHEMA = DATABASE() AND (? IS NULL OR TABLE_NAME = ?) \
         ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
    )
    .bind(table)
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(mysql_error)?;
    for row in &indexes {
        let key: String = row.try_get("name").map_err(mysql_error)?;
        let Some(entry) = parts.get_mut(&key) else {
            continue;
        };
        let index_name: String = row.try_get("idx").map_err(mysql_error)?;
        // NULL for a functional key part (MySQL 8 `((lower(x)))`): kept as an
        // Expression part so the key arity survives. STATISTICS.EXPRESSION
        // would hold its text, but MySQL 8 has that column and MariaDB does
        // not — no text (None) works on both.
        let part = match row.try_get::<Option<String>, _>("col") {
            Ok(Some(name)) => KeyPart::Named(name),
            _ => KeyPart::Expression(None),
        };
        // The primary key is always named PRIMARY; its index is redundant with
        // the pk column flags. (A pk part is always a real column.)
        if index_name == "PRIMARY" {
            if let KeyPart::Named(name) = part {
                entry.pk.push(name);
            }
            continue;
        }
        let unique = row.try_get::<i64, _>("non_unique").unwrap_or(1) == 0;
        push_index_column(&mut entry.indexes, index_name, part, unique);
    }

    let fks = sqlx::query(
        // A foreign key may point at another database; qualify the parent then,
        // the way PostgreSQL qualifies anything outside `public`.
        "SELECT TABLE_NAME AS name, CONSTRAINT_NAME AS con, COLUMN_NAME AS col, \
         IF(REFERENCED_TABLE_SCHEMA = DATABASE(), REFERENCED_TABLE_NAME, \
            CONCAT(REFERENCED_TABLE_SCHEMA, '.', REFERENCED_TABLE_NAME)) AS ref_table, \
         REFERENCED_COLUMN_NAME AS ref_col \
         FROM information_schema.KEY_COLUMN_USAGE \
         WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL \
         AND (? IS NULL OR TABLE_NAME = ?) \
         ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION",
    )
    .bind(table)
    .bind(table)
    .fetch_all(&mut *conn)
    .await
    .map_err(mysql_error)?;
    // Rows are one key column each, ordered by table+constraint: a row either
    // extends the fk being built or starts a new one. Grouped in a plain Vec
    // first (like sqlite_fks), then attached — no bookkeeping across borrows.
    let mut grouped: Vec<(String, String, SchemaFk)> = Vec::new();
    for row in &fks {
        let key: String = row.try_get("name").map_err(mysql_error)?;
        let constraint: String = row.try_get("con").map_err(mysql_error)?;
        let column: String = row.try_get("col").map_err(mysql_error)?;
        let ref_table: String = row.try_get("ref_table").map_err(mysql_error)?;
        let ref_column: String = row.try_get("ref_col").map_err(mysql_error)?;
        match grouped.last_mut() {
            Some((last_table, last_con, fk)) if *last_table == key && *last_con == constraint => {
                fk.columns.push(column);
                fk.ref_columns.push(ref_column);
            }
            _ => grouped.push((
                key,
                constraint,
                SchemaFk {
                    columns: vec![column],
                    ref_table,
                    ref_columns: vec![ref_column],
                },
            )),
        }
    }
    for (key, _, fk) in grouped {
        if let Some(entry) = parts.get_mut(&key) {
            entry.fks.push(fk);
        }
    }

    Ok(assemble(parts.into_iter().collect()))
}

fn decode_mysql_row(row: &MySqlRow) -> Result<Vec<Value>, EngineError> {
    (0..row.len())
        .map(|i| decode_mysql_column(row, i))
        .collect()
}

/// Decode one MySQL/MariaDB cell into JSON by its wire type (names from
/// sqlx's `MySqlTypeInfo`). Representation (DEV.md): signed ints -> number,
/// unsigned ints & BIT -> number (BIGINT UNSIGNED as u64, may exceed i64),
/// DECIMAL -> string (exact), FLOAT/DOUBLE -> number, text/ENUM -> string,
/// DATE/DATETIME/TIMESTAMP/TIME -> string, binary/BLOB -> lowercase hex,
/// JSON -> structured JSON, NULL -> null. Anything else falls back to a text
/// decode and, failing that, a clear ::CHAR-cast DB_ERROR (never a panic, Д3).
fn decode_mysql_column(row: &MySqlRow, i: usize) -> Result<Value, EngineError> {
    let raw = row.try_get_raw(i).map_err(mysql_error)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let ty = raw.type_info().name().to_string();
    use sqlx::mysql::types::MySqlTime;
    use sqlx::types::chrono::{NaiveDate, NaiveDateTime};
    use sqlx::types::BigDecimal;
    // Some(Err) (a typed decoder that could not represent the value) and None
    // (no typed arm) both fall through to the text fallback — same shape as
    // decode_pg_column.
    let typed: Option<Result<Value, sqlx::Error>> = match ty.as_str() {
        "BOOLEAN" | "TINYINT" | "SMALLINT" | "INT" | "MEDIUMINT" | "BIGINT" | "YEAR" => {
            Some(row.try_get::<i64, _>(i).map(Value::from))
        }
        // Unsigned ints and BIT are all uint-decodable; BIGINT UNSIGNED can
        // exceed i64, so decode as u64 (serde_json Number holds it exactly).
        "TINYINT UNSIGNED" | "SMALLINT UNSIGNED" | "INT UNSIGNED" | "MEDIUMINT UNSIGNED"
        | "BIGINT UNSIGNED" | "BIT" => Some(row.try_get::<u64, _>(i).map(Value::from)),
        "FLOAT" => Some(row.try_get::<f32, _>(i).map(|v| number_or_string(v as f64))),
        "DOUBLE" => Some(row.try_get::<f64, _>(i).map(number_or_string)),
        "DECIMAL" => Some(
            row.try_get::<BigDecimal, _>(i)
                .map(|d| Value::String(d.to_string())),
        ),
        "JSON" => Some(row.try_get::<Value, _>(i)),
        "DATE" => Some(
            row.try_get::<NaiveDate, _>(i)
                .map(|d| Value::String(d.to_string())),
        ),
        "DATETIME" | "TIMESTAMP" => Some(
            row.try_get::<NaiveDateTime, _>(i)
                .map(|t| Value::String(t.to_string())),
        ),
        // MySqlTime, not chrono::NaiveTime: MySQL TIME spans -838:59:59..838:59:59
        // (a duration, can be negative / exceed 24h), which NaiveTime cannot hold
        // — decoding a normal such column as NaiveTime would DB_ERROR.
        "TIME" => Some(
            row.try_get::<MySqlTime, _>(i)
                .map(|t| Value::String(t.to_string())),
        ),
        "VARCHAR" | "CHAR" | "TEXT" | "TINYTEXT" | "MEDIUMTEXT" | "LONGTEXT" | "ENUM" => {
            Some(row.try_get::<String, _>(i).map(Value::String))
        }
        // ponytail: binary/blob -> lowercase hex; same convention as Postgres
        // bytea and SQLite BLOB. A dedicated representation can land if needed.
        "BINARY" | "VARBINARY" | "BLOB" | "TINYBLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
            Some(row.try_get::<Vec<u8>, _>(i).map(|b| Value::String(hex(&b))))
        }
        // SET, GEOMETRY and anything exotic: text fallback, then a ::CHAR-cast
        // DB_ERROR if that fails too.
        _ => None,
    };
    match typed {
        Some(Ok(v)) => Ok(v),
        _ => decode_mysql_text_fallback(row, i, &ty),
    }
}

fn decode_mysql_text_fallback(row: &MySqlRow, i: usize, ty: &str) -> Result<Value, EngineError> {
    match row.try_get::<String, _>(i) {
        Ok(s) => Ok(Value::String(s)),
        Err(_) => Err(EngineError::Db {
            message: format!("nyet cannot serialize a value of MySQL type {ty} to JSON"),
            hint: "cast the column to text in the query (e.g. CAST(col AS CHAR)) and retry"
                .to_string(),
        }),
    }
}

/// Connection/auth failures -> CONNECTION_FAILED (exit 6). The driver names
/// the failing user on auth errors but never the password.
fn mysql_connect_error(e: sqlx::Error) -> EngineError {
    EngineError::Connect {
        message: format!("cannot connect to the MySQL database: {}", error_text(&e)),
        hint: if is_tls_error(&e) {
            tls_hint()
        } else {
            "check the host/port in `url` and the credentials; set password_env to the \
             env var holding the password for this connection"
                .to_string()
        },
    }
}

/// Query-time errors. The server statement timeout maps to TIMEOUT (exit 8) so
/// the exit code is deterministic: MySQL raises 3024 (max_execution_time) and
/// MariaDB 1969 (max_statement_time). Everything else is DB_ERROR.
fn mysql_error(e: sqlx::Error) -> EngineError {
    if let Some(n) = mysql_err_number(&e) {
        if n == 3024 || n == 1969 {
            return EngineError::Timeout {
                message: "the query exceeded the timeout and was cancelled by the server"
                    .to_string(),
                hint: "narrow the query (WHERE / LIMIT), or raise --timeout or timeout_secs \
                       in the config"
                    .to_string(),
            };
        }
    }
    EngineError::Db {
        message: format!("the database returned an error: {}", error_text(&e)),
        hint: "check the query against the actual schema, e.g. SHOW TABLES or \
               SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
            .to_string(),
    }
}

/// The MySQL/MariaDB error number (1193 = unknown system variable, 3024 /
/// 1969 = statement timeout), or None for non-database errors.
fn mysql_err_number(e: &sqlx::Error) -> Option<u16> {
    e.as_database_error()
        .and_then(|db| db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .map(|m| m.number())
}

/// ER_UNKNOWN_SYSTEM_VARIABLE (1193): the server does not know the timeout
/// variable we tried (wrong flavor) — swallowed, tokio timeout is the backstop.
fn is_unknown_var(e: &sqlx::Error) -> bool {
    mysql_err_number(e) == Some(1193)
}

fn decode_row(row: &SqliteRow) -> Result<Vec<Value>, EngineError> {
    (0..row.len()).map(|i| decode_column(row, i)).collect()
}

/// Decode by the value's storage class. SQLite values are NULL/INTEGER/
/// REAL/TEXT/BLOB; declared column types (DATE, BOOLEAN, ...) fall through
/// to the closest JSON-able form.
fn decode_column(row: &SqliteRow, i: usize) -> Result<Value, EngineError> {
    let raw = row.try_get_raw(i).map_err(db_error)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let value = match raw.type_info().name() {
        "INTEGER" | "BOOLEAN" => row.try_get::<i64, _>(i).map(Value::from),
        // number_or_string: SQLite can store infinities (e.g. 9e999), which
        // JSON cannot — shared with the Postgres float path so the non-finite
        // handling never drifts between engines.
        "REAL" | "NUMERIC" => row.try_get::<f64, _>(i).map(number_or_string),
        // ponytail: blobs come back as a lowercase hex string; a dedicated
        // representation can land if agents actually query binary data.
        "BLOB" => row.try_get::<Vec<u8>, _>(i).map(|b| Value::String(hex(&b))),
        // TEXT and declared date/time types. Decoded as bytes + lossy UTF-8:
        // sqlite does not enforce encoding, and one broken cell must not
        // fail the whole query.
        _ => row
            .try_get::<Vec<u8>, _>(i)
            .map(|b| Value::String(String::from_utf8_lossy(&b).into_owned())),
    };
    value.map_err(db_error)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn db_error(e: sqlx::Error) -> EngineError {
    EngineError::Db {
        message: format!("the database returned an error: {}", error_text(&e)),
        hint: "check the query against the actual schema, e.g. \
               SELECT name, sql FROM sqlite_master WHERE type = 'table'"
            .to_string(),
    }
}

/// For database-level errors prefer the driver's bare message over
/// sqlx's wrapper text.
fn error_text(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(db) => db.message().to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn make_db(path: &std::path::Path) {
        block_on(async {
            let mut conn = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .connect()
                .await
                .unwrap();
            sqlx::query(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, score REAL, data BLOB)",
            )
            .execute(&mut conn)
            .await
            .unwrap();
            sqlx::query("INSERT INTO t VALUES (1, 'a', 1.5, x'00ff'), (2, NULL, NULL, NULL)")
                .execute(&mut conn)
                .await
                .unwrap();
            conn.close().await.unwrap();
        });
    }

    /// Layer 2: a write that bypasses the validator entirely (direct Engine
    /// call) still fails, because the file is opened read-only.
    #[test]
    fn mode_ro_rejects_writes_that_bypass_the_validator() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 30_000,
        };
        let err = block_on(engine.execute("INSERT INTO t (id) VALUES (99)", 10)).err();
        match err {
            Some(EngineError::Db { message, .. }) => {
                assert!(message.contains("readonly"), "{message}")
            }
            _ => panic!("write must fail against a read-only connection"),
        }
        // And the database is intact.
        let rs = block_on(engine.execute("SELECT count(*) AS n FROM t", 10))
            .ok()
            .unwrap();
        assert_eq!(rs.rows, vec![vec![Value::from(2)]]);
    }

    /// The tunnel override swaps host+port to the local forward but keeps the
    /// user, database and query params (and the password stays separate).
    #[test]
    fn host_override_swaps_host_port_keeps_user_db_params() {
        let opts: PgConnectOptions = "postgres://nyet_ro@db.internal:5432/app?application_name=x"
            .parse()
            .unwrap();
        let opts = apply_host_override(opts, &Some(("127.0.0.1".to_string(), 61234)));
        assert_eq!(opts.get_host(), "127.0.0.1");
        assert_eq!(opts.get_port(), 61234);
        assert_eq!(opts.get_username(), "nyet_ro");
        assert_eq!(opts.get_database(), Some("app"));
        // sslmode forced to disable on the tunnel leg (the ssh tunnel already
        // encrypts the loopback hop; TLS verification against 127.0.0.1 would
        // fail anyway). The direct leg honors the url's sslmode — see the
        // container tests.
        assert!(matches!(opts.get_ssl_mode(), PgSslMode::Disable));
        // None -> unchanged.
        let opts2: PgConnectOptions = "postgres://u@h:6000/d".parse().unwrap();
        let opts2 = apply_host_override(opts2, &None);
        assert_eq!(opts2.get_host(), "h");
        assert_eq!(opts2.get_port(), 6000);
    }

    #[test]
    fn decodes_all_storage_classes() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 30_000,
        };
        let rs = block_on(engine.execute("SELECT * FROM t ORDER BY id", 10))
            .ok()
            .unwrap();
        assert_eq!(rs.columns, ["id", "name", "score", "data"]);
        assert_eq!(
            rs.rows[0],
            vec![
                Value::from(1),
                Value::from("a"),
                Value::from(1.5),
                Value::from("00ff")
            ]
        );
        assert_eq!(
            rs.rows[1],
            vec![Value::from(2), Value::Null, Value::Null, Value::Null]
        );
    }

    #[test]
    fn fetch_limit_stops_reading() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 30_000,
        };
        let rs = block_on(engine.execute("SELECT id FROM t", 1))
            .ok()
            .unwrap();
        assert_eq!(rs.rows.len(), 1);
    }

    #[test]
    fn invalid_utf8_text_is_decoded_lossily() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 30_000,
        };
        // CAST(x'80ff' AS TEXT): a TEXT value that is not valid UTF-8 —
        // must come back with replacement chars, not fail the query.
        let rs = block_on(engine.execute("SELECT CAST(x'80ff' AS TEXT) AS t", 10))
            .ok()
            .unwrap();
        assert_eq!(rs.rows[0][0], Value::from("\u{FFFD}\u{FFFD}"));
    }

    #[test]
    fn empty_result_still_reports_columns() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 30_000,
        };
        let rs = block_on(engine.execute("SELECT id, name FROM t WHERE 0 = 1", 10))
            .ok()
            .unwrap();
        assert!(rs.rows.is_empty());
        assert_eq!(rs.columns, ["id", "name"]);
    }

    #[test]
    fn missing_file_is_connect_error() {
        let engine = Sqlite {
            path: PathBuf::from("/no/such/file.db"),
            query_timeout_ms: 30_000,
        };
        match block_on(engine.execute("SELECT 1", 10)) {
            Err(EngineError::Connect { message, hint }) => {
                assert!(message.contains("/no/such/file.db"), "{message}");
                assert!(!hint.is_empty());
            }
            _ => panic!("missing file must be a Connect error"),
        }
    }

    /// The query-phase timeout now lives INSIDE `execute` (the cli no longer
    /// wraps it in an outer timeout), and for sqlite it is the ONLY query bound
    /// (no server-side timeout). A heavy recursive CTE with a tiny budget must
    /// map to Timeout (exit 8). No Docker. The runtime is shut down in the
    /// background (like the cli) so the abandoned sqlite worker — which keeps
    /// grinding the CTE until it finishes — does not block the test.
    #[test]
    fn sqlite_query_timeout_maps_to_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("t.db");
        make_db(&db);
        let engine = Sqlite {
            path: db,
            query_timeout_ms: 150,
        };
        // Bounded-but-huge recursive CTE: far more than 150ms of work, yet
        // finite so the background worker eventually stops on its own.
        let sql = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c \
                   WHERE n < 50000000) SELECT count(*) FROM c";
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(engine.execute(sql, 10));
        rt.shutdown_background();
        match result {
            Err(EngineError::Timeout { .. }) => {}
            other => {
                panic!("a heavy query past the in-process budget must be Timeout, got {other:?}")
            }
        }
    }

    /// The INSECURE_TRANSPORT decision (pure, no network): a url whose
    /// sslmode/ssl-mode is absent or below require flags true; require and
    /// stricter flag false. The cli additionally gates it on there being no ssh
    /// tunnel.
    #[test]
    fn transport_below_require_flags_weak_sslmodes() {
        // Absent -> sqlx default (prefer/preferred) -> below require -> warn.
        assert!(transport_below_require("mysql", "mysql://u@h:3306/db"));
        assert!(transport_below_require("mariadb", "mysql://u@h:3306/db"));
        assert!(transport_below_require(
            "postgres",
            "postgres://u@h:5432/db"
        ));
        // Explicitly forced at/above require -> no warn.
        assert!(!transport_below_require(
            "mysql",
            "mysql://u@h:3306/db?ssl-mode=REQUIRED"
        ));
        assert!(!transport_below_require(
            "mysql",
            "mysql://u@h:3306/db?ssl-mode=VERIFY_IDENTITY"
        ));
        assert!(!transport_below_require(
            "postgres",
            "postgres://u@h:5432/db?sslmode=require"
        ));
        assert!(!transport_below_require(
            "postgres",
            "postgres://u@h:5432/db?sslmode=verify-full"
        ));
        // sqlite / unknown engine -> never (no network transport to warn about).
        assert!(!transport_below_require("sqlite", ""));
    }

    // --- PostgreSQL: needs Docker (colima). Requires a reachable daemon;
    // fails (not skips) without one, so CI with a docker service runs it. ---

    /// Multi-thread runtime: testcontainers + the Postgres TCP driver need
    /// full IO, unlike the time-only runtime the SQLite tests use.
    fn pg_block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    async fn writable(url: &str) -> sqlx::PgConnection {
        let opts: PgConnectOptions = url.parse().unwrap();
        opts.password("postgres").connect().await.unwrap()
    }

    /// A hung TCP handshake (SYN accepted, no server response) is classified as
    /// CONNECTION_FAILED, not a query TIMEOUT. No Docker: a std listener that
    /// accepts and then goes silent stands in for a firewall blackhole. Uses the
    /// injected short `connect_timeout_ms` (500ms) so the test finishes fast
    /// instead of waiting out the 10s production floor, and is deterministic
    /// without the cli's outer timeout in play.
    #[test]
    fn postgres_hung_connect_is_connection_failed_not_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept connections and hold them open, never replying to the startup
        // packet — the sqlx handshake blocks until our connect deadline.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => held.push(s), // keep the socket open, send nothing
                    Err(_) => break,
                }
            }
        });
        let engine = Postgres {
            url: format!("postgres://postgres@127.0.0.1:{port}/postgres"),
            password: Some("postgres".to_string()),
            statement_timeout_ms: 30_000,
            // Tiny QUERY budget on purpose: it must NOT misclassify a slow/hung
            // CONNECT as a query Timeout. The query timer is armed only after a
            // successful connect, which never happens here — the connect deadline
            // (500ms) fires first -> Connect (exit 6), not Timeout (exit 8).
            query_timeout_ms: 100,
            host_override: None,
            connect_timeout_ms: Some(500), // short so the hang test finishes fast
        };
        match pg_block_on(engine.execute("SELECT 1", 10)) {
            Err(EngineError::Connect { hint, .. }) => {
                assert!(
                    hint.contains("host") || hint.contains("reachable"),
                    "{hint}"
                )
            }
            other => panic!("hung handshake must be a Connect error, got {other:?}"),
        }
    }

    /// Layer 2 held by the real database, plus type decoding and the server
    /// statement_timeout -> Timeout mapping — one container, several checks.
    #[test]
    fn postgres_layer2_types_and_timeout() {
        use sqlx::Executor;
        use testcontainers_modules::postgres::Postgres as PgImage;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;
        use testcontainers_modules::testcontainers::ImageExt;

        pg_block_on(async {
            let container = PgImage::default()
                .with_tag("16-alpine")
                .start()
                .await
                .expect("start postgres:16-alpine (is docker/colima running?)");
            let port = container.get_host_port_ipv4(5432).await.unwrap();
            let url = format!("postgres://postgres@127.0.0.1:{port}/postgres");

            // Seed with a writable connection.
            let mut w = writable(&url).await;
            w.execute(
                "CREATE TABLE t (id int primary key, name text, price numeric, \
                 uid uuid, doc jsonb, ts timestamptz, flag bool, blob bytea)",
            )
            .await
            .unwrap();
            w.execute(
                "INSERT INTO t VALUES \
                 (1, 'a', 12345.67, '00000000-0000-0000-0000-000000000001', \
                 '{\"k\":1}', '2024-01-02T03:04:05Z', true, '\\x00ff'), \
                 (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
            )
            .await
            .unwrap();
            w.close().await.unwrap();

            let engine = Postgres {
                url: url.clone(),
                password: Some("postgres".to_string()),
                statement_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };

            // Layer 2: a write bypassing the validator fails at the database
            // (the read-only transaction refuses it, SQLSTATE 25006).
            match engine.execute("INSERT INTO t (id) VALUES (99)", 10).await {
                Err(EngineError::Db { message, .. }) => {
                    assert!(message.to_lowercase().contains("read-only"), "{message}")
                }
                _ => panic!("a write must fail inside the read-only transaction"),
            }
            // ...and the table is intact.
            let rs = engine
                .execute("SELECT count(*) AS n FROM t", 10)
                .await
                .unwrap();
            assert_eq!(rs.rows, vec![vec![Value::from(2)]]);

            // Type decoding across the common Postgres types.
            let rs = engine
                .execute(
                    "SELECT id, name, price, uid, doc, ts, flag, blob FROM t WHERE id = 1",
                    10,
                )
                .await
                .unwrap();
            assert_eq!(
                rs.columns,
                ["id", "name", "price", "uid", "doc", "ts", "flag", "blob"]
            );
            let row = &rs.rows[0];
            assert_eq!(row[0], Value::from(1));
            assert_eq!(row[1], Value::from("a"));
            // numeric -> string (exact, no f64 rounding; trailing zeros are
            // the stored scale, still exact).
            assert!(
                row[2].as_str().unwrap().starts_with("12345.67"),
                "{:?}",
                row[2]
            );
            assert_eq!(row[3], Value::from("00000000-0000-0000-0000-000000000001"));
            // jsonb -> structured JSON as-is.
            assert_eq!(row[4], serde_json::json!({"k": 1}));
            // timestamptz -> ISO string.
            assert!(
                row[5].as_str().unwrap().starts_with("2024-01-02"),
                "{row:?}"
            );
            assert_eq!(row[6], Value::Bool(true));
            // bytea -> lowercase hex, like a SQLite BLOB.
            assert_eq!(row[7], Value::from("00ff"));

            // NULLs across types.
            let rs = engine
                .execute("SELECT name, price, uid, doc FROM t WHERE id = 2", 10)
                .await
                .unwrap();
            assert_eq!(
                rs.rows[0],
                vec![Value::Null, Value::Null, Value::Null, Value::Null]
            );

            // Special values that a typed decoder cannot represent must not get
            // the misleading "check the schema" hint. 'infinity'::float8 fits
            // f64 -> "inf" string; 'NaN'::numeric has no BigDecimal (and sqlx's
            // PgNumeric is pub(crate)), so it falls back to a clear ::text-cast
            // DB_ERROR — the schema is fine, the value just isn't JSON-able.
            let rs = engine
                .execute("SELECT 'infinity'::float8 AS f", 10)
                .await
                .unwrap();
            assert_eq!(rs.rows[0][0], Value::from("inf"));
            match engine.execute("SELECT 'NaN'::numeric AS n", 10).await {
                Err(EngineError::Db { hint, .. }) => {
                    assert!(hint.contains("text"), "wrong hint for NaN numeric: {hint}")
                }
                other => panic!("NaN numeric should be a ::text-cast DB_ERROR, got {other:?}"),
            }

            // jsonb numbers beyond f64 keep full precision (serde_json
            // arbitrary_precision), not silently rounded.
            let big = "123456789012345678901234567890";
            let rs = engine
                .execute(&format!("SELECT '{{\"n\":{big}}}'::jsonb AS j"), 10)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_string(&rs.rows[0][0]).unwrap(),
                format!("{{\"n\":{big}}}"),
                "jsonb big integer must not be rounded"
            );

            // fetch_limit stops the stream early.
            let rs = engine
                .execute("SELECT id FROM t ORDER BY id", 1)
                .await
                .unwrap();
            assert_eq!(rs.rows.len(), 1);

            // Server statement_timeout (57014) maps to Timeout, not Db. The
            // client query timer is left generous (30s) so the SERVER cancels
            // first — this test still proves the 57014 path, not the client one.
            let slow = Postgres {
                url: url.clone(),
                password: Some("postgres".to_string()),
                statement_timeout_ms: 300,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            match slow
                .execute(
                    "SELECT count(*) FROM generate_series(1, 100000000000) g",
                    10,
                )
                .await
            {
                Err(EngineError::Timeout { .. }) => {}
                _ => panic!("server statement_timeout must map to EngineError::Timeout"),
            }

            // The rustls backend makes `sslmode` honored on the DIRECT leg: this
            // alpine container runs with ssl=off, so `sslmode=require` MUST fail
            // the connect (proof that `require` is enforced, not silently ignored
            // / downgraded to plaintext) and carries a TLS-specific hint.
            let tls_required = Postgres {
                url: format!("postgres://postgres@127.0.0.1:{port}/postgres?sslmode=require"),
                password: Some("postgres".to_string()),
                statement_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            match tls_required.execute("SELECT 1", 10).await {
                Err(EngineError::Connect { hint, .. }) => {
                    assert!(
                        hint.contains("TLS"),
                        "require without server TLS wants a TLS hint: {hint}"
                    )
                }
                other => panic!(
                    "sslmode=require against a non-TLS server must fail to connect, got {other:?}"
                ),
            }

            drop(container);
        });
    }

    // --- MySQL/MariaDB: needs Docker (colima). mysql:8.4 is used (real JSON
    // type + max_execution_time, the variable DESIGN §3 names). ---

    #[test]
    fn mysql_host_override_swaps_host_port_keeps_user_db_forces_disable() {
        let opts: MySqlConnectOptions = "mysql://nyet_ro@db.internal:3306/app".parse().unwrap();
        let opts = apply_mysql_host_override(opts, &Some(("127.0.0.1".to_string(), 61234)));
        assert_eq!(opts.get_host(), "127.0.0.1");
        assert_eq!(opts.get_port(), 61234);
        assert_eq!(opts.get_username(), "nyet_ro");
        assert_eq!(opts.get_database(), Some("app"));
        // sslmode forced to Disabled on the tunnel leg (ssh already encrypts;
        // the direct leg honors the url's ssl-mode — see the container tests).
        assert!(matches!(opts.get_ssl_mode(), MySqlSslMode::Disabled));
        // None -> unchanged.
        let opts2: MySqlConnectOptions = "mysql://u@h:6000/d".parse().unwrap();
        let opts2 = apply_mysql_host_override(opts2, &None);
        assert_eq!(opts2.get_host(), "h");
        assert_eq!(opts2.get_port(), 6000);
    }

    /// A hung TCP handshake is CONNECTION_FAILED, not a query TIMEOUT — the
    /// injected short `connect_timeout_ms` (500ms) fires (mirrors the Postgres
    /// test; no Docker).
    #[test]
    fn mysql_hung_connect_is_connection_failed_not_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        let engine = Mysql {
            url: format!("mysql://root@127.0.0.1:{port}/test"),
            password: None,
            statement_timeout_ms: 30_000,
            // Tiny QUERY budget on purpose: a slow/hung CONNECT must stay
            // Connect (exit 6), never a query Timeout — the query timer arms
            // only after connect, which never completes here.
            query_timeout_ms: 100,
            host_override: None,
            connect_timeout_ms: Some(500), // short so the hang test finishes fast
        };
        match pg_block_on(engine.execute("SELECT 1", 10)) {
            Err(EngineError::Connect { hint, .. }) => {
                assert!(
                    hint.contains("host") || hint.contains("reachable"),
                    "{hint}"
                )
            }
            other => panic!("hung handshake must be a Connect error, got {other:?}"),
        }
    }

    async fn mysql_writable(url: &str) -> sqlx::MySqlConnection {
        let opts: MySqlConnectOptions = url.parse().unwrap();
        opts.connect().await.unwrap()
    }

    /// Layer 2 held by the real database, type decoding and the server
    /// max_execution_time -> Timeout mapping — one container, several checks.
    #[test]
    fn mysql_layer2_types_and_timeout() {
        use sqlx::Executor;
        use testcontainers_modules::mysql::Mysql as MysqlImage;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;
        use testcontainers_modules::testcontainers::ImageExt;

        pg_block_on(async {
            let container = MysqlImage::default()
                .with_tag("8.4")
                .start()
                .await
                .expect("start mysql:8.4 (is docker/colima running?)");
            let port = container.get_host_port_ipv4(3306).await.unwrap();
            // Root has an empty password (MYSQL_ALLOW_EMPTY_PASSWORD), db `test`.
            let url = format!("mysql://root@127.0.0.1:{port}/test");

            let mut w = mysql_writable(&url).await;
            w.execute(
                "CREATE TABLE t (id int primary key, name varchar(255), price decimal(10,2), \
                 big bigint unsigned, flag boolean, doc json, dt datetime, bin varbinary(16), \
                 bits bit(8))",
            )
            .await
            .unwrap();
            w.execute(
                "INSERT INTO t VALUES \
                 (1, 'a', 12345.67, 18446744073709551615, true, '{\"k\":1}', \
                 '2024-01-02 03:04:05', x'00ff', b'10000000'), \
                 (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
            )
            .await
            .unwrap();
            w.close().await.unwrap();

            let engine = Mysql {
                url: url.clone(),
                password: None,
                statement_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };

            // Layer 2: a write bypassing the validator fails at the database
            // (the read-only transaction refuses it).
            match engine.execute("INSERT INTO t (id) VALUES (99)", 10).await {
                Err(EngineError::Db { message, .. }) => {
                    assert!(message.to_lowercase().contains("read only"), "{message}")
                }
                other => {
                    panic!("a write must fail inside the read-only transaction, got {other:?}")
                }
            }
            // ...and the table is intact.
            let rs = engine
                .execute("SELECT count(*) AS n FROM t", 10)
                .await
                .unwrap();
            assert_eq!(rs.rows, vec![vec![Value::from(2)]]);

            // Type decoding across the common MySQL types.
            let rs = engine
                .execute(
                    "SELECT id, name, price, big, flag, doc, dt, bin, bits FROM t WHERE id = 1",
                    10,
                )
                .await
                .unwrap();
            let row = &rs.rows[0];
            // BIT(8) = 0x80 -> lossless number (sqlx decodes BIT via u64: big-
            // endian bytes accumulated into an integer). NOT a DB_ERROR — pins
            // that BIT is a normal, serializable column. (Hex would need the raw
            // bytes, which sqlx keeps pub(crate), and the byte width, which the
            // type name drops — so a number is the faithful representation.)
            assert_eq!(row[8], Value::from(128), "BIT decode: {:?}", row[8]);
            assert_eq!(row[0], Value::from(1)); // INT
            assert_eq!(row[1], Value::from("a")); // VARCHAR
                                                  // DECIMAL -> string (exact, no f64 rounding).
            assert!(
                row[2].as_str().unwrap().starts_with("12345.67"),
                "{:?}",
                row[2]
            );
            // BIGINT UNSIGNED at the u64 ceiling stays exact (would overflow i64).
            assert_eq!(row[3], Value::from(u64::MAX));
            // BOOLEAN is TINYINT(1) -> number.
            assert_eq!(row[4], Value::from(1));
            // JSON -> structured JSON as-is.
            assert_eq!(row[5], serde_json::json!({"k": 1}));
            // DATETIME -> string.
            assert!(
                row[6].as_str().unwrap().starts_with("2024-01-02"),
                "{row:?}"
            );
            // VARBINARY -> lowercase hex.
            assert_eq!(row[7], Value::from("00ff"));

            // TIME across MySQL's full duration range (negative and > 24h), which
            // chrono::NaiveTime cannot hold — decoded via MySqlTime, so a normal
            // column reads back as a string instead of a DB_ERROR.
            let rs = engine
                .execute(
                    "SELECT CAST('-25:00:00' AS TIME) AS a, CAST('838:59:59' AS TIME) AS b",
                    10,
                )
                .await
                .unwrap();
            assert_eq!(rs.rows[0][0], Value::from("-25:00:00"), "{:?}", rs.rows[0]);
            assert_eq!(rs.rows[0][1], Value::from("838:59:59"), "{:?}", rs.rows[0]);

            // NULLs across types.
            let rs = engine
                .execute("SELECT name, price, doc, dt FROM t WHERE id = 2", 10)
                .await
                .unwrap();
            assert_eq!(
                rs.rows[0],
                vec![Value::Null, Value::Null, Value::Null, Value::Null]
            );

            // fetch_limit stops the stream early.
            let rs = engine
                .execute("SELECT id FROM t ORDER BY id", 1)
                .await
                .unwrap();
            assert_eq!(rs.rows.len(), 1);

            // Server max_execution_time -> Timeout (exit 8), not Db. A big
            // cross join is a read-only SELECT (so max_execution_time applies)
            // and cannot finish inside 1s. sleep()/benchmark() are denylisted,
            // so this is the heavy-read path used in the e2e test too.
            let slow = Mysql {
                url: url.clone(),
                password: None,
                statement_timeout_ms: 1000,
                // Generous client timer so the SERVER max_execution_time /
                // max_statement_time cancels first — preserves the server-path
                // proof; the client timer is just the backstop.
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            match slow
                .execute(
                    "SELECT count(*) FROM information_schema.columns a, \
                     information_schema.columns b, information_schema.columns c",
                    10,
                )
                .await
            {
                Err(EngineError::Timeout { .. }) => {}
                other => panic!("server max_execution_time must map to Timeout, got {other:?}"),
            }

            container.rm().await.unwrap();
        });
    }

    /// TLS + `caching_sha2_password` + a real password — the headline win of the
    /// rustls backend. MySQL 8 auto-generates a self-signed server cert and
    /// enables TLS at init; a `caching_sha2_password` user (the 8.x default auth
    /// plugin) can send its password over the encrypted channel. `ssl-mode=REQUIRED`
    /// demands TLS but does NOT verify the CA, so the self-signed cert is accepted.
    /// Before the TLS feature this exact connection failed at auth (the removed
    /// "MySQL 8 password needs TLS" limitation) — this is the direct-leg proof.
    #[test]
    fn mysql8_caching_sha2_password_over_tls() {
        use sqlx::Executor;
        use testcontainers_modules::mysql::Mysql as MysqlImage;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;
        use testcontainers_modules::testcontainers::ImageExt;

        pg_block_on(async {
            let container = MysqlImage::default()
                .with_tag("8.4")
                .start()
                .await
                .expect("start mysql:8.4 (is docker/colima running?)");
            let port = container.get_host_port_ipv4(3306).await.unwrap();
            let root_url = format!("mysql://root@127.0.0.1:{port}/test");

            // Seed as root (empty password = fast auth, needs no TLS/RSA): create
            // a caching_sha2_password user WITH a password and a readable table.
            let mut w = mysql_writable(&root_url).await;
            w.execute(
                "CREATE USER 'nyet_tls'@'%' IDENTIFIED WITH caching_sha2_password BY 'sup3r-secret'",
            )
            .await
            .unwrap();
            w.execute("GRANT SELECT ON test.* TO 'nyet_tls'@'%'")
                .await
                .unwrap();
            w.execute("CREATE TABLE tls_t (id int primary key, name text)")
                .await
                .unwrap();
            w.execute("INSERT INTO tls_t VALUES (1, 'ok')")
                .await
                .unwrap();
            w.close().await.unwrap();

            // The password travels over the TLS channel; ssl-mode=REQUIRED (from
            // the url, honored on the direct leg) accepts the self-signed cert.
            let engine = Mysql {
                url: format!("mysql://nyet_tls@127.0.0.1:{port}/test?ssl-mode=REQUIRED"),
                password: Some("sup3r-secret".to_string()),
                statement_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            let rs = engine
                .execute("SELECT id, name FROM tls_t", 10)
                .await
                .unwrap();
            assert_eq!(rs.rows, vec![vec![Value::from(1), Value::from("ok")]]);

            container.rm().await.unwrap();
        });
    }

    /// MariaDB proof (mariadb:11.4): the OTHER server-timeout variable
    /// (`max_statement_time`, seconds → SQLSTATE 1969) actually caps a query.
    /// The in-process query timer is left GENEROUS (30s) while the server cap is
    /// 1s, so this ~1-2s query is cancelled by the SERVER, not the client timer —
    /// a `Timeout` result here proves the 1969 path specifically.
    #[test]
    fn mariadb_server_timeout_maps_to_timeout() {
        use testcontainers_modules::mariadb::Mariadb;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;
        use testcontainers_modules::testcontainers::ImageExt;

        pg_block_on(async {
            let container = Mariadb::default()
                .with_tag("11.4")
                .start()
                .await
                .expect("start mariadb:11.4 (is docker/colima running?)");
            let port = container.get_host_port_ipv4(3306).await.unwrap();
            let url = format!("mysql://root@127.0.0.1:{port}/test");

            // The SET landed: a fresh connection reports the max_statement_time
            // the engine set (5s here). Proves the MariaDB variable was accepted
            // (its MySQL sibling got 1193 and was swallowed).
            let e5 = Mysql {
                url: url.clone(),
                password: None,
                statement_timeout_ms: 5000,
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            let rs = e5
                .execute("SELECT @@max_statement_time AS t", 10)
                .await
                .unwrap();
            assert!(
                serde_json::to_string(&rs.rows[0][0]).unwrap().contains('5'),
                "max_statement_time not set: {:?}",
                rs.rows[0]
            );

            // Client query timer generous (30s) vs server cap 1s: this heavy
            // read is cancelled by the SERVER (max_statement_time -> 1969), not
            // the client timer, and mapped to Timeout.
            let slow = Mysql {
                url: url.clone(),
                password: None,
                statement_timeout_ms: 1000,
                // Generous client timer so the SERVER max_execution_time /
                // max_statement_time cancels first — preserves the server-path
                // proof; the client timer is just the backstop.
                query_timeout_ms: 30_000,
                host_override: None,
                connect_timeout_ms: None,
            };
            match slow
                .execute(
                    "SELECT count(*) FROM information_schema.columns a, \
                     information_schema.columns b, information_schema.columns c",
                    10,
                )
                .await
            {
                Err(EngineError::Timeout { .. }) => {}
                other => panic!("MariaDB max_statement_time must map to Timeout, got {other:?}"),
            }

            container.rm().await.unwrap();
        });
    }
}
