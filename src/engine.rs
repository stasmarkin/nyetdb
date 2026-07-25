//! Engines: IO adapters behind the `Engine` trait (Д2). Engines know their
//! drivers (sqlx) and nothing about clap or output; the cli layer maps
//! `EngineError` onto contract codes and wraps execution in a timeout.

use futures_util::TryStreamExt;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgRow, PgSslMode};
use sqlx::sqlite::{SqliteConnectOptions, SqliteRow};
use sqlx::{Column, ConnectOptions, Connection, Row, TypeInfo, ValueRef};
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

/// The one planned abstraction of the project (Д5). Fetches at most
/// `fetch_limit` rows; the caller passes limit+1 to detect truncation.
pub trait Engine {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError>;
}

/// SQLite via sqlx, opened with `mode=ro` (file-level read-only — layer 2:
/// even a write that slipped past the validator fails in the database).
pub struct Sqlite {
    pub path: PathBuf,
}

impl Engine for Sqlite {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError> {
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
        let mut conn = SqliteConnectOptions::new()
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
            })?;
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
                            columns = row.columns().iter().map(|c| c.name().to_string()).collect();
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
        Ok(ResultSet { columns, rows })
    }
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
    /// When an SSH tunnel is up, `(127.0.0.1, local_port)` to connect through
    /// instead of the url's host/port. User/dbname/params from the url stay.
    pub host_override: Option<(String, u16)>,
}

/// Redirect host+port to the tunnel's local end while keeping every other
/// connect option (user, dbname, params, password) from the url. Overriding
/// `PgConnectOptions` is more robust than rewriting the url string. Pure — no
/// IO — so it is unit-tested without a database.
///
/// Also forces `sslmode=disable` on the tunnel leg: the hop to 127.0.0.1 is
/// already encrypted by the ssh tunnel, and this build of sqlx has no TLS
/// backend — a prod url carrying `sslmode=require` would otherwise fail the
/// connect with a misleading "check host/creds" error.
fn apply_host_override(
    opts: PgConnectOptions,
    host_override: &Option<(String, u16)>,
) -> PgConnectOptions {
    match host_override {
        Some((host, port)) => opts.host(host).port(*port).ssl_mode(PgSslMode::Disable),
        None => opts,
    }
}

impl Engine for Postgres {
    async fn execute(&self, sql: &str, fetch_limit: u64) -> Result<ResultSet, EngineError> {
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
        // Bound connect on its OWN deadline so a hung TCP handshake
        // (firewall blackhole: SYN accepted, handshake never completes)
        // is CONNECTION_FAILED (exit 6), not TIMEOUT (exit 8). Set a hair
        // under the effective timeout so this fires before the cli's outer
        // tokio timeout, which wraps connect+query. The query itself stays
        // covered by the server statement_timeout and the outer timeout.
        let connect_deadline = Duration::from_millis(self.statement_timeout_ms.saturating_sub(250));
        let mut conn = match tokio::time::timeout(connect_deadline, opts.connect()).await {
            Ok(r) => r.map_err(pg_connect_error)?,
            Err(_elapsed) => {
                return Err(EngineError::Connect {
                    message: "the connection to the PostgreSQL database did not complete in time"
                        .to_string(),
                    hint: "check the host/port in `url` and that the server is reachable \
                           (a firewall may be dropping the connection)"
                        .to_string(),
                })
            }
        };

        // Explicit read-only transaction (belt and suspenders over the session
        // default): the read runs inside it, and a smuggled write is rejected.
        {
            use sqlx::Executor;
            conn.execute("BEGIN READ ONLY").await.map_err(pg_error)?;
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
                            columns = row.columns().iter().map(|c| c.name().to_string()).collect();
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
        // Read-only: nothing to persist, so rollback (cheaper than commit).
        {
            use sqlx::Executor;
            let _ = conn.execute("ROLLBACK").await;
        }
        let _ = conn.close().await;
        fetched?;
        Ok(ResultSet { columns, rows })
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
/// message names the failing user on auth errors but never the password.
fn pg_connect_error(e: sqlx::Error) -> EngineError {
    EngineError::Connect {
        message: format!(
            "cannot connect to the PostgreSQL database: {}",
            error_text(&e)
        ),
        hint: "check the host/port in `url` and the credentials; set password_env to the \
               env var holding the password for this connection"
            .to_string(),
    }
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
        let engine = Sqlite { path: db };
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
        // sslmode forced to disable on the tunnel leg (no TLS backend; the ssh
        // tunnel already encrypts the loopback hop).
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
        let engine = Sqlite { path: db };
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
        let engine = Sqlite { path: db };
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
        let engine = Sqlite { path: db };
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
        let engine = Sqlite { path: db };
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
        };
        match block_on(engine.execute("SELECT 1", 10)) {
            Err(EngineError::Connect { message, hint }) => {
                assert!(message.contains("/no/such/file.db"), "{message}");
                assert!(!hint.is_empty());
            }
            _ => panic!("missing file must be a Connect error"),
        }
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
    /// accepts and then goes silent stands in for a firewall blackhole. The
    /// connect deadline (statement_timeout_ms - 250) fires, so it is
    /// deterministic without the cli's outer timeout in play.
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
            statement_timeout_ms: 750, // connect deadline = 500ms
            host_override: None,
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
                host_override: None,
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

            // Server statement_timeout (57014) maps to Timeout, not Db.
            let slow = Postgres {
                url: url.clone(),
                password: Some("postgres".to_string()),
                statement_timeout_ms: 300,
                host_override: None,
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

            drop(container);
        });
    }
}
