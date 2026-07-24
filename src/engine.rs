//! Engines: IO adapters behind the `Engine` trait (Д2). Engines know their
//! drivers (sqlx) and nothing about clap or output; the cli layer maps
//! `EngineError` onto contract codes and wraps execution in a timeout.

use futures_util::TryStreamExt;
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqliteRow};
use sqlx::{Column, ConnectOptions, Connection, Row, TypeInfo, ValueRef};
use std::path::PathBuf;

pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

pub enum EngineError {
    /// The database could not be reached/opened (-> CONNECTION_FAILED, exit 6).
    Connect { message: String, hint: String },
    /// The database accepted the connection but rejected the query
    /// (-> DB_ERROR, exit 7).
    Db { message: String, hint: String },
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
        "REAL" | "NUMERIC" => row.try_get::<f64, _>(i).map(|x| {
            // SQLite can store infinities (e.g. 9e999), which JSON cannot.
            serde_json::Number::from_f64(x)
                .map(Value::Number)
                .unwrap_or_else(|| Value::String(x.to_string()))
        }),
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
}
