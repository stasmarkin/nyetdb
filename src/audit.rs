//! Audit log (UX-8): one JSON line per database-touching command, appended to
//! `~/.local/share/nyet/audit.jsonl` for the human's forensics. Split per D1/D2:
//! this module is the pure record builder (`Event` -> compact JSON line, snapshot
//! tested with an injected timestamp) plus the ONE piece of IO the feature needs
//! (`append`: mkdir + create 0600 + advisory-lock + write + flush). Orchestration
//! — deciding what to log, and enforcing fail-closed ordering — lives in the cli.

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// The audit-record schema version. Independent of the JSON-envelope `v`: the
/// forensic record can evolve on its own cadence (append-only fields, like the
/// envelope). Bumped only on a breaking change to the record shape.
pub const AUDIT_V: u8 = 1;

/// The result the agent received, logged only when `[audit] log_responses`.
/// `Rows` keeps the query's column order (the same ordered-object serialization
/// as the output envelope), so the log shows exactly what the agent saw; the
/// other commands hand over their already-structured payload as a `Value`.
pub enum Response {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Value>>,
    },
    Payload(Value),
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Response::Rows { columns, rows } => {
                let mut seq = serializer.serialize_seq(Some(rows.len()))?;
                for row in rows {
                    seq.serialize_element(&Row { columns, row })?;
                }
                seq.end()
            }
            Response::Payload(value) => value.serialize(serializer),
        }
    }
}

/// One response row as an object with keys in column order (serde_json's own
/// Map would sort them) — mirrors `output::RowObject`.
struct Row<'a> {
    columns: &'a [String],
    row: &'a [Value],
}

impl Serialize for Row<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.columns.iter().zip(self.row))
    }
}

/// One audit event. Compact, credential-free by construction: it carries the
/// alias and engine, NEVER the url (which may embed an inline password) or the
/// password itself. The optional fields are omitted when they do not apply, so
/// each command's line stays minimal (UX-4).
#[derive(Serialize)]
pub struct Event<'a> {
    pub audit_v: u8,
    /// ISO 8601 UTC, millisecond precision (`2026-07-26T12:34:56.789Z`).
    pub ts: &'a str,
    /// `query` | `sample` | `schema` | `explain` | `doctor`.
    pub command: &'a str,
    pub alias: &'a str,
    pub engine: &'a str,
    /// The working directory the command ran from (directory-scoping forensics).
    pub cwd: &'a str,
    /// The full SQL the agent submitted (query/explain) — the RAW text, before
    /// the validator's Unicode normalization, so a zero-width-injection attempt
    /// is visible in the log. For `sample` it is the statement NYET wrote: as
    /// the database saw it when the read SUCCEEDED (the human sees what
    /// actually reached their database), as built otherwise — a refused, failed
    /// or timed-out attempt returns no text to log, so the built form is what
    /// there is. Either way `table` below holds the agent's raw argument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<&'a str>,
    /// The table argument (schema/sample), when one was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<&'a str>,
    /// `ok` | `refused` (a NYET verdict) | `error` (any other failure).
    pub verdict: &'a str,
    /// The NYET `reason` on a refusal, or the `error.code` on an error; absent
    /// when `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    pub exit_code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    pub duration_ms: u64,
    /// The warning CODES attached to the answer (the messages are derivable and
    /// would only bloat the log).
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    pub warnings: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<&'a Response>,
}

/// Serialize an event to its one-line JSON form (no trailing newline).
pub fn line(event: &Event) -> String {
    // Internal invariant (D3): our structs and Values serialize infallibly.
    serde_json::to_string(event).expect("audit record serialization cannot fail")
}

/// Append one already-serialized line to the log, durably and without
/// interleaving concurrent writers.
///
/// - **mkdir**: the parent directory is created if missing.
/// - **0600**: the file is created owner-only (it holds the agent's SQL). umask
///   can only clear bits, so the mode is never looser than 0600. An existing
///   file's mode is left as-is (like the config file, nyet does not chmod it).
/// - **no interleaving (CONCURRENCY)**: an advisory exclusive lock
///   (`File::lock`, flock(2) on unix) is held across the write+flush, so two
///   nyet processes appending large (>4 KiB, multi-`write()`) lines cannot mix
///   their bytes. Combined with `O_APPEND`, each line lands whole at the end.
/// - **durability (D9 trade-off)**: the line is written and flushed to the OS
///   (visible to readers, survives a process crash) but NOT `fsync`ed — a
///   per-query fsync would tax every request, and a full OS/power loss losing
///   only the very last record is acceptable for a cooperative-agent forensic
///   log. The meaningful guarantee — the record is committed before the agent
///   gets its result — is the cli's ordering, not fsync.
pub fn append(path: &Path, log_line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // The trail has to be an actual file. A path aimed at /dev/null — directly
    // or through a symlink dropped in place — accepts every line, keeps none,
    // and lets the query answer normally: an audit log silently turned off,
    // which is the exact opposite of the fail-closed promise (UX-8). Refusing
    // here withholds the result instead, exactly as an unwritable log does.
    // Checked on the OPEN handle, so swapping the path afterwards cannot fool
    // the check.
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the audit log path is not a regular file — a device, fifo or socket \
             accepts writes without keeping them",
        ));
    }
    // Blocks until the lock is free; released on unlock (and on drop as a
    // backstop). All nyet writers take it, so it fully serializes appends.
    file.lock()?;
    let result = write_flush(&mut file, log_line);
    let _ = file.unlock();
    result
}

/// The append target. Abstracted ONLY so the partial-write rollback can be
/// fault-injected in a unit test — `File` is the sole real implementation.
trait LogSink: Write {
    fn len(&self) -> std::io::Result<u64>;
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

impl LogSink for std::fs::File {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.metadata()?.len())
    }
    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

/// Append `log_line` + newline as one write, rolling back a PARTIAL write on
/// failure. `write_all` can commit a prefix before erroring (a full disk mid
/// record); left in place it would corrupt every jsonl line below it. Under the
/// still-held flock (no other writer has appended) we restore the file to its
/// pre-write length, so the log stays parseable, then surface the error
/// (-> AUDIT_FAILED, fail-closed intact).
fn write_flush<S: LogSink>(sink: &mut S, log_line: &str) -> std::io::Result<()> {
    let original_len = sink.len()?;
    let mut buf = String::with_capacity(log_line.len() + 1);
    buf.push_str(log_line);
    buf.push('\n');
    match sink.write_all(buf.as_bytes()).and_then(|_| sink.flush()) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = sink.truncate(original_len);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Read;

    const TS: &str = "2026-07-26T12:34:56.789Z";

    fn base<'a>() -> Event<'a> {
        Event {
            audit_v: AUDIT_V,
            ts: TS,
            command: "query",
            alias: "prod",
            engine: "postgres",
            cwd: "/home/u/app",
            sql: None,
            table: None,
            verdict: "ok",
            reason: None,
            exit_code: 0,
            row_count: None,
            truncated: None,
            duration_ms: 42,
            warnings: &[],
            response: None,
        }
    }

    #[test]
    fn query_ok_record_is_compact_and_carries_the_schema_version() {
        let event = Event {
            sql: Some("SELECT id, email FROM users"),
            row_count: Some(3),
            truncated: Some(false),
            ..base()
        };
        assert_eq!(
            line(&event),
            r#"{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/u/app","sql":"SELECT id, email FROM users","verdict":"ok","exit_code":0,"row_count":3,"truncated":false,"duration_ms":42}"#
        );
    }

    #[test]
    fn a_validator_refusal_records_verdict_and_reason() {
        let event = Event {
            sql: Some("DELETE FROM users"),
            verdict: "refused",
            reason: Some("WRITE_OPERATION"),
            exit_code: 5,
            duration_ms: 0,
            ..base()
        };
        assert_eq!(
            line(&event),
            r#"{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/u/app","sql":"DELETE FROM users","verdict":"refused","reason":"WRITE_OPERATION","exit_code":5,"duration_ms":0}"#
        );
    }

    #[test]
    fn a_database_error_records_verdict_error_with_the_error_code() {
        let event = Event {
            sql: Some("SELECT * FROM nope"),
            verdict: "error",
            reason: Some("DB_ERROR"),
            exit_code: 7,
            duration_ms: 0,
            ..base()
        };
        assert_eq!(
            line(&event),
            r#"{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/u/app","sql":"SELECT * FROM nope","verdict":"error","reason":"DB_ERROR","exit_code":7,"duration_ms":0}"#
        );
    }

    #[test]
    fn schema_record_carries_the_table_argument_not_sql() {
        let event = Event {
            command: "schema",
            table: Some("users"),
            ..base()
        };
        assert_eq!(
            line(&event),
            r#"{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"schema","alias":"prod","engine":"postgres","cwd":"/home/u/app","table":"users","verdict":"ok","exit_code":0,"duration_ms":42}"#
        );
    }

    #[test]
    fn explain_and_doctor_records() {
        let explain = Event {
            command: "explain",
            sql: Some("SELECT count(*) FROM events"),
            ..base()
        };
        assert!(line(&explain).contains(r#""command":"explain""#));
        let doctor = Event {
            command: "doctor",
            ..base()
        };
        assert_eq!(
            line(&doctor),
            r#"{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"doctor","alias":"prod","engine":"postgres","cwd":"/home/u/app","verdict":"ok","exit_code":0,"duration_ms":42}"#
        );
    }

    #[test]
    fn warning_codes_are_listed_but_never_the_url_or_password() {
        let warnings = ["TRUNCATED", "INSECURE_TRANSPORT"];
        let event = Event {
            sql: Some("SELECT * FROM t"),
            row_count: Some(1000),
            truncated: Some(true),
            warnings: &warnings,
            ..base()
        };
        let l = line(&event);
        assert!(
            l.contains(r#""warnings":["TRUNCATED","INSECURE_TRANSPORT"]"#),
            "{l}"
        );
        // The record carries alias + engine only, never a connection url or a
        // password (there is nowhere in the Event to put one).
        assert!(!l.contains("postgres://"));
        assert!(!l.contains("password"));
    }

    #[test]
    fn log_responses_on_adds_rows_in_column_order_off_omits_them() {
        let response = Response::Rows {
            columns: vec!["id".into(), "email".into()],
            rows: vec![vec![json!(1), json!("a@b.c")], vec![json!(2), Value::Null]],
        };
        let event = Event {
            sql: Some("SELECT id, email FROM users"),
            row_count: Some(2),
            truncated: Some(false),
            response: Some(&response),
            ..base()
        };
        let l = line(&event);
        // Column order preserved (id before email, not alphabetical).
        assert!(
            l.contains(r#""response":[{"id":1,"email":"a@b.c"},{"id":2,"email":null}]"#),
            "{l}"
        );
        // Off: no response field at all.
        let off = Event {
            sql: Some("SELECT id, email FROM users"),
            ..base()
        };
        assert!(!line(&off).contains("response"));
    }

    #[test]
    fn payload_response_serializes_a_structured_value() {
        let response = Response::Payload(json!({"tables": [{"name": "users"}]}));
        let event = Event {
            command: "schema",
            table: Some("users"),
            response: Some(&response),
            ..base()
        };
        assert!(line(&event).contains(r#""response":{"tables":[{"name":"users"}]}"#));
    }

    /// W7: a trail that goes to /dev/null is worse than no trail — the query
    /// answers, the log stays empty, and nothing says so. Fail closed instead.
    #[cfg(unix)]
    #[test]
    fn a_sink_that_keeps_nothing_is_refused_rather_than_written_to() {
        let err = append(Path::new("/dev/null"), "line").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");

        // ...and the same through a symlink, which is how it would actually
        // arrive: an agent replacing the configured path.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        let err = append(&link, "line").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");

        // A symlink to a REAL file still works: the rule is about what the
        // path keeps, not about symlinks being suspicious.
        let real = dir.path().join("real.jsonl");
        let link2 = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&real, &link2).unwrap();
        append(&link2, "kept").unwrap();
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "kept\n");
    }

    #[test]
    fn append_creates_the_dir_and_file_0600_and_appends_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/audit.jsonl");
        append(&path, "line-one").unwrap();
        append(&path, "line-two").unwrap();
        let mut contents = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "line-one\nline-two\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "audit file must be owner-only");
        }
    }

    /// A sink that commits a PREFIX and then fails — models a full disk mid
    /// record. `truncate` mirrors `File::set_len`, so the rollback is exercised.
    struct FaultySink {
        buf: Vec<u8>,
        fail_after: usize,
    }

    impl Write for FaultySink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let room = self.fail_after.saturating_sub(self.buf.len());
            if room == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            let take = room.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            Ok(take)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LogSink for FaultySink {
        fn len(&self) -> std::io::Result<u64> {
            Ok(self.buf.len() as u64)
        }
        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            self.buf.truncate(len as usize);
            Ok(())
        }
    }

    #[test]
    fn a_partial_write_is_rolled_back_and_leaves_valid_jsonl() {
        // One good line already committed, then a write that fails partway.
        let good = b"{\"prev\":1}\n".to_vec();
        let original_len = good.len();
        let mut sink = FaultySink {
            buf: good,
            // Allow only 4 more bytes of the next (long) record before failing.
            fail_after: original_len + 4,
        };
        let err =
            write_flush(&mut sink, &format!(r#"{{"big":"{}"}}"#, "x".repeat(5000))).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        // The fragment is gone: the file is exactly the earlier valid content.
        assert_eq!(sink.buf, b"{\"prev\":1}\n");
        let text = String::from_utf8(sink.buf).unwrap();
        for line in text.lines() {
            serde_json::from_str::<Value>(line).expect("every line stays valid jsonl");
        }
    }

    /// CONCURRENCY proof: four threads each append 50 distinct 8 KiB lines
    /// (well past a 4 KiB single-write boundary) to the same file at once. With
    /// the advisory lock every line must land whole — no interleaving, no
    /// truncation — and all 200 must be present and valid.
    #[test]
    fn concurrent_large_appends_never_interleave() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let threads = 4;
        let per_thread = 50;
        let big = 8 * 1024;
        std::thread::scope(|scope| {
            for t in 0..threads {
                let path = &path;
                scope.spawn(move || {
                    for i in 0..per_thread {
                        // A valid JSON object whose payload is one long run of a
                        // per-thread character, so any interleave is detectable.
                        let filler: String =
                            std::iter::repeat_n(char::from(b'a' + t as u8), big).collect();
                        let record = format!(r#"{{"t":{t},"i":{i},"data":"{filler}"}}"#);
                        append(path, &record).unwrap();
                    }
                });
            }
        });
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), (threads * per_thread) as usize);
        for l in &lines {
            // Every line is intact, valid JSON, with the exact filler length.
            let v: Value =
                serde_json::from_str(l).unwrap_or_else(|_| panic!("garbled line: {l:.60}"));
            assert_eq!(v["data"].as_str().unwrap().len(), big);
        }
    }
}
