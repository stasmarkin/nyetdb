//! Differential test: what layer 1 ALLOWS, judged by the SERVER itself.
//!
//! Layer 1 classifies with sqlparser; the database parses with its own grammar.
//! Where the two disagree, a text nyet believes is a read can be a WRITE to the
//! server (or a second statement smuggled into the first) — the root class of
//! holes a corpus cannot close, because it can only pin the shapes someone
//! already thought of.
//!
//! Only inputs `validate()` ALLOWED are executed, and only against a session
//! the SERVER holds read-only:
//!
//! * **Oracle A — write**: the server refuses the text AS A WRITE. Nothing else
//!   it may say counts. This catches only STATEMENT-level writes — a read whose
//!   FUNCTION has a side effect (`COPY ... TO PROGRAM`, which runs even under a
//!   read-only transaction; `pg_logical_emit_message`; `lo_export`;
//!   `pg_advisory_lock`) is a write the server runs happily. That half is held
//!   from the other side by the denylist + `property.rs`; the split is
//!   deliberate, and this oracle is not the guard for it.
//! * **Oracle B — one statement (Postgres only)**: layer 1 accepted the text as
//!   exactly one statement, so the prepared protocol (which takes exactly one)
//!   must agree. Only `pg_verdict` distinguishes it — MySQL reports a second
//!   command as a plain syntax error and SQLite silently executes the tail, so
//!   there the multi-statement input lands in the report, not in a finding.
//!
//! The read-only guard is not trusted to hold for free: the write canary is
//! fired BOTH before and after the input loop, so a validator regression that
//! let one input disarm read-only mid-run (`SET ... read_only = off`) fails the
//! test instead of turning every later input into a silent real write.
//!
//! Every other server error — no such table/column/function, a syntax that
//! dialect does not have — is NOT a finding: it is counted and printed, so a
//! run that degenerated into "relation does not exist" is visible instead of
//! passing quietly. `SCHEMA_TABLES`/`cols()` exist for the same reason: the
//! tables the corpus and the generator name are created BEFORE the session goes
//! read-only, so a statement reaches the write check instead of dying earlier —
//! and `assert_covered` fails the run if too few inputs reach execution at all,
//! so schema drift cannot collapse the test into a green pass over nothing.
//!
//! Measured on the first full run (no divergence found, which is the result
//! this file exists to keep true): postgres 460 allowed inputs of which 335
//! reached execution, mysql 369/306, sqlite 399/290 — ~0.5s of round trips per
//! dialect, ~7s wall with both containers, and +0.4s on `cargo test --lib`,
//! where they overlap the container tests already there.
//!
//! Not run by `just test-fast` (see the justfile): two of the three need a
//! container, and all three are one experiment.

use super::property::{policy, statement, Node};
use super::{validate, Verdict};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use sqlx::{ConnectOptions, Connection, Executor};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Fire the write canary and assert the server STILL refuses it as a write.
/// Run before the input loop (the guard is armed) and after it (the guard was
/// not disarmed by any input). A macro, not an async fn, so it borrows `conn`
/// inline without the lifetime gymnastics a `&mut conn` helper would need.
macro_rules! assert_readonly_holds {
    ($conn:expr, $verdict:expr, $label:literal, $when:literal) => {{
        let err = sqlx::query(WRITE_CANARY)
            .execute(&mut $conn)
            .await
            .expect_err(concat!($label, ": write canary was accepted ", $when));
        let got = $verdict(&err);
        assert!(
            matches!(got, ServerVerdict::Write(_)),
            "{}: read-only does not hold {} — write canary judged {:?}",
            $label,
            $when,
            got,
        );
    }};
}

/// Generated statements per dialect. Each one is a network round trip, so this
/// is hundreds, not thousands — the corpus carries the hand-written breadth and
/// the generator adds composition on top.
const GENERATED_PER_DIALECT: usize = 250;

/// Tables the corpus and the generator name. Created empty (the oracle judges
/// the STATEMENT, not rows) with the union of every column any of those reads
/// projects — see `cols`.
const SCHEMA_TABLES: &[&str] = &[
    "users",
    "orders",
    "dict",
    "events",
    "posts",
    "payments",
    "signups",
    "settings",
    "customers",
    "newsletter_signups",
    "t",
    "a",
    "b",
    "dblink",
    "column_statistics",
];

/// The union of the column names those reads project, typed per dialect where
/// the type is load-bearing (`tags[1]`, `data->>'k'`, `created_at DESC`). One
/// wide table shape for every name: a differential oracle only needs the
/// statement to survive planning.
fn cols(dialect: &str) -> String {
    let (json, ts, array) = match dialect {
        "postgres" => ("jsonb", "timestamptz", "text[]"),
        "mysql" => ("json", "timestamp NULL", "text"),
        _ => ("text", "text", "text"),
    };
    format!(
        "id int, user_id int, uid int, order_id int, x int, n int, \
         a int, b int, c int, s text, col text, k text, \
         email text, phone text, ssn text, name text, contact text, note text, \
         dept text, first_tag text, emails text, \
         created_at {ts}, amount decimal(10,2), total decimal(10,2), price decimal(10,2), \
         tags {array}, data {json}, doc {json}, \
         sleep int, benchmark int, get_lock int, release_lock int, load_file text, \
         master_pos_wait int, master_gtid_wait int, pg_sleep int, pg_advisory_lock int, \
         histogram text, min_value text, max_value text, most_common_vals text"
    )
}

/// `CREATE TABLE`s to run BEFORE the session goes read-only.
fn schema(dialect: &str) -> Vec<String> {
    let cols = cols(dialect);
    let mut ddl: Vec<String> = SCHEMA_TABLES
        .iter()
        .map(|t| format!("CREATE TABLE {t} ({cols})"))
        .collect();
    if dialect == "postgres" {
        // `SELECT ssn FROM app.customers` (corpus) and `currval('users_id_seq')`.
        ddl.insert(0, "CREATE SCHEMA app".to_string());
        ddl.push(format!("CREATE TABLE app.customers ({cols})"));
        ddl.push("CREATE SEQUENCE users_id_seq".to_string());
    }
    ddl
}

/// What the server thought of a text layer 1 had ALLOWED.
#[derive(Debug)]
enum ServerVerdict {
    /// The server executed it (or failed for a reason that is not ours).
    Ran,
    /// FINDING: refused as an attempt to write.
    Write(String),
    /// FINDING: the server counted more statements than layer 1 did.
    MultiStatement(String),
    /// Not a finding — bucketed by server error code for the report.
    Other(String),
}

#[derive(Default)]
struct Tally {
    ran: usize,
    /// `(input, what the server said)` — non-empty means the test fails.
    findings: Vec<(String, String)>,
    classes: BTreeMap<String, usize>,
    /// First message seen per class, so the printed report is readable.
    samples: BTreeMap<String, String>,
}

impl Tally {
    fn record(&mut self, sql: &str, verdict: ServerVerdict) {
        match verdict {
            ServerVerdict::Ran => self.ran += 1,
            ServerVerdict::Write(msg) => self.findings.push((
                sql.to_string(),
                format!("server refused it as a WRITE: {msg}"),
            )),
            ServerVerdict::MultiStatement(msg) => self.findings.push((
                sql.to_string(),
                format!("server saw MORE THAN ONE statement: {msg}"),
            )),
            ServerVerdict::Other(class) => {
                *self.classes.entry(class.clone()).or_default() += 1;
                self.samples.entry(class).or_insert_with(|| sql.to_string());
            }
        }
    }

    /// Always printed (`cargo test -- --nocapture`): a green run whose inputs
    /// all died on "no such table" proves nothing, and the distribution is the
    /// only place that shows.
    fn report(&self, label: &str, total: usize, elapsed: Duration) {
        println!(
            "\n{label}: {total} allowed inputs in {:.1}s — {} executed, {} refused for \
             other reasons:",
            elapsed.as_secs_f64(),
            self.ran,
            total - self.ran - self.findings.len(),
        );
        let mut by_count: Vec<_> = self.classes.iter().collect();
        by_count.sort_by_key(|(class, n)| (std::cmp::Reverse(**n), (*class).clone()));
        for (class, n) in by_count {
            println!("  {n:5} {class}  e.g. {}", self.samples[class]);
        }
        for (sql, what) in &self.findings {
            println!("  FINDING: {what}\n           input: {sql}");
        }
    }

    fn assert_clean(&self, label: &str) {
        assert!(
            self.findings.is_empty(),
            "{label}: layer 1 allowed {} statement(s) the server judges differently \
             (a validator bypass — see the FINDING lines above): {:?}",
            self.findings.len(),
            self.findings,
        );
    }

    /// The whole test is vacuous if the inputs never reach the write check. If
    /// schema or server drift pushes most of them into the `Other` bucket
    /// (`relation does not exist`, a syntax the dialect lost), `assert_clean`
    /// still passes green over nothing — so demand a floor of inputs that
    /// actually EXECUTED. Half: the lowest measured share is 0.73 (PG 335/460,
    /// sqlite 290/399; mysql 0.83), and 0.5 leaves comfortable headroom for
    /// honest drift (a sqlparser upgrade parsing shapes the empty schema
    /// rejects) while still failing hard the moment coverage roughly halves.
    fn assert_covered(&self, label: &str, total: usize) {
        let floor = total / 2;
        assert!(
            self.ran >= floor,
            "{label}: only {} of {total} allowed inputs executed (need >= {floor}); \
             schema/server drift collapsed coverage — the oracle is testing almost \
             nothing. See the class distribution (`cargo test -- --nocapture`).",
            self.ran,
        );
    }
}

/// Every corpus query of this dialect plus `GENERATED_PER_DIALECT` statements
/// from the property generator, reduced to what `validate` ALLOWS — and to the
/// NORMALIZED text it allowed, which is what the engine would really execute.
///
/// Corpus deny cases are fed in as well and simply filter themselves out: what
/// matters is the allow verdict, not which file the line came from.
fn allowed_inputs(dialect: &str) -> Vec<String> {
    let policy = policy(dialect);
    let mut out = Vec::new();
    let keep = |sql: &str, out: &mut Vec<String>| {
        if let Verdict::Allow { sql, .. } = validate(sql, &policy) {
            out.push(sql);
        }
    };

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "yaml")
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(dialect))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no {dialect} corpus files in {dir:?}");
    for file in files {
        for line in std::fs::read_to_string(&file).unwrap().lines() {
            if let Some(q) = line.trim().strip_prefix("- query: ") {
                keep(q, &mut out);
            }
        }
    }
    let from_corpus = out.len();

    // Deterministic RNG: a differential test that fails on one CI run and
    // passes on the next teaches nobody anything. To soak new shapes when
    // hunting, swap this for `TestRunner::new(Config::default())`, which seeds
    // from entropy and so draws a fresh set each run.
    let mut runner = TestRunner::deterministic();
    let strategy = statement();
    let mut drawn = 0;
    while out.len() - from_corpus < GENERATED_PER_DIALECT && drawn < GENERATED_PER_DIALECT * 20 {
        drawn += 1;
        let node: Node = strategy.new_tree(&mut runner).unwrap().current();
        keep(&node.render(dialect), &mut out);
    }
    assert!(
        out.len() - from_corpus >= GENERATED_PER_DIALECT,
        "{dialect}: generator produced only {} allowed statements in {drawn} draws",
        out.len() - from_corpus
    );
    out
}

fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

/// Canaries: the two inputs whose classification the whole test rests on. If a
/// dialect ever stops reporting these, every "no finding" above it is vacuous.
const WRITE_CANARY: &str = "INSERT INTO t (id) VALUES (1)";
const MULTI_CANARY: &str = "SELECT 1; SELECT 2";

// --- PostgreSQL ---------------------------------------------------------

fn pg_verdict(err: &sqlx::Error) -> ServerVerdict {
    let Some(db) = err.as_database_error() else {
        return ServerVerdict::Other(format!("driver: {err}"));
    };
    let code = db.code().unwrap_or_default().into_owned();
    let msg = db.message().to_string();
    match code.as_str() {
        // read_only_sql_transaction — the ONLY code that means "this is a write".
        "25006" => ServerVerdict::Write(msg),
        // syntax_error; the multi-command refusal is a specific message under it
        // (extended protocol takes exactly one statement per Parse).
        "42601" if msg.contains("multiple commands") => ServerVerdict::MultiStatement(msg),
        _ => ServerVerdict::Other(format!("{code} {}", first_words(&msg))),
    }
}

#[test]
fn differential_postgres_readonly_oracle() {
    use testcontainers_modules::postgres::Postgres as PgImage;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::testcontainers::ImageExt;

    block_on(async {
        let container = PgImage::default()
            .with_tag("16-alpine")
            .start()
            .await
            .expect("start postgres:16-alpine (is docker/colima running?)");
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres@127.0.0.1:{port}/postgres");
        let opts: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        let opts = opts.password("postgres");

        let mut w = opts.clone().connect().await.unwrap();
        for ddl in schema("postgres") {
            w.execute(sqlx::AssertSqlSafe(ddl)).await.unwrap();
        }
        w.close().await.unwrap();

        // Read-only from CONNECT time via the server's `-c` startup options.
        // A runtime `SET default_transaction_read_only = off` can still override
        // that default, so the guard is not trusted to hold — the write canary
        // below fires after the loop as well. statement_timeout keeps one
        // pathological read from hanging the suite.
        let mut conn = opts
            .options([
                ("default_transaction_read_only", "on"),
                ("statement_timeout", "5000"),
            ])
            .connect()
            .await
            .unwrap();

        assert_readonly_holds!(conn, pg_verdict, "postgres", "before the loop");
        // Oracle B canary: the extended protocol must reject a second command.
        let err = sqlx::query(MULTI_CANARY)
            .execute(&mut conn)
            .await
            .expect_err("multi-statement canary must be refused");
        assert!(
            matches!(pg_verdict(&err), ServerVerdict::MultiStatement(_)),
            "postgres oracle B is blind to {MULTI_CANARY:?}: {:?}",
            pg_verdict(&err),
        );

        let inputs = allowed_inputs("postgres");
        let started = Instant::now();
        let mut tally = Tally::default();
        for sql in &inputs {
            match sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .execute(&mut conn)
                .await
            {
                Ok(_) => tally.record(sql, ServerVerdict::Ran),
                Err(e) => tally.record(sql, pg_verdict(&e)),
            }
        }
        tally.report("postgres", inputs.len(), started.elapsed());
        // Re-arm AFTER the loop: if any input disarmed read-only, every "Ran"
        // above was a real write and the whole run is worthless — fail here
        // rather than pass green.
        assert_readonly_holds!(conn, pg_verdict, "postgres", "after the loop");
        tally.assert_covered("postgres", inputs.len());
        tally.assert_clean("postgres");
    });
}

// --- MySQL --------------------------------------------------------------

fn mysql_verdict(err: &sqlx::Error) -> ServerVerdict {
    let Some(db) = err.as_database_error() else {
        return ServerVerdict::Other(format!("driver: {err}"));
    };
    let msg = db.message().to_string();
    let Some(mysql) = db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>() else {
        return ServerVerdict::Other(format!("non-mysql error: {msg}"));
    };
    match mysql.number() {
        // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION — what `SET SESSION
        // transaction_read_only = 1` raises for a write (measured, not assumed).
        // NOT 1290 (ER_OPTION_PREVENTS_STATEMENT): that code is overloaded
        // (secure_file_priv, --read-only server, ...) and this session never
        // produces it, so matching it would only add a dead, imprecise branch.
        1792 => ServerVerdict::Write(msg),
        n => ServerVerdict::Other(format!("{n} {}", first_words(&msg))),
    }
}

#[test]
fn differential_mysql_readonly_oracle() {
    use testcontainers_modules::mysql::Mysql as MysqlImage;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::testcontainers::ImageExt;

    block_on(async {
        let container = MysqlImage::default()
            .with_tag("8.4")
            .start()
            .await
            .expect("start mysql:8.4 (is docker/colima running?)");
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        // Root, empty password, database `test` (the image's defaults).
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();

        let mut w = opts.clone().connect().await.unwrap();
        for ddl in schema("mysql") {
            w.execute(sqlx::AssertSqlSafe(ddl)).await.unwrap();
        }
        w.close().await.unwrap();

        let mut conn = opts.connect().await.unwrap();
        // No connect-time equivalent of Postgres' -c options; the session var is
        // the documented way. It CAN be turned back off (`SET SESSION
        // transaction_read_only = 0`), so the guard is re-armed after the loop.
        conn.execute("SET SESSION transaction_read_only = 1")
            .await
            .unwrap();
        conn.execute("SET SESSION max_execution_time = 5000")
            .await
            .unwrap();

        assert_readonly_holds!(conn, mysql_verdict, "mysql", "before the loop");
        // Oracle B on MySQL is weaker than on Postgres BY THE PROTOCOL: a second
        // command in a COM_STMT_PREPARE comes back as a plain parse error, with
        // nothing to tell it from a genuine syntax error. So the canary pins only
        // that the server refuses it, and multi-statement inputs land in the
        // syntax bucket of the report rather than in a finding.
        let multi = sqlx::query(MULTI_CANARY).execute(&mut conn).await;
        assert!(
            multi.is_err(),
            "mysql executed {MULTI_CANARY:?} — the prepared protocol was expected to \
             refuse a second command"
        );

        let inputs = allowed_inputs("mysql");
        let started = Instant::now();
        let mut tally = Tally::default();
        for sql in &inputs {
            match sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .execute(&mut conn)
                .await
            {
                Ok(_) => tally.record(sql, ServerVerdict::Ran),
                Err(e) => tally.record(sql, mysql_verdict(&e)),
            }
        }
        tally.report("mysql", inputs.len(), started.elapsed());
        assert_readonly_holds!(conn, mysql_verdict, "mysql", "after the loop");
        tally.assert_covered("mysql", inputs.len());
        tally.assert_clean("mysql");
    });
}

// --- SQLite (in process, no container) ----------------------------------

fn sqlite_verdict(err: &sqlx::Error) -> ServerVerdict {
    let Some(db) = err.as_database_error() else {
        return ServerVerdict::Other(format!("driver: {err}"));
    };
    let msg = db.message().to_string();
    // SQLITE_READONLY (8) is what `PRAGMA query_only` raises; the message is
    // pinned by the canary, so a code-only match cannot silently widen.
    if msg.contains("readonly database") {
        return ServerVerdict::Write(msg);
    }
    ServerVerdict::Other(format!(
        "{} {}",
        db.code().unwrap_or_default(),
        first_words(&msg)
    ))
}

#[test]
fn differential_sqlite_readonly_oracle() {
    use std::str::FromStr;

    block_on(async {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
        let mut conn = opts.connect().await.unwrap();
        for ddl in schema("sqlite") {
            conn.execute(sqlx::AssertSqlSafe(ddl)).await.unwrap();
        }
        conn.execute("PRAGMA query_only = 1").await.unwrap();

        assert_readonly_holds!(conn, sqlite_verdict, "sqlite", "before the loop");
        // Oracle B does not exist here: sqlite3_prepare consumes one statement
        // and the driver walks on to execute the tail, so a piggybacked write is
        // never a parse error — `query_only` is the only thing that catches it.
        // Pinned, not just asserted in prose: the tail INSERT must be a Write.
        let err = sqlx::query(sqlx::AssertSqlSafe(
            "SELECT 1; INSERT INTO t (id) VALUES (1)".to_string(),
        ))
        .execute(&mut conn)
        .await
        .expect_err("query_only must catch the piggybacked write");
        assert!(
            matches!(sqlite_verdict(&err), ServerVerdict::Write(_)),
            "sqlite: a piggybacked write was not caught as a write: {:?}",
            sqlite_verdict(&err),
        );

        let inputs = allowed_inputs("sqlite");
        let started = Instant::now();
        let mut tally = Tally::default();
        for sql in &inputs {
            match sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .execute(&mut conn)
                .await
            {
                Ok(_) => tally.record(sql, ServerVerdict::Ran),
                Err(e) => tally.record(sql, sqlite_verdict(&e)),
            }
        }
        tally.report("sqlite", inputs.len(), started.elapsed());
        assert_readonly_holds!(conn, sqlite_verdict, "sqlite", "after the loop");
        tally.assert_covered("sqlite", inputs.len());
        tally.assert_clean("sqlite");
    });
}

/// A server message's first few words — enough to tell error classes apart in
/// the report without one bucket per table name.
fn first_words(msg: &str) -> String {
    msg.split_whitespace().take(4).collect::<Vec<_>>().join(" ")
}
