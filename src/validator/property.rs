//! Property-based test for the one guarantee layer 1 makes: **a statement that
//! contains a write node is never allowed**.
//!
//! The golden corpus (`tests/corpus/*.yaml`) pins hand-written cases, and it is
//! the specification — but a corpus cannot pin COMPOSITIONS. Every bypass found
//! so far has been a known write wrapped in enough read scaffolding that some
//! hook stopped looking (`ONLY (t)`, a parenthesised join, a write in a
//! set-operation arm). This generator builds that scaffolding to depth, on all
//! three dialects.
//!
//! **The flag is computed by CONSTRUCTION, never by parsing.** `Node::has_write`
//! reads the TREE the generator built, not the text it rendered: the generator
//! knows a write is in there because it is the one that put it there. Deriving
//! the flag from the rendered SQL would only prove that two parsers agree with
//! each other, which is the very thing under test.
//!
//! That makes ONE property of the generator load-bearing: a composition must not
//! silently neutralize the write node it wraps, or the invariant becomes a claim
//! about text that no longer contains a write. It can happen — `SELECT (BEGIN)`
//! is an honest read of a column named `begin`, because a bare keyword in an
//! expression position is an IDENTIFIER — so the leaves are split by POSITION
//! (see `STATEMENT_ONLY_WRITE_LEAVES`) and every wrapper is filed under the
//! position it actually offers its inner fragment.
//!
//! Only one direction is asserted. "write => refused" is the security
//! guarantee; "a clean read is allowed" is UX, and it does not survive random
//! composition (plenty of read shapes are honestly refused — an inner LIMIT in a
//! set operation, a dialect that will not parse the shape). What IS pinned, and
//! deterministically, is the narrow half of it the generator's own honesty
//! depends on: `the_read_leaves_are_really_reads` below.

use super::*;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use std::cell::{Cell, RefCell};

/// Fragments that contain NO write node, used as the read scaffolding's filler.
/// Two of them carry a `;` and a `DELETE` inside a string LITERAL: a validator
/// that split those into two statements — or a generator that scored them as
/// writes — would make the whole property lie, so
/// `the_read_leaves_are_really_reads` pins them.
const READ_LEAVES: &[&str] = &[
    "SELECT 1",
    "SELECT id FROM users WHERE name = 'a;b'",
    "SELECT 'DELETE FROM t; DROP TABLE x' AS s",
];

/// Write nodes that a QUERY position keeps as writes: DML, which every dialect
/// parses inside a CTE body or a derived table, so the case lands on the
/// recursive AST walk (WRITE_OPERATION) rather than on the parser's error path.
const WRITE_LEAVES: &[&str] = &[
    "DELETE FROM t",
    "INSERT INTO t (a) VALUES (1)",
    "UPDATE t SET a = 1",
    // The RETURNING spellings, which are the ones a derived table really
    // accepts (`SELECT * FROM (DELETE FROM t RETURNING *) d`).
    "INSERT INTO t (a) VALUES (1) RETURNING a",
    "UPDATE t SET a = 1 RETURNING a",
    "DELETE FROM t RETURNING *",
    "SELECT * INTO t2 FROM users",
];

/// Writes that only a STATEMENT position keeps — two different reasons, same
/// consequence, so one list:
///
/// - **DDL and MERGE**: no dialect parses them where a query belongs, so every
///   query-wrapped case was a PARSE_FAILED (measured: 0 of 10 reached
///   WRITE_OPERATION). Fail-closed, but it proved the parser rejects DDL rather
///   than that the walk refuses it. Under `EXPLAIN` and after a `;` they are
///   parsed, and then they are judged.
/// - **Session and transaction control**: in an expression position sqlparser
///   reads the bare keyword as an IDENTIFIER — `SELECT (BEGIN)` is a plain read
///   of a column called `begin`, and allowing it is correct (pinned in
///   tests/corpus/sqlite_allow.yaml) — so query-wrapping these would generate
///   cases whose "write" flag is simply false.
const STATEMENT_ONLY_WRITE_LEAVES: &[&str] = &[
    "DROP TABLE t",
    "CREATE TABLE t2 (id INT)",
    "ALTER TABLE t ADD COLUMN c INT",
    "TRUNCATE TABLE t",
    "CREATE INDEX i ON t (a)",
    "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1",
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT s",
    "SET search_path = public",
];

/// Calls on the engine's function denylist, wrapped in a SELECT so they compose
/// like every other leaf. Per dialect BY NECESSITY: `setval` mutates durably on
/// PostgreSQL and is an unknown name on SQLite, so scoring it as a write
/// everywhere would report a bypass that is not one. Names taken from the
/// denylists in `validator.rs`, one per family — including the prefix-matched
/// ones (`pg_read_file`, `dblink_exec`), which config cannot re-allow.
const SQLITE_DENIED_CALLS: &[&str] = &[
    "SELECT load_extension('/tmp/x.so')",
    "SELECT writefile('/tmp/x', 'd')",
    "SELECT readfile('/etc/passwd')",
    "SELECT edit('x')",
    "SELECT fts3_tokenizer('simple')",
];

const POSTGRES_DENIED_CALLS: &[&str] = &[
    "SELECT setval('s', 1)",
    "SELECT nextval('s')",
    "SELECT pg_logical_emit_message(false, 'a', 'b')",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT dblink_exec('c', 'q')",
    "SELECT pg_advisory_lock(1)",
    "SELECT query_to_xml('select 1', false, false, '')",
    "SELECT lo_export(1, '/tmp/x')",
];

const MYSQL_DENIED_CALLS: &[&str] = &[
    "SELECT sys_exec('x')",
    "SELECT load_file('/etc/passwd')",
    "SELECT get_lock('l', -1)",
    "SELECT sleep(1)",
    "SELECT benchmark(1000000, md5('x'))",
];

/// Read scaffolding that offers its inner fragment a QUERY position — a CTE
/// body, a derived table, a subquery, a set-operation arm, plain parentheses.
/// None of them puts the inner text inside a literal or a comment, which would
/// disarm the write and make the case vacuous.
const QUERY_WRAPPERS: &[(&str, &str)] = &[
    ("(", ")"),
    ("WITH w AS (", ") SELECT 1"),
    ("WITH w AS (", ") SELECT * FROM w"),
    ("SELECT * FROM (", ") AS d"),
    ("SELECT 1 WHERE EXISTS (", ")"),
    ("SELECT (", ")"),
    ("SELECT * FROM users WHERE id IN (", ")"),
    ("SELECT * FROM users u JOIN (", ") j ON j.id = u.id"),
    ("SELECT 1 UNION ", ""),
    ("", " UNION SELECT 1"),
];

/// Scaffolding that offers a STATEMENT position, so even a bare-keyword write
/// keeps its meaning inside it (`EXPLAIN BEGIN` really is a StartTransaction).
const STATEMENT_WRAPPERS: &[(&str, &str)] = &[("EXPLAIN ", "")];

const DIALECTS: &[&str] = &["sqlite", "postgres", "mysql"];

/// `pub(super)` here and on `Node`/`statement` below: the differential test
/// (`super::differential`) draws from this same generator, so the two tests
/// judge the SAME shapes — one against the invariant, one against a live
/// server. Sharing the generator is the point; duplicating it would let the
/// two drift.
pub(super) fn policy(dialect: &str) -> Policy {
    match dialect {
        "sqlite" => Policy::sqlite(&[], &[]),
        "postgres" => Policy::postgres(&[], &[]),
        "mysql" => Policy::mysql(&[], &[]),
        other => panic!("unknown dialect {other:?}"),
    }
}

fn denied_calls(dialect: &str) -> &'static [&'static str] {
    match dialect {
        "sqlite" => SQLITE_DENIED_CALLS,
        "postgres" => POSTGRES_DENIED_CALLS,
        "mysql" => MYSQL_DENIED_CALLS,
        other => panic!("unknown dialect {other:?}"),
    }
}

/// One generated statement, as a tree. Whether a case contains a write is a
/// property of THIS structure, decided when the tree is built — see the module
/// doc. The leaves carry their own text so a minimized counterexample prints as
/// readable SQL fragments rather than as indexes.
#[derive(Debug, Clone)]
pub(super) enum Node {
    Read(&'static str),
    Write(&'static str),
    /// A denied-function call, resolved against the dialect at render time.
    WriteCall(usize),
    Wrap((&'static str, &'static str), Box<Node>),
    /// Two statements separated by `;` — the classic piggyback. Combined with
    /// the read leaves that hold a `;` inside a literal, this is also where a
    /// naive statement splitter would miscount.
    Seq(Box<Node>, Box<Node>),
}

impl Node {
    fn has_write(&self) -> bool {
        match self {
            Node::Read(_) => false,
            Node::Write(_) | Node::WriteCall(_) => true,
            Node::Wrap(_, inner) => inner.has_write(),
            Node::Seq(left, right) => left.has_write() || right.has_write(),
        }
    }

    pub(super) fn render(&self, dialect: &str) -> String {
        match self {
            Node::Read(sql) | Node::Write(sql) => (*sql).to_string(),
            // Modulo rather than a per-dialect strategy: the three lists have
            // different lengths, and this keeps the whole generator
            // dialect-independent, so proptest shrinks the dialect and the tree
            // side by side.
            Node::WriteCall(i) => {
                let calls = denied_calls(dialect);
                calls[i % calls.len()].to_string()
            }
            Node::Wrap((prefix, suffix), inner) => {
                format!("{prefix}{}{suffix}", inner.render(dialect))
            }
            Node::Seq(left, right) => {
                format!("{}; {}", left.render(dialect), right.render(dialect))
            }
        }
    }
}

/// Fragments that make sense where a QUERY is expected — the recursive half.
fn query_fragment() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        select(READ_LEAVES).prop_map(Node::Read),
        select(WRITE_LEAVES).prop_map(Node::Write),
        // The longest denylist sample decides the range, so adding a call can
        // never leave it silently out of reach (`render` folds the index into
        // the shorter lists).
        (0usize..POSTGRES_DENIED_CALLS.len()).prop_map(Node::WriteCall),
    ];
    // Depth 4 / ~24 nodes: enough for "a write under four layers of read
    // scaffolding", short enough that a counterexample is still readable.
    leaf.prop_recursive(4, 24, 2, |inner| {
        (select(QUERY_WRAPPERS), inner).prop_map(|(w, node)| Node::Wrap(w, Box::new(node)))
    })
}

/// A whole statement: a query fragment, a statement-only write, or either of
/// those under scaffolding that takes a statement (EXPLAIN, `a; b`).
pub(super) fn statement() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        3 => query_fragment(),
        1 => select(STATEMENT_ONLY_WRITE_LEAVES).prop_map(Node::Write),
    ];
    leaf.prop_recursive(2, 8, 2, |inner| {
        prop_oneof![
            // `a; b` is weighted DOWN on purpose: a second statement is refused
            // by the statement COUNT before the tree is ever walked, so an
            // even split spends most of the budget re-proving MULTI_STATEMENT
            // instead of exercising the recursive walk this test is about.
            7 => (select(STATEMENT_WRAPPERS), inner.clone())
                .prop_map(|(w, node)| Node::Wrap(w, Box::new(node))),
            1 => (inner.clone(), inner).prop_map(|(l, r)| Node::Seq(Box::new(l), Box::new(r))),
        ]
    })
}

/// THE property: whatever read scaffolding a write node is buried under, on
/// whatever dialect, `validate` must refuse it. WHICH refusal it picks
/// (WRITE_OPERATION, MULTI_STATEMENT, TXN_CONTROL, DENIED_FUNCTION,
/// PARSE_FAILED, ...) is deliberately not asserted — fail-closed is a property
/// of the verdict, and pinning the reason here would turn every sqlparser
/// upgrade into a red test without protecting anything.
#[test]
fn a_generated_write_is_never_allowed() {
    // A panic inside validate() is already mapped to a refusal, so an
    // INTERNAL_ERROR is a PASS for this property: the write did not reach the
    // database. It is still a bug and a lead for the fuzzing that comes next,
    // so it is counted and reported (`cargo test -- --nocapture` to see it).
    let internal_errors = Cell::new(0usize);
    let first_internal = RefCell::new(String::new());
    // 1024 cases: ~0.2s, with every leaf and wrapper hit many times over
    // (3 dialects x ~27 leaf spellings x 11 wrappers, composed) and every case
    // carrying a write (see the filter below). Measured refusals over 5 runs,
    // so the shape of the coverage is on the record rather than assumed:
    // ~420 PARSE_FAILED (a write in a position that dialect will not parse —
    // fail-closed, and the largest class by construction), ~205
    // WRITE_OPERATION (the recursive AST walk itself), ~170 MULTI_STATEMENT,
    // ~155 DENIED_FUNCTION, ~74 TXN_CONTROL. A 60_000-case soak found nothing
    // the small budget does not reach, so tens of thousands per run would buy
    // repetition rather than coverage — and `just test-fast` is a seconds-long
    // recipe on purpose. Raise it here (not via PROPTEST_CASES, which this
    // explicit value overrides) to soak again.
    let mut runner = TestRunner::new(Config {
        cases: 1024,
        // Lets proptest persist a counterexample under proptest-regressions/ at
        // the crate root, where it becomes a permanent regression case.
        source_file: Some(file!()),
        ..Config::default()
    });
    // The filter is where "by construction" is enforced: a tree with no write
    // leaf is not a case of this property at all, so it is rejected instead of
    // spending a case on a vacuous pass — and a SHRINK that drops the last
    // write is rejected too, which keeps the minimized counterexample a write.
    let cases = (select(DIALECTS), statement())
        .prop_filter("must contain a write node", |(_, node)| node.has_write());
    let outcome = runner.run(&cases, |(dialect, node)| {
        let sql = node.render(dialect);
        match validate(&sql, &policy(dialect)) {
            Verdict::Deny { reason, .. } => {
                if reason == DenyReason::InternalError {
                    internal_errors.set(internal_errors.get() + 1);
                    let mut first = first_internal.borrow_mut();
                    if first.is_empty() {
                        *first = sql;
                    }
                }
                Ok(())
            }
            Verdict::Allow { .. } => Err(TestCaseError::fail(format!(
                "layer 1 ALLOWED a statement built around a write node \
                 (dialect {dialect}): {sql}"
            ))),
        }
    });
    if let Err(failure) = outcome {
        panic!("{failure}");
    }
    if internal_errors.get() > 0 {
        println!(
            "note: {} generated write(s) were refused as INTERNAL_ERROR (a caught panic \
             in the validator — still fail-closed, but a bug worth fuzzing); first one: {}",
            internal_errors.get(),
            first_internal.borrow(),
        );
    }
}

/// The generator's own honesty check: a leaf it scores as a READ must really be
/// one, on every dialect. The two literal-carrying leaves are the point — were
/// `SELECT 'DELETE FROM t; DROP TABLE x'` refused (as a write, or as two
/// statements), the `Seq(read, write)` cases above would be passing for the
/// wrong reason and the property would be measuring nothing.
#[test]
fn the_read_leaves_are_really_reads() {
    for dialect in DIALECTS {
        for sql in READ_LEAVES {
            assert!(
                matches!(validate(sql, &policy(dialect)), Verdict::Allow { .. }),
                "{dialect}: {sql} must be allowed — the generator counts it as a read"
            );
        }
    }
}
