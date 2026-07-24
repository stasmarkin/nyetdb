//! SQL validator, layer 1: pure classification of a query string into
//! Allow/Deny. Depends only on sqlparser (+std) — the golden corpus runs
//! without live databases (Д1/Д2). Fail closed: anything not understood
//! is denied.
//!
//! Step 2 scope: parse -> exactly one statement -> top-level allowlist.
//! Recursive AST walking, Unicode stripping and the function denylist
//! arrive in step 3.

use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

/// Closed list; the strings are part of the agent-facing contract
/// (`error.reason` under `error.code = "NYET"`). Append-only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    ParseFailed,
    MultiStatement,
    WriteOperation,
    TxnControl,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::ParseFailed => "PARSE_FAILED",
            DenyReason::MultiStatement => "MULTI_STATEMENT",
            DenyReason::WriteOperation => "WRITE_OPERATION",
            DenyReason::TxnControl => "TXN_CONTROL",
        }
    }
}

pub enum Verdict {
    Allow,
    Deny {
        reason: DenyReason,
        message: String,
        hint: String,
    },
}

/// Classify one query (SQLite dialect — the only engine in this step; the
/// dialect becomes a parameter when a second engine lands).
pub fn validate(sql: &str) -> Verdict {
    // Before parsing: sqlparser cannot parse several PRAGMA forms (the call
    // form `PRAGMA table_info(users)`, keyword values `PRAGMA journal_mode =
    // DELETE`), which would fall into a generic PARSE_FAILED whose "fix the
    // SQL syntax" hint is a dead end. Catch the keyword up front so every
    // PRAGMA gets the teaching refusal.
    let first_token_len = sql
        .trim_start()
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(sql.trim_start().len());
    if sql.trim_start()[..first_token_len].eq_ignore_ascii_case("pragma") {
        return pragma_deny();
    }
    let statements = match Parser::parse_sql(&SQLiteDialect {}, sql) {
        Ok(s) => s,
        // The parser error names the offending token — it comes from the
        // caller's own query, so echoing it back is safe and actionable.
        Err(e) => {
            return deny(
                DenyReason::ParseFailed,
                format!("cannot parse the query as SQL: {e}"),
                "nyet rejects anything it cannot parse (fail closed); fix the SQL syntax \
                 and retry",
            )
        }
    };
    if statements.len() > 1 {
        return deny(
            DenyReason::MultiStatement,
            format!(
                "the query contains {} statements; nyet runs exactly one statement per call",
                statements.len()
            ),
            "split the statements and run each one as a separate nyet query invocation",
        );
    }
    let Some(stmt) = statements.into_iter().next() else {
        return deny(
            DenyReason::ParseFailed,
            "the query contains no SQL statement".to_string(),
            "pass exactly one read statement, e.g. SELECT * FROM some_table LIMIT 10",
        );
    };
    classify(&stmt)
}

/// Top-level allowlist. Only Show* variants that SQLiteDialect can actually
/// produce are listed (checked empirically; ShowStatus/ShowVariables/
/// ShowObjects all parse into ShowVariable under this dialect).
fn classify(stmt: &Statement) -> Verdict {
    match stmt {
        // A Query statement can still carry a write in its body:
        // `WITH x AS (...) DELETE ...` or `SELECT ... INTO t`.
        Statement::Query(query) => query_body_verdict(&query.body),
        // EXPLAIN wraps an arbitrary statement; on some engines
        // (EXPLAIN ANALYZE, PostgreSQL) it *executes* it — the inner
        // statement must pass the same allowlist.
        Statement::Explain { statement, .. } => classify(statement),
        Statement::ExplainTable { .. }
        | Statement::ShowCatalogs { .. }
        | Statement::ShowCharset(_)
        | Statement::ShowCollation { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowProcessList { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowViews { .. } => Verdict::Allow,
        Statement::Set(_)
        | Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => deny(
            DenyReason::TxnControl,
            format!(
                "'{}' is transaction/session control, which nyet does not accept",
                head(stmt)
            ),
            "nyet manages its own read-only session; send the SELECT directly, without \
             BEGIN/COMMIT/SET",
        ),
        // Defense in depth: validate() already catches the leading keyword,
        // but PRAGMA can also reach here wrapped (e.g. EXPLAIN PRAGMA ...).
        Statement::Pragma { .. } => pragma_deny(),
        other => deny(
            DenyReason::WriteOperation,
            format!("'{}' is not a read operation", head(other)),
            "nyet is read-only; only SELECT, EXPLAIN, SHOW and DESCRIBE statements are \
             accepted — rewrite the task as a read query",
        ),
    }
}

/// The body tree of a top-level Query: only SELECT (without INTO), VALUES,
/// TABLE and set operations over those are reads; Insert/Update/Delete/Merge
/// bodies are writes in a Query costume. Unknown future variants fall to
/// deny (fail closed). CTE *contents* are step 3 (recursive walk).
fn query_body_verdict(body: &SetExpr) -> Verdict {
    let denied = match body {
        SetExpr::Select(select) => {
            if select.into.is_some() {
                Some("SELECT INTO")
            } else {
                None
            }
        }
        SetExpr::Values(_) | SetExpr::Table(_) => None,
        SetExpr::Query(inner) => return query_body_verdict(&inner.body),
        SetExpr::SetOperation { left, right, .. } => {
            if let v @ Verdict::Deny { .. } = query_body_verdict(left) {
                return v;
            }
            return query_body_verdict(right);
        }
        SetExpr::Insert(_) => Some("INSERT"),
        SetExpr::Update(_) => Some("UPDATE"),
        SetExpr::Delete(_) => Some("DELETE"),
        SetExpr::Merge(_) => Some("MERGE"),
    };
    match denied {
        None => Verdict::Allow,
        Some(what) => deny(
            DenyReason::WriteOperation,
            format!("the query body is a {what}, which is not a read operation"),
            "nyet is read-only; remove the data-modifying part and keep only the SELECT",
        ),
    }
}

/// First words of the statement's canonical form — names what was denied
/// without echoing the whole query back. Rendering stops after a small
/// budget so a multi-megabyte statement is never fully serialized.
fn head(stmt: &Statement) -> String {
    use std::fmt::Write;
    struct Head {
        buf: String,
        budget: usize,
    }
    impl Write for Head {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for c in s.chars() {
                if self.budget == 0 {
                    // Err aborts the Display machinery early; the buffer
                    // already holds everything we need.
                    return Err(std::fmt::Error);
                }
                self.buf.push(c);
                self.budget -= 1;
            }
            Ok(())
        }
    }
    let mut head = Head {
        buf: String::new(),
        budget: 48,
    };
    let _ = write!(head, "{stmt}");
    head.buf
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// One refusal for every PRAGMA form: "rewrite as a read" would be a dead
/// end — the schema questions PRAGMA answers have a SELECT equivalent.
fn pragma_deny() -> Verdict {
    deny(
        DenyReason::WriteOperation,
        "PRAGMA statements are blocked (fail closed): they can read and change \
         database/session state"
            .to_string(),
        "for schema info query sqlite_master instead, e.g. \
         SELECT name, sql FROM sqlite_master WHERE type = 'table'",
    )
}

fn deny(reason: DenyReason, message: String, hint: &str) -> Verdict {
    Verdict::Deny {
        reason,
        message: format!("nyet: {message}"),
        hint: hint.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Golden corpus (Д6): every yaml file in tests/corpus is the public
    /// security specification. Format — see docs/DEV.md; parsed here by a
    /// deliberately tiny line-based reader instead of a yaml dependency (Д8).
    #[derive(Debug)]
    struct Case {
        file: String,
        line: usize,
        query: String,
        dialect: String,
        verdict: String,
        reason: Option<String>,
    }

    fn parse_corpus(file: &Path) -> Vec<Case> {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(file).unwrap();
        let mut cases: Vec<Case> = Vec::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(q) = line.strip_prefix("- query: ") {
                cases.push(Case {
                    file: name.clone(),
                    line: idx + 1,
                    query: q.to_string(),
                    dialect: "sqlite".to_string(),
                    verdict: String::new(),
                    reason: None,
                });
                continue;
            }
            let case = cases
                .last_mut()
                .unwrap_or_else(|| panic!("{name}:{}: key before first '- query:'", idx + 1));
            if let Some(v) = line.strip_prefix("verdict: ") {
                case.verdict = v.to_string();
            } else if let Some(r) = line.strip_prefix("reason: ") {
                case.reason = Some(r.to_string());
            } else if let Some(d) = line.strip_prefix("dialect: ") {
                case.dialect = d.to_string();
            } else {
                panic!("{name}:{}: unrecognized corpus line: {raw}", idx + 1);
            }
        }
        cases
    }

    #[test]
    fn golden_corpus() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no corpus files in {}", dir.display());
        let mut total = 0;
        for file in files {
            for case in parse_corpus(&file) {
                total += 1;
                let at = format!("{}:{} {:?}", case.file, case.line, case.query);
                assert_eq!(case.dialect, "sqlite", "{at}: only sqlite in this step");
                match validate(&case.query) {
                    Verdict::Allow => {
                        assert_eq!(case.verdict, "allow", "{at}: got allow");
                        assert!(case.reason.is_none(), "{at}: reason on an allow case");
                    }
                    Verdict::Deny {
                        reason,
                        message,
                        hint,
                    } => {
                        assert_eq!(case.verdict, "deny", "{at}: got deny ({message})");
                        assert_eq!(
                            case.reason.as_deref(),
                            Some(reason.as_str()),
                            "{at}: wrong reason"
                        );
                        // Д10: a refusal without an actionable hint does not ship.
                        assert!(!hint.is_empty(), "{at}: empty hint");
                        assert!(!message.is_empty(), "{at}: empty message");
                    }
                }
            }
        }
        // Tripwire against accidental corpus loss (a whole file or a large
        // chunk vanishing must fail loudly). Raise as the corpus grows.
        assert!(total >= 55, "corpus suspiciously small: {total} cases");
    }

    #[test]
    fn empty_query_is_parse_failed() {
        for sql in ["", "   ", ";"] {
            match validate(sql) {
                Verdict::Deny { reason, .. } => {
                    assert_eq!(reason, DenyReason::ParseFailed, "{sql:?}")
                }
                Verdict::Allow => panic!("{sql:?} must not be allowed"),
            }
        }
    }

    #[test]
    fn every_pragma_form_gets_the_teaching_hint() {
        // The corpus runner only checks verdict/reason; the dedicated hint
        // (pointing at sqlite_master, not "fix your syntax") is pinned here,
        // including the forms sqlparser itself cannot parse.
        for sql in [
            "PRAGMA user_version",
            "PRAGMA table_info(users)",
            "PRAGMA journal_mode = DELETE",
            "  pragma busy_timeout = 1000",
        ] {
            let Verdict::Deny {
                reason,
                message,
                hint,
            } = validate(sql)
            else {
                panic!("{sql:?} must be denied")
            };
            assert_eq!(reason, DenyReason::WriteOperation, "{sql}");
            assert!(message.contains("PRAGMA"), "{sql}: {message}");
            assert!(hint.contains("sqlite_master"), "{sql}: {hint}");
        }
        // Word boundary: an identifier that merely starts with "pragma"
        // is not a PRAGMA statement.
        assert!(matches!(
            validate("SELECT pragmatic FROM words"),
            Verdict::Allow
        ));
    }

    #[test]
    fn deny_messages_name_the_offender() {
        let Verdict::Deny {
            reason, message, ..
        } = validate("DROP TABLE users")
        else {
            panic!("DROP must be denied")
        };
        assert_eq!(reason, DenyReason::WriteOperation);
        assert!(message.contains("DROP"), "{message}");
    }
}
