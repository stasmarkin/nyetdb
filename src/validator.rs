//! SQL validator, layer 1: pure classification of a query string into
//! Allow/Deny. Depends only on sqlparser + unicode-properties (+std) — the
//! golden corpus runs without live databases (Д1/Д2). Fail closed: anything
//! not understood is denied.
//!
//! Pipeline (DESIGN §3): Unicode normalization -> parse -> exactly one
//! statement -> recursive AST walk (top-level allowlist, nested writes,
//! locking clauses, function denylist).

use sqlparser::ast::{Expr, ObjectName, Query, Select, Statement, TableFactor, Visit, Visitor};
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::ops::ControlFlow;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

/// Closed list; the strings are part of the agent-facing contract
/// (`error.reason` under `error.code = "NYET"`). Append-only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    ParseFailed,
    MultiStatement,
    WriteOperation,
    TxnControl,
    LockingClause,
    DeniedFunction,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::ParseFailed => "PARSE_FAILED",
            DenyReason::MultiStatement => "MULTI_STATEMENT",
            DenyReason::WriteOperation => "WRITE_OPERATION",
            DenyReason::TxnControl => "TXN_CONTROL",
            DenyReason::LockingClause => "LOCKING_CLAUSE",
            DenyReason::DeniedFunction => "DENIED_FUNCTION",
        }
    }
}

/// Validator-produced warning; the cli maps it into the envelope's
/// `warnings` array (`code` is part of the closed warning-code contract).
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

pub enum Verdict {
    /// `sql` is the normalized text that MUST be executed instead of the
    /// original: the validator classified this exact string, and running
    /// anything else would reopen the gap normalization closes.
    Allow { sql: String, warnings: Vec<Warning> },
    Deny {
        reason: DenyReason,
        message: String,
        hint: String,
    },
}

/// The SQL dialect to parse and classify with (per engine). Held inside the
/// Policy so dialect and function policy can never drift apart — one source of
/// truth per engine.
#[derive(Clone, Copy)]
enum Dialect {
    Sqlite,
    Postgres,
}

/// Per-engine validation policy: the SQL dialect plus the function denylist
/// (built-in list merged with the per-connection config
/// `validator.allow_functions` / `deny_functions`).
pub struct Policy {
    dialect: Dialect,
    /// Lowercased effective denylist (matching is case-insensitive).
    denied_functions: BTreeSet<String>,
    /// Built-in, non-config-tunable name prefixes that are denied wholesale
    /// (e.g. the `dblink*` and `pg_read_*` families, DESIGN §3 п.7) — fail
    /// closed on functions we did not enumerate by exact name.
    denied_prefixes: &'static [&'static str],
}

/// Built-in SQLite denylist (rationale in docs/DEV.md). All defense in
/// depth: nyet's own bundled SQLite ships without extension loading, but
/// the validator is engine-independent and must hold on any SQLite build.
const SQLITE_DENIED_FUNCTIONS: &[&str] = &[
    "load_extension", // loads an arbitrary shared library into the process
    "fts3_tokenizer", // two-arg form historically allowed pointer injection
    "readfile",       // sqlite3 CLI/ext function: reads any file into a blob
    "writefile",      // sqlite3 CLI/ext function: writes any file on disk
    "edit",           // sqlite3 CLI function: spawns an editor process
];

/// Built-in PostgreSQL denylist (DESIGN §3 п.7; rationale in docs/DEV.md):
/// functions that act OUTSIDE the read-only transaction — layer 2 does not
/// stop them, so the validator is the only guard. Exact names here; the
/// file-read and dblink families are prefix-matched (see below).
const POSTGRES_DENIED_FUNCTIONS: &[&str] = &[
    "pg_terminate_backend", // kills another backend
    "pg_cancel_backend",    // cancels another backend's query
    "pg_reload_conf",       // reloads server configuration
    "pg_promote",           // promotes a standby (cluster-level)
    // pg_sleep family: silent DoS (ties up a pooled connection). Enumerated,
    // not prefixed, so `validator.allow_functions = ["pg_sleep"]` (DESIGN's
    // documented escape hatch) still works — prefixes are not config-tunable.
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_stat_file", // stats an arbitrary server file (not a pg_ls_/pg_read_ name)
    // nextval/setval are EXCLUDED from SET TRANSACTION READ ONLY by Postgres:
    // a durable sequence mutation through a read-only tool. (currval/lastval
    // are pure reads and stay allowed.)
    "nextval",
    "setval",
    // non-transactional WAL message: survives ROLLBACK, so it mutates durably
    // through a read-only transaction (same class as nextval/setval).
    "pg_logical_emit_message",
    "lo_import", // reads a server file into a large object
    "lo_export", // writes a large object to a server file
];

/// Prefix-matched denied families — fail closed on members we did not
/// enumerate (every current and future member is dangerous, none is a
/// legitimate agent read, so making them non-config-tunable is deliberate):
/// - `dblink*` — outbound connections / remote SQL (extension).
/// - `pg_read_*` — pg_read_file, pg_read_binary_file: arbitrary server-file read.
/// - `pg_ls_*` — pg_ls_dir, pg_ls_logdir, pg_ls_waldir, ...: server-dir listing.
const POSTGRES_DENIED_PREFIXES: &[&str] = &["dblink", "pg_read_", "pg_ls_"];

impl Policy {
    /// Effective SQLite policy: built-in list minus `allow_functions` plus
    /// `deny_functions`. Deny wins when a name appears in both (fail closed).
    pub fn sqlite(allow_functions: &[String], deny_functions: &[String]) -> Policy {
        Policy {
            dialect: Dialect::Sqlite,
            denied_functions: merge_denylist(
                SQLITE_DENIED_FUNCTIONS,
                allow_functions,
                deny_functions,
            ),
            denied_prefixes: &[],
        }
    }

    /// Effective PostgreSQL policy: built-in list (plus the denied prefixes)
    /// tuned by config the same way as sqlite(). Prefixes are built-in only.
    pub fn postgres(allow_functions: &[String], deny_functions: &[String]) -> Policy {
        Policy {
            dialect: Dialect::Postgres,
            denied_functions: merge_denylist(
                POSTGRES_DENIED_FUNCTIONS,
                allow_functions,
                deny_functions,
            ),
            denied_prefixes: POSTGRES_DENIED_PREFIXES,
        }
    }
}

/// Pure merge: (built-in, config) -> effective set, all lowercased.
fn merge_denylist(
    builtin: &[&str],
    allow_functions: &[String],
    deny_functions: &[String],
) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = builtin.iter().map(|f| f.to_lowercase()).collect();
    for f in allow_functions {
        set.remove(&f.to_lowercase());
    }
    for f in deny_functions {
        set.insert(f.to_lowercase());
    }
    set
}

/// Remove Unicode Cf (format: zero-width joiners, direction overrides, BOM)
/// and Cc (control) characters, keeping \t \n \r. These are invisible in
/// most renderings and can smuggle keywords past a human or an LLM reviewer
/// (`SEL<ZWJ>ECT`). Returns the (borrowed when nothing was stripped) cleaned
/// text and how many characters were removed.
pub fn strip_control(sql: &str) -> (Cow<'_, str>, usize) {
    fn strip(c: char) -> bool {
        !matches!(c, '\t' | '\n' | '\r')
            && matches!(
                c.general_category(),
                GeneralCategory::Control | GeneralCategory::Format
            )
    }
    let removed = sql.chars().filter(|&c| strip(c)).count();
    if removed == 0 {
        // Hot path: the common query has nothing to strip — borrow, no alloc.
        (Cow::Borrowed(sql), 0)
    } else {
        (
            Cow::Owned(sql.chars().filter(|&c| !strip(c)).collect()),
            removed,
        )
    }
}

/// Classify one query under the engine's policy (which carries the dialect).
pub fn validate(sql: &str, policy: &Policy) -> Verdict {
    let (sql, removed) = strip_control(sql);
    // SQLite only: sqlparser cannot parse several PRAGMA forms (the call form
    // `PRAGMA table_info(users)`, keyword values `PRAGMA journal_mode =
    // DELETE`), which would fall into a generic PARSE_FAILED whose "fix the
    // SQL syntax" hint is a dead end. Catch the keyword up front so every
    // PRAGMA gets the teaching refusal. PostgreSQL has no PRAGMA — there it is
    // just an unknown token that fails closed as PARSE_FAILED.
    if matches!(policy.dialect, Dialect::Sqlite) {
        let first_token_len = sql
            .trim_start()
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(sql.trim_start().len());
        if sql.trim_start()[..first_token_len].eq_ignore_ascii_case("pragma") {
            return pragma_deny();
        }
    }
    let parsed = match policy.dialect {
        Dialect::Sqlite => Parser::parse_sql(&SQLiteDialect {}, &sql),
        Dialect::Postgres => Parser::parse_sql(&PostgreSqlDialect {}, &sql),
    };
    let statements = match parsed {
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
    // Recursive walk (DESIGN §3 п.4–7): the visitor sees every Statement
    // node in the tree — the top-level one AND writes nested in CTE bodies,
    // derived tables and subqueries (sqlparser wraps those in SetExpr::
    // Insert/Update/Delete/Merge, whose inner Statement is visited too) —
    // plus every Query (locking clauses, SELECT INTO) and every expression
    // (function denylist).
    let mut checker = Checker { policy };
    if let ControlFlow::Break(v) = stmt.visit(&mut checker) {
        return *v;
    }
    let mut warnings = Vec::new();
    if removed > 0 {
        warnings.push(Warning {
            code: "UNICODE_STRIPPED",
            message: format!(
                "{removed} invisible Unicode control/format character(s) were removed \
                 from the query before validation and execution"
            ),
        });
    }
    // into_owned() only here, when the query is actually accepted and its
    // text must travel to the engine; borrowed input clones once, owned moves.
    Verdict::Allow {
        sql: sql.into_owned(),
        warnings,
    }
}

struct Checker<'a> {
    policy: &'a Policy,
}

impl Visitor for Checker<'_> {
    // Boxed: sqlparser recommends a small Break type (it rides the whole
    // recursion); the box also carries our String-heavy Deny cheaply.
    type Break = Box<Verdict>;

    /// Statement allowlist, applied to EVERY Statement node in the tree
    /// (not just the root): `Query`, `Explain` (its inner statement is
    /// visited as well — EXPLAIN ANALYZE executes it on some engines),
    /// the Show* family and Describe. Everything else is fail closed.
    /// Only Show* variants that SQLiteDialect can actually produce are
    /// listed (checked empirically; ShowStatus/ShowVariables/ShowObjects
    /// all parse into ShowVariable under this dialect).
    fn pre_visit_statement(&mut self, stmt: &Statement) -> ControlFlow<Self::Break> {
        match stmt {
            Statement::Query(_)
            | Statement::Explain { .. }
            | Statement::ExplainTable { .. }
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
            | Statement::ShowViews { .. } => ControlFlow::Continue(()),
            Statement::Set(_)
            | Statement::StartTransaction { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::Savepoint { .. }
            | Statement::ReleaseSavepoint { .. } => break_deny(deny(
                DenyReason::TxnControl,
                format!(
                    "'{}' is transaction/session control, which nyet does not accept",
                    head(stmt)
                ),
                "nyet manages its own read-only session; send the SELECT directly, without \
                 BEGIN/COMMIT/SET",
            )),
            // Defense in depth: validate() already catches the leading
            // keyword, but PRAGMA can also reach here wrapped
            // (e.g. EXPLAIN PRAGMA ...).
            Statement::Pragma { .. } => break_deny(pragma_deny()),
            other => break_deny(deny(
                DenyReason::WriteOperation,
                format!("'{}' is not a read operation", head(other)),
                "nyet is read-only; only SELECT, EXPLAIN, SHOW and DESCRIBE statements are \
                 accepted — rewrite the task as a read query",
            )),
        }
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        // DESIGN §3 п.6: SELECT ... FOR UPDATE / FOR SHARE takes row locks —
        // not a plain read. (Layer 2 would refuse it too; this error is
        // clearer.)
        if let Some(lock) = query.locks.first() {
            return break_deny(deny(
                DenyReason::LockingClause,
                format!(
                    "'FOR {}' takes row locks, which is not a plain read",
                    lock.lock_type
                ),
                "nyet is read-only and never locks rows; remove the FOR UPDATE/FOR SHARE \
                 clause",
            ));
        }
        ControlFlow::Continue(())
    }

    /// SELECT ... INTO creates a table; every Select node in the tree
    /// (set-operation arms included) passes through this hook.
    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        if select.into.is_some() {
            return break_deny(deny(
                DenyReason::WriteOperation,
                "the query body is a SELECT INTO, which is not a read operation".to_string(),
                "nyet is read-only; remove the data-modifying part and keep only the SELECT",
            ));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(f) = expr {
            return self.check_function_name(&f.name);
        }
        ControlFlow::Continue(())
    }

    /// Table factors that call a function by a bare `ObjectName` (no
    /// Expr::Function node, so pre_visit_expr never sees them):
    /// `SELECT * FROM f(...)` (Table with args) and `... FROM LATERAL f(...)`
    /// (Function — the LATERAL denylist bypass). The other function-carrying
    /// factors (TableFunction, JsonTable, OpenJson, UNNEST) hold their call
    /// in an `Expr` field the visitor already descends into, so
    /// pre_visit_expr covers them. Plain table names (Table without args)
    /// never match by accident.
    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        match table_factor {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => self.check_function_name(name),
            _ => ControlFlow::Continue(()),
        }
    }
}

impl Checker<'_> {
    /// Case-insensitive denylist match on the TERMINAL component of a (maybe
    /// qualified) function name — that component IS the function name. So
    /// `pg_catalog.pg_read_file` matches (terminal `pg_read_file`), but
    /// `pg_sleep.safe_fn()` (a schema/table happens to be named `pg_sleep`)
    /// does NOT — it is a call to `safe_fn`, not to anything denied. The
    /// config denylists (`deny_functions`/`allow_functions`) likewise carry
    /// unqualified names; a dotted entry is matched literally and so never hits
    /// a terminal name (documented).
    fn check_function_name(&mut self, name: &ObjectName) -> ControlFlow<Box<Verdict>> {
        let Some(ident) = name.0.last().and_then(|p| p.as_ident()) else {
            return ControlFlow::Continue(());
        };
        let lower = ident.value.to_lowercase();
        let denied = self.policy.denied_functions.contains(&lower)
            || self
                .policy
                .denied_prefixes
                .iter()
                .any(|p| lower.starts_with(p));
        if denied {
            return break_deny(deny(
                DenyReason::DeniedFunction,
                format!("the function '{lower}' is on the denylist for this connection"),
                &format!(
                    "'{lower}' can affect state outside a read-only query; if you \
                     accept the risk, add it to validator.allow_functions for this \
                     connection in the config"
                ),
            ));
        }
        ControlFlow::Continue(())
    }
}

fn break_deny(v: Verdict) -> ControlFlow<Box<Verdict>> {
    ControlFlow::Break(Box::new(v))
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

    fn default_policy() -> Policy {
        Policy::sqlite(&[], &[])
    }

    fn validate_default(sql: &str) -> Verdict {
        validate(sql, &default_policy())
    }

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
        warnings: Option<String>,
    }

    fn parse_corpus(file: &Path) -> Vec<Case> {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        // Default dialect from the filename prefix (sqlite_/postgres_), so
        // per-engine files need no repeated `dialect:` key; a per-case
        // `dialect:` still overrides.
        let default_dialect = if name.starts_with("postgres") {
            "postgres"
        } else {
            "sqlite"
        };
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
                    dialect: default_dialect.to_string(),
                    verdict: String::new(),
                    reason: None,
                    warnings: None,
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
            } else if let Some(w) = line.strip_prefix("warnings: ") {
                case.warnings = Some(w.to_string());
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
                let verdict = match case.dialect.as_str() {
                    "sqlite" => validate(&case.query, &Policy::sqlite(&[], &[])),
                    "postgres" => validate(&case.query, &Policy::postgres(&[], &[])),
                    other => panic!("{at}: unknown dialect {other:?}"),
                };
                match verdict {
                    Verdict::Allow { warnings, .. } => {
                        assert_eq!(case.verdict, "allow", "{at}: got allow");
                        assert!(case.reason.is_none(), "{at}: reason on an allow case");
                        let got: Vec<&str> = warnings.iter().map(|w| w.code).collect();
                        match &case.warnings {
                            None => assert!(got.is_empty(), "{at}: unexpected warnings {got:?}"),
                            Some(want) => assert_eq!(got.join(","), *want, "{at}"),
                        }
                        for w in &warnings {
                            assert!(!w.message.is_empty(), "{at}: empty warning message");
                        }
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
                        assert!(
                            case.warnings.is_none(),
                            "{at}: warnings on a deny case (denies carry none)"
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
        assert!(total >= 150, "corpus suspiciously small: {total} cases");
    }

    #[test]
    fn empty_query_is_parse_failed() {
        // "\u{200B}" strips to empty: entirely-invisible input fails closed.
        for sql in ["", "   ", ";", "\u{200B}"] {
            match validate_default(sql) {
                Verdict::Deny { reason, .. } => {
                    assert_eq!(reason, DenyReason::ParseFailed, "{sql:?}")
                }
                Verdict::Allow { .. } => panic!("{sql:?} must not be allowed"),
            }
        }
    }

    #[test]
    fn strip_control_removes_cf_and_cc_keeps_whitespace() {
        // Cf: ZWJ, RTL override, BOM, zero-width space. Cc: NUL, ESC.
        let (cleaned, removed) =
            strip_control("SEL\u{200D}ECT\u{202E} 1\u{FEFF};\u{200B}\u{0000}\u{001B}");
        assert_eq!(cleaned, "SELECT 1;");
        assert_eq!(removed, 6);
        // \t \n \r survive; plain text is untouched and borrowed (no alloc).
        let (cleaned, removed) = strip_control("SELECT\t1\r\nFROM t");
        assert_eq!(cleaned, "SELECT\t1\r\nFROM t");
        assert_eq!(removed, 0);
        assert!(
            matches!(cleaned, Cow::Borrowed(_)),
            "clean input must borrow"
        );
    }

    #[test]
    fn allow_carries_normalized_sql_and_warning() {
        match validate_default("SEL\u{200D}ECT 1") {
            Verdict::Allow { sql, warnings } => {
                assert_eq!(sql, "SELECT 1");
                assert_eq!(warnings.len(), 1);
                assert_eq!(warnings[0].code, "UNICODE_STRIPPED");
                assert!(warnings[0].message.contains('1'), "{}", warnings[0].message);
            }
            Verdict::Deny { message, .. } => panic!("must be allowed: {message}"),
        }
        // No stripping -> no warnings, sql passes through unchanged.
        match validate_default("SELECT 1") {
            Verdict::Allow { sql, warnings } => {
                assert_eq!(sql, "SELECT 1");
                assert!(warnings.is_empty());
            }
            Verdict::Deny { message, .. } => panic!("must be allowed: {message}"),
        }
    }

    #[test]
    fn merge_policy_allow_removes_deny_adds_case_insensitive() {
        let builtin = &["load_extension", "readfile"];
        // allow removes (case-insensitively)...
        let set = merge_denylist(builtin, &["LOAD_EXTENSION".into()], &[]);
        assert!(!set.contains("load_extension"));
        assert!(set.contains("readfile"));
        // ...deny adds (lowercased)...
        let set = merge_denylist(builtin, &[], &["My_Scary_Fn".into()]);
        assert!(set.contains("my_scary_fn"));
        assert!(set.contains("load_extension"));
        // ...both together; deny wins over allow for the same name (fail closed).
        let set = merge_denylist(
            builtin,
            &["readfile".into(), "both".into()],
            &["extra".into(), "BOTH".into()],
        );
        assert!(!set.contains("readfile"));
        assert!(set.contains("extra"));
        assert!(set.contains("both"));
    }

    #[test]
    fn policy_from_config_changes_the_verdict() {
        // allow_functions really allows...
        let relaxed = Policy::sqlite(&["load_extension".to_string()], &[]);
        assert!(matches!(
            validate("SELECT load_extension('x')", &relaxed),
            Verdict::Allow { .. }
        ));
        // ...deny_functions really denies, case-insensitively.
        let strict = Policy::sqlite(&[], &["my_scary_fn".to_string()]);
        match validate("SELECT My_Scary_Fn(1)", &strict) {
            Verdict::Deny {
                reason,
                message,
                hint,
            } => {
                assert_eq!(reason, DenyReason::DeniedFunction);
                assert!(message.contains("my_scary_fn"), "{message}");
                assert!(hint.contains("allow_functions"), "{hint}");
            }
            Verdict::Allow { .. } => panic!("must be denied"),
        }
    }

    #[test]
    fn postgres_sleep_is_overridable_but_prefixes_are_not() {
        // pg_sleep is enumerated (not prefixed) precisely so DESIGN's
        // documented escape hatch `allow_functions = ["pg_sleep"]` still works.
        let relaxed = Policy::postgres(&["pg_sleep".to_string()], &[]);
        assert!(matches!(
            validate("SELECT pg_sleep(1)", &relaxed),
            Verdict::Allow { .. }
        ));
        // The dangerous prefix families (pg_read_*, pg_ls_*, dblink*) are
        // built-in only — allow_functions cannot reach them (fail closed).
        for (sql, allow) in [
            ("SELECT pg_read_binary_file('/x')", "pg_read_binary_file"),
            ("SELECT pg_ls_dir('/')", "pg_ls_dir"),
            ("SELECT dblink_exec('c', 'q')", "dblink_exec"),
        ] {
            let p = Policy::postgres(&[allow.to_string()], &[]);
            assert!(
                matches!(
                    validate(sql, &p),
                    Verdict::Deny {
                        reason: DenyReason::DeniedFunction,
                        ..
                    }
                ),
                "{sql} must stay denied despite allow_functions"
            );
        }
    }

    #[test]
    fn denylist_matches_the_terminal_component_only() {
        let pg = Policy::postgres(&[], &[]);
        // Qualified targets: the real function is the terminal component.
        for sql in [
            "SELECT pg_catalog.pg_sleep(1)",
            "SELECT pg_catalog.pg_read_file('/x')", // prefix family via terminal
            "SELECT pg_catalog.dblink_exec('c', 'q')",
            "SELECT pg_logical_emit_message(false, 'a', 'b')",
        ] {
            assert!(
                matches!(
                    validate(sql, &pg),
                    Verdict::Deny {
                        reason: DenyReason::DeniedFunction,
                        ..
                    }
                ),
                "{sql} must be denied"
            );
        }
        // A schema/table NAMED like a denied function is not a call to it —
        // the terminal component (safe_fn / col) is what runs.
        assert!(matches!(
            validate("SELECT pg_sleep.safe_fn(1)", &pg),
            Verdict::Allow { .. }
        ));
        assert!(matches!(
            validate("SELECT pg_read_file.col FROM t", &pg),
            Verdict::Allow { .. }
        ));
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
            // Unicode-smuggled PRAGMA: normalization runs before the check.
            "P\u{200D}RAGMA user_version",
        ] {
            let Verdict::Deny {
                reason,
                message,
                hint,
            } = validate_default(sql)
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
            validate_default("SELECT pragmatic FROM words"),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn deny_messages_name_the_offender() {
        let Verdict::Deny {
            reason, message, ..
        } = validate_default("DROP TABLE users")
        else {
            panic!("DROP must be denied")
        };
        assert_eq!(reason, DenyReason::WriteOperation);
        assert!(message.contains("DROP"), "{message}");
    }
}
