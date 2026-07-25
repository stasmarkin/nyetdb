//! SQL validator, layer 1: pure classification of a query string into
//! Allow/Deny. Depends only on sqlparser + unicode-properties (+std) — the
//! golden corpus runs without live databases (Д1/Д2). Fail closed: anything
//! not understood is denied.
//!
//! Pipeline (DESIGN §3): Unicode normalization -> parse -> exactly one
//! statement -> recursive AST walk (top-level allowlist, nested writes,
//! locking clauses, function denylist).

use sqlparser::ast::{
    Expr, ObjectName, Query, Select, Statement, TableFactor, UtilityOption, Visit, Visitor,
};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect, SQLiteDialect};
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
    ExecutableComment,
    ExplainAnalyze,
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
            DenyReason::ExecutableComment => "EXECUTABLE_COMMENT",
            DenyReason::ExplainAnalyze => "EXPLAIN_ANALYZE",
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
    Allow {
        sql: String,
        warnings: Vec<Warning>,
        /// True when the accepted statement is a plain query (SELECT / WITH /
        /// set operation) — the only kind that can be wrapped in an EXPLAIN.
        /// The rest of the allowlist (EXPLAIN, SHOW, DESCRIBE) is metadata that
        /// no planner estimates, so the cli skips the guardrail for it.
        is_query: bool,
    },
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
    Mysql,
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

/// Built-in MySQL/MariaDB denylist (rationale in docs/DEV.md): functions that
/// act OUTSIDE the read-only transaction (filesystem, connection-tie-up DoS,
/// UDF code execution), so layer 2 does not stop them — the validator is the
/// only guard. Config-tunable via `allow_functions` / `deny_functions`.
const MYSQL_DENIED_FUNCTIONS: &[&str] = &[
    "load_file", // reads any server file into a string (needs FILE priv; deny anyway)
    "sleep",     // silent DoS: ties up a pooled connection (like pg_sleep)
    "benchmark", // BENCHMARK(count, expr): CPU DoS loop
    "sys_exec",  // lib_mysqludf_sys UDF: runs a shell command (RCE) if installed
    "sys_eval",  // lib_mysqludf_sys UDF: runs a command and returns output (RCE)
    // Named-lock family: GET_LOCK(name, -1) blocks the connection forever
    // (DoS, the SLEEP class). release_* are non-blocking but denied for
    // completeness — an agent read never needs any of them. (is_used_lock /
    // is_free_lock are pure reads, left allowed.)
    "get_lock",
    "release_lock",
    "release_all_locks",
    // Replication-wait family: each blocks until a replica/GTID position
    // (unbounded DoS).
    "master_pos_wait",
    "source_pos_wait",
    "master_gtid_wait", // MariaDB: blocks until a GTID position is reached
    "wait_for_executed_gtid_set",
    "wait_until_sql_thread_after_gtids",
];

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

    /// Effective MySQL/MariaDB policy. MariaDB is dialect-identical to MySQL in
    /// sqlparser, so both engines share this. Tuned by config like sqlite().
    /// No prefix families (MySQL's dangerous functions have no clean shared
    /// prefix; enumerated by exact name so `allow_functions` can reach them).
    pub fn mysql(allow_functions: &[String], deny_functions: &[String]) -> Policy {
        Policy {
            dialect: Dialect::Mysql,
            denied_functions: merge_denylist(
                MYSQL_DENIED_FUNCTIONS,
                allow_functions,
                deny_functions,
            ),
            denied_prefixes: &[],
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

/// True if `sql` contains a MySQL/MariaDB *executable* comment opener — `/*!`,
/// `/*M!` (case-insensitive) or an optimizer hint `/*+` — OUTSIDE any string or
/// identifier literal and outside an ordinary comment. String-aware so a literal
/// that merely contains the text (`'/*! not a comment */'`) is data, not a hit.
///
/// The validator is pure and runs BEFORE connecting, so it does not know the
/// server's `sql_mode` — which changes where a string ENDS: under
/// `NO_BACKSLASH_ESCAPES` a `\` is a literal (so `'x\'` closes the string), and
/// under `ANSI_QUOTES` `"` is an identifier without `\` escapes (so `"x\"`
/// closes). A single default-mode pass under-denies both: it would think the
/// string runs past a `/*!` the server actually executes. Fail-closed fix: scan
/// TWICE and deny if EITHER pass finds an opener outside a literal —
/// `backslash_escapes = true` (default `'`/`"` strings) and `= false`
/// (`NO_BACKSLASH_ESCAPES`, which also models `ANSI_QUOTES` `"`-identifiers,
/// escape-free). The real server matches exactly one pass on the backslash
/// question, so an executed opener is flagged by at least one. Doubling
/// (`''`/`""`/`` `` ``) is mode-independent and applied in both. Over-denial of a
/// benign string containing a backslash is the acceptable failure direction.
/// Pure (Д1); scans bytes (ASCII delimiters never collide with UTF-8 >= 0x80).
fn has_mysql_executable_comment(sql: &str) -> bool {
    scan_executable_comment(sql, true) || scan_executable_comment(sql, false)
}

fn scan_executable_comment(sql: &str, backslash_escapes: bool) -> bool {
    #[derive(PartialEq)]
    enum S {
        Normal,
        Single,
        Double,
        Backtick,
        Block,
        Line,
    }
    let b = sql.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut state = S::Normal;
    while i < n {
        let c = b[i];
        match state {
            S::Normal => match c {
                b'\'' => state = S::Single,
                b'"' => state = S::Double,
                b'`' => state = S::Backtick,
                b'#' => state = S::Line,
                // MySQL `-- ` comment: the `--` must be followed by whitespace
                // (or EOL). `--x` is NOT a comment, so don't enter Line there
                // (that would skip a later `/*!` on the "line" — a bypass).
                b'-' if b.get(i + 1) == Some(&b'-')
                    && b.get(i + 2).is_none_or(|&x| x.is_ascii_whitespace()) =>
                {
                    state = S::Line;
                    i += 1;
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    let after = b.get(i + 2).copied();
                    let executable = matches!(after, Some(b'!') | Some(b'+'))
                        || (matches!(after, Some(b'M') | Some(b'm'))
                            && b.get(i + 3) == Some(&b'!'));
                    if executable {
                        return true;
                    }
                    state = S::Block;
                    i += 1; // consume the '*' so `/*/` isn't read as opener+closer
                }
                _ => {}
            },
            S::Single => {
                if backslash_escapes && c == b'\\' {
                    i += 1; // skip the escaped byte
                } else if c == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        i += 1; // doubled '' is a literal quote (mode-independent)
                    } else {
                        state = S::Normal;
                    }
                }
            }
            S::Double => {
                if backslash_escapes && c == b'\\' {
                    i += 1;
                } else if c == b'"' {
                    if b.get(i + 1) == Some(&b'"') {
                        i += 1;
                    } else {
                        state = S::Normal;
                    }
                }
            }
            S::Backtick => {
                // Identifiers never take `\` escapes; only `` `` `` doubling.
                if c == b'`' {
                    if b.get(i + 1) == Some(&b'`') {
                        i += 1;
                    } else {
                        state = S::Normal;
                    }
                }
            }
            S::Block => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    state = S::Normal;
                    i += 1;
                }
            }
            S::Line => {
                if c == b'\n' {
                    state = S::Normal;
                }
            }
        }
        i += 1;
    }
    false
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
    // MySQL/MariaDB only: reject executable comments and optimizer hints BEFORE
    // parsing. sqlparser drops `/*! ... */`, `/*M! ... */` and `/*+ ... */` as
    // ordinary comments, so their payload never reaches the AST — but the SERVER
    // executes it. `SELECT 1 /*! SLEEP(10) */` would validate as `SELECT 1` yet
    // run SLEEP (and `/*! ... INTO OUTFILE ... */` would write a file), bypassing
    // the whole layer-1 policy. Fail closed. Postgres/SQLite do not execute
    // comment bodies, so this is MySQL-only.
    if matches!(policy.dialect, Dialect::Mysql) && has_mysql_executable_comment(&sql) {
        return deny(
            DenyReason::ExecutableComment,
            "the query contains a MySQL executable comment or optimizer hint \
             (/*! ... */, /*M! ... */ or /*+ ... */), whose body the server runs \
             but a SQL parser ignores"
                .to_string(),
            "remove the /*! ... */, /*M! ... */ or /*+ ... */ comment; write the \
             statement as plain SQL so nyet can see everything it will execute",
        );
    }
    let parsed = match policy.dialect {
        Dialect::Sqlite => Parser::parse_sql(&SQLiteDialect {}, &sql),
        Dialect::Postgres => Parser::parse_sql(&PostgreSqlDialect {}, &sql),
        Dialect::Mysql => Parser::parse_sql(&MySqlDialect {}, &sql),
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
        is_query: matches!(stmt, Statement::Query(_)),
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
            // EXPLAIN ANALYZE *runs* the statement — it is an execution wearing
            // a plan's clothes, and it slips past everything a plan-based
            // guardrail can do (no plan is returned to judge, and the row limit
            // does not apply to plan output either). Only a plain query needs
            // this arm: a write inside the EXPLAIN falls through and the
            // recursion below denies it with the sharper WRITE_OPERATION.
            Statement::Explain {
                analyze,
                options,
                statement,
                ..
            } if explain_executes(*analyze, options.as_deref())
                && matches!(**statement, Statement::Query(_)) =>
            {
                break_deny(deny(
                    DenyReason::ExplainAnalyze,
                    "EXPLAIN ANALYZE executes the statement it is asked to explain, so it is \
                     an execution, not a plan"
                        .to_string(),
                    "run `nyet explain <alias> <query>` instead — it returns the plan and a \
                     cost estimate without executing anything; a plain EXPLAIN (no ANALYZE) \
                     is accepted as a query too",
                ))
            }
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

/// Does this EXPLAIN carry ANALYZE? Every spelling of it:
///
/// - the keyword form (`EXPLAIN ANALYZE ...`) sets the `analyze` flag, while the
///   PostgreSQL parenthesized form (`EXPLAIN (ANALYZE, FORMAT JSON) ...`) lands
///   in `options` with the flag left FALSE — reading only the flag left the whole
///   paren form as a bypass;
/// - **PostgreSQL also accepts the British `ANALYSE`**, and `EXPLAIN (ANALYSE)
///   SELECT ...` executed the query in full (verified live) while a name match on
///   "analyze" alone waved it through.
///
/// Any such option counts, `(analyze false)` included: fail closed.
fn explain_executes(analyze: bool, options: Option<&[UtilityOption]>) -> bool {
    analyze
        || options.is_some_and(|options| {
            options.iter().any(|o| {
                matches!(
                    o.name.value.to_ascii_lowercase().as_str(),
                    "analyze" | "analyse"
                )
            })
        })
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
        } else if name.starts_with("mysql") {
            "mysql"
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
                    "mysql" => validate(&case.query, &Policy::mysql(&[], &[])),
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
        assert!(total >= 200, "corpus suspiciously small: {total} cases");
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
            Verdict::Allow { sql, warnings, .. } => {
                assert_eq!(sql, "SELECT 1");
                assert_eq!(warnings.len(), 1);
                assert_eq!(warnings[0].code, "UNICODE_STRIPPED");
                assert!(warnings[0].message.contains('1'), "{}", warnings[0].message);
            }
            Verdict::Deny { message, .. } => panic!("must be allowed: {message}"),
        }
        // No stripping -> no warnings, sql passes through unchanged.
        match validate_default("SELECT 1") {
            Verdict::Allow { sql, warnings, .. } => {
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
    fn mysql_denylist_and_dialect() {
        let my = Policy::mysql(&[], &[]);
        // Built-in MySQL denials.
        for sql in [
            "SELECT sleep(5)",
            "SELECT benchmark(1000000, md5('x'))",
            "SELECT load_file('/etc/passwd')",
            "SELECT sys_exec('rm -rf /')",
            "SELECT SLEEP(1)", // case-insensitive
        ] {
            assert!(
                matches!(
                    validate(sql, &my),
                    Verdict::Deny {
                        reason: DenyReason::DeniedFunction,
                        ..
                    }
                ),
                "{sql} must be denied"
            );
        }
        // MySQL-specific syntax that must parse and pass under MySqlDialect.
        for sql in [
            "SELECT `id`, `email` FROM `users` LIMIT 10",
            "SELECT JSON_EXTRACT(doc, '$.k') AS k FROM events",
            "SELECT id FROM users WHERE name = \"quoted\"", // MySQL double-quoted string
        ] {
            assert!(
                matches!(validate(sql, &my), Verdict::Allow { .. }),
                "{sql} must be allowed"
            );
        }
        // allow_functions un-denies (documented escape hatch).
        let relaxed = Policy::mysql(&["sleep".to_string()], &[]);
        assert!(matches!(
            validate("SELECT sleep(1)", &relaxed),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn executable_comment_scanner_is_string_aware() {
        // Hits: executable comments / optimizer hint in normal code.
        for sql in [
            "SELECT 1 /*! SLEEP(1) */",
            "SELECT 1 /*!50000 SLEEP(1) */",
            "SELECT 1 /*M! SLEEP(1) */",
            "SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1",
            "SELECT 1/*!*/",
            // sql_mode bypasses (fail closed via the no-backslash-escapes pass):
            // NO_BACKSLASH_ESCAPES makes 'x\' close the string, exposing /*!.
            "SELECT id FROM t WHERE name='x\\' AND 1=1 /*! OR SLEEP(5) */ AND note='y'",
            // ANSI_QUOTES makes "x\" a closed identifier, likewise exposing /*!.
            "SELECT id FROM t WHERE name=\"x\\\" AND 1=1 /*! OR SLEEP(5) */ AND id=\"y\"",
        ] {
            assert!(has_mysql_executable_comment(sql), "must flag: {sql}");
        }
        // Misses: the opener sits inside a clean literal or an ordinary comment
        // (no backslash trick) — data, not an executable comment. Both passes
        // agree the opener is inside a string/identifier.
        for sql in [
            "SELECT '/*! not a comment */' AS s",
            "SELECT \"/*! nope */\" AS s",
            "SELECT `/*!col` FROM t",         // backtick identifier
            "SELECT 1 /* plain comment */",   // ordinary block comment
            "SELECT 1 # tail /*! hidden */",  // inside a # line comment
            "SELECT 1 -- tail /*! hidden */", // inside a -- line comment
            "SELECT 'a''b /*! ok */' AS s",   // doubled-quote escape (mode-independent)
        ] {
            assert!(!has_mysql_executable_comment(sql), "must not flag: {sql}");
        }
        // End-to-end: the validator denies with EXECUTABLE_COMMENT, and the
        // string-literal twin is allowed (only under the MySQL dialect).
        let my = Policy::mysql(&[], &[]);
        assert!(matches!(
            validate("SELECT 1 /*! SLEEP(1) */", &my),
            Verdict::Deny {
                reason: DenyReason::ExecutableComment,
                ..
            }
        ));
        assert!(matches!(
            validate("SELECT '/*! not a comment */' AS s", &my),
            Verdict::Allow { .. }
        ));
        // Postgres/SQLite do not execute comment bodies -> not scanned here:
        // the same text that MySQL denies is an ordinary comment elsewhere.
        assert!(matches!(
            validate("SELECT 1 /*! */", &Policy::postgres(&[], &[])),
            Verdict::Allow { .. }
        ));
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
