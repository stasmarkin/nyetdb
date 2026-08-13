//! SQL validator, layer 1: pure classification of a query string into
//! Allow/Deny. Depends only on sqlparser + unicode-properties (+std) — the
//! golden corpus runs without live databases (Д1/Д2). Fail closed: anything
//! not understood is denied.
//!
//! Pipeline (DESIGN §3): Unicode normalization -> parse -> exactly one
//! statement -> recursive AST walk (top-level allowlist, nested writes,
//! locking clauses, function denylist).

use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, JoinConstraint,
    JoinOperator, ObjectName, OrderByKind, Query, Select, SelectItem,
    SelectItemQualifiedWildcardKind, SetExpr, Statement, TableAlias, TableFactor,
    TableFunctionArgs, TableWithJoins, UtilityOption, Visit, Visitor,
};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use std::any::Any;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;
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
    /// A column the connection's `[pii]` policy protects would be exposed —
    /// proven either by NAME before execution (net A) or by the driver's column
    /// PROVENANCE after execution (net B).
    PiiColumn,
    /// The validator itself panicked: a BUG in nyet, reported to the caller as
    /// an ordinary refusal so the query still does not reach the database.
    InternalError,
    /// The result carries a column whose origin the database would not state,
    /// on a connection that protects columns as PII: nyet cannot prove the
    /// value is not protected data, so it refuses (fail closed).
    PiiUnprovable,
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
            DenyReason::InternalError => "INTERNAL_ERROR",
            DenyReason::PiiColumn => "PII_COLUMN",
            DenyReason::PiiUnprovable => "PII_UNPROVABLE",
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
        /// RESULT-column indexes that `mode = "mask"` let through on the
        /// PROMISE that net B redacts them (empty in every other case). The cli
        /// hands them to `check_origins`, which refuses when a promise was not
        /// kept — net A's relaxation is only ever as good as net B's proof.
        pii_exempt: Vec<usize>,
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
    /// Catalogs of THIS engine that publish sampled data values (see
    /// `*_VALUE_SAMPLING_CATALOGS`). Per-dialect like `denied_prefixes`: a
    /// user table that merely shares a name with another engine's catalog is
    /// not a catalog (finding 10).
    value_sampling_catalogs: &'static [&'static str],
    /// `[connections.X.pii] columns` — empty by default, so a connection
    /// without the section behaves byte for byte as before (UX-5).
    pii: PiiRules,
}

/// The connection's PII policy: which `table.column` pairs the config owner
/// marked as personal data. Pure value object — the strings arrive from the
/// config, the validator only matches names against them.
///
/// **Matching is case-insensitive and ignores any schema qualifier**: a rule
/// may be written `schema.table.column` for readability, but only the
/// `table.column` tail is compared (against the terminal component of whatever
/// the query or the driver names). Both choices widen the deny surface, which
/// is the only safe direction here — Postgres folds unquoted identifiers to
/// lower case, MySQL's table-name case sensitivity is platform-dependent, and
/// the same physical table can be reached under several qualifications.
#[derive(Debug, Clone, Default)]
pub struct PiiRules {
    /// Lowercased (bare table, column) pairs — the ONE piece of state. Every
    /// other view of the policy (which tables are protected, which columns of a
    /// given table) is derived on the fly: a second, cached copy is exactly the
    /// kind of state a later edit desynchronizes into a fail-OPEN net A.
    pairs: BTreeSet<(String, String)>,
    /// What happens when a rule matches. `Deny` is the default, so a config
    /// written before this key keeps the same VERDICT and the same rows (UX-5);
    /// the refusal `hint` texts were rewritten and `schema`/`doctor` gained the
    /// PII marking and check, which are additive.
    mode: PiiMode,
}

/// The sanction a matching rule carries (`[connections.X.pii] mode`). One mode
/// per connection on purpose (Д5): per-column modes would multiply the rules an
/// agent has to learn without protecting anything the connection-wide choice
/// does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PiiMode {
    /// Refuse the whole query (the historical, and default, behavior).
    #[default]
    Deny,
    /// Let a plain projection through and replace every value of the protected
    /// column with `[REDACTED]`. Only the PROJECTION is relaxed — see
    /// `maskable_projection`.
    Mask,
}

impl PiiMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PiiMode::Deny => "deny",
            PiiMode::Mask => "mask",
        }
    }

    /// Config value -> mode. Fail loud (Д3): a typo must not silently pick the
    /// weaker OR the stronger sanction.
    pub fn parse(value: &str) -> Result<PiiMode, String> {
        match value {
            "deny" => Ok(PiiMode::Deny),
            "mask" => Ok(PiiMode::Mask),
            other => Err(format!(
                "\"{other}\" is not a PII mode: write mode = \"deny\" (refuse the whole \
                 query, the default) or mode = \"mask\" (return the protected column as \
                 [REDACTED] when it is plainly projected)"
            )),
        }
    }
}

impl PiiRules {
    /// Parse `["users.email", "app.users.phone"]`. Fail loud (Д3) on anything
    /// that is not `table.column` / `schema.table.column` **or that cannot
    /// possibly match an identifier**: a rule nyet accepts but can never match
    /// is worse than a rejected one — the config owner believes the column is
    /// protected while every query returns it (finding 7).
    pub fn parse(rules: &[String], mode: PiiMode) -> Result<PiiRules, String> {
        let mut out = PiiRules {
            mode,
            ..PiiRules::default()
        };
        for raw in rules {
            let parts: Vec<&str> = raw.split('.').map(str::trim).collect();
            let bad = |why: &str| {
                Err(format!(
                    "\"{raw}\" is not a valid PII rule ({why}): write \"table.column\" \
                     (or \"schema.table.column\"), one column per list entry — plain \
                     identifiers, or double-quoted ones for a name that needs it \
                     (\"users\".\"e-mail\")"
                ))
            };
            if !matches!(parts.len(), 2 | 3) {
                return bad("expected 2 or 3 dot-separated parts");
            }
            let mut names = Vec::with_capacity(parts.len());
            for part in &parts {
                match unquote(part) {
                    // A fully double-quoted part is taken verbatim, so a name
                    // that NEEDS quotes ("e-mail", "user data") can be protected
                    // at all — and `"users"."email"`, the way psql/pg_dump print
                    // identifiers, becomes a working rule.
                    Some("") => return bad("empty quoted name component"),
                    Some(inner) => names.push(inner.to_lowercase()),
                    None => {
                        if part.is_empty() {
                            return bad("empty name component");
                        }
                        // Otherwise: identifier characters only. This is what
                        // rejects a whole list crammed into one string
                        // ("users.email, users.phone" — one forgotten comma),
                        // which used to be accepted and could never match.
                        if let Some(c) = part.chars().find(|c| !is_identifier_char(*c)) {
                            return bad(&format!("{c:?} is not valid in an identifier"));
                        }
                        names.push(part.to_lowercase());
                    }
                }
            }
            let column = names.pop().unwrap_or_default();
            let table = names.pop().unwrap_or_default();
            out.pairs.insert((table, column));
        }
        Ok(out)
    }

    /// No rules = no PII policy on this connection (the historical behavior).
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The sanction this connection applies (deny / mask).
    pub fn mode(&self) -> PiiMode {
        self.mode
    }

    /// The protected `(table, column)` pairs, bare and lowercased — for the
    /// `doctor` check that asks the SERVER whether the role can read them.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pairs.iter().map(|(t, c)| (t.as_str(), c.as_str()))
    }

    /// Does this policy protect `column` of `table`? Both may be qualified
    /// (`app.users`, `test.users`, `public.users`) — only the terminal
    /// component is compared, see the type doc.
    /// (The AST and the drivers both hand over the identifier VALUE without its
    /// quotes, so a quoted rule matches the same way an unquoted one does.)
    pub fn protects(&self, table: &str, column: &str) -> bool {
        self.pairs
            .contains(&(bare_name(table).to_lowercase(), column.to_lowercase()))
    }

    /// Is `table` (already lowercased and bare) protected at all?
    fn protects_table(&self, table: &str) -> bool {
        self.pairs.iter().any(|(t, _)| t == table)
    }
}

/// The inside of a fully double-quoted part (`"e-mail"` -> `e-mail`), or None
/// when the part is not quoted at all. A part that only opens or only closes a
/// quote — or holds one in the middle — is neither, and fails validation below.
/// A quoted name is still matched case-insensitively like every other rule
/// (over-matching is the safe direction; documented).
fn unquote(part: &str) -> Option<&str> {
    let inner = part.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('"')).then_some(inner)
}

/// What may appear in an unquoted SQL identifier. `is_alphanumeric` covers
/// non-ASCII letters and digits, which PostgreSQL and MySQL both accept.
fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// The terminal component of a possibly-qualified name (`s.t` -> `t`).
fn bare_name(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// Catalog objects of THIS engine that publish **sampled DATA VALUES**, not just
/// statistics shapes: reading them hands out the very cells a PII rule protects,
/// without ever naming the protected column. Denied wholesale on any connection
/// that has at least one PII rule (name-matched on the terminal component, so
/// the schema-qualified spellings — `pg_catalog.pg_stats`,
/// `information_schema.column_statistics` — are covered too).
///
/// PostgreSQL: `pg_stats` / `pg_stats_ext` / `pg_stats_ext_exprs` expose
/// `most_common_vals` and `histogram_bounds` (literal column values);
/// `pg_statistic` / `pg_statistic_ext_data` are the raw tables behind them.
const POSTGRES_VALUE_SAMPLING_CATALOGS: &[&str] = &[
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    "pg_statistic",
    "pg_statistic_ext_data",
];

/// MySQL `information_schema.column_statistics` carries histogram buckets of
/// real values; MariaDB's `mysql.column_stats` carries `min_value`/`max_value`.
const MYSQL_VALUE_SAMPLING_CATALOGS: &[&str] = &["column_statistics", "column_stats"];

/// `sqlite_stat3`/`sqlite_stat4` store sampled index-key values.
/// `sqlite_stat1` holds only row counts, so it is deliberately NOT here.
const SQLITE_VALUE_SAMPLING_CATALOGS: &[&str] = &["sqlite_stat3", "sqlite_stat4"];

/// Where one column of a RESULT SET came from, as the driver reported it on the
/// wire (net B). Mirrors `sqlx::ColumnOrigin` without depending on sqlx: the
/// engines translate, this pure module judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The driver named the table and the original column.
    Table { table: String, column: String },
    /// The driver stated the value is computed, not a stored column.
    Expression,
    /// The driver would not say. Undetermined -> refused (fail closed).
    Unknown,
}

/// A refusal without the Allow half of `Verdict` — what a check that can only
/// ever refuse returns. Keeps the caller free of an unreachable Allow arm.
#[derive(Debug)]
pub struct Refusal {
    pub reason: DenyReason,
    pub message: String,
    pub hint: String,
}

/// Net B: judge the RESULT of an executed query by the provenance the driver
/// reported, before a single row reaches the agent.
///
/// `columns` are the result column labels (agent-chosen names, safe to echo); a
/// column with no reported origin at all counts as `Unknown`. **No cell value is
/// ever read here.**
///
/// **What this net is and is not.** It is a wire-level cross-check on what the
/// database actually returned. `Expression` is accepted, and that is a
/// deliberate, documented LIMIT — not a proof that the value is clean. An
/// expression carries no provenance at all, so a computed column over an
/// unlisted view (`contact || ''`) is invisible here even on SQLite, where the
/// bare `contact` IS caught. Refusing every `Expression` would close that, and
/// was rejected on cost, not on principle: it would refuse every aggregate,
/// every computed column and every set operation on every PII connection
/// (UX-1), and it is not the root fix for any known bypass — those live in net
/// A and are fixed there. The boundary that holds for renaming layers is:
/// list the view's own columns in the policy, and use column-level GRANTs
/// (README).
///
/// **Under `mode = "mask"` this net is also the ENFORCER, and the masked set is
/// EXACTLY the set net A sanctioned** (`pii_exempt`, the result-column indexes it
/// let through on the promise of redaction). Both halves are load-bearing:
///
/// - a promised column that did NOT come back protected refuses
///   (`PII_UNPROVABLE`) — otherwise `mask` returns what `deny` refused;
/// - a protected column that was NOT promised refuses exactly as it does under
///   `deny`, instead of being masked. Net B knows MORE than net A (SQLite
///   resolves a view column to its base table), and a column net A never saw is
///   one it could not judge the `ORDER BY`/`DISTINCT` over: `SELECT id, contact
///   FROM v_users ORDER BY contact` came back fully redacted and perfectly
///   sorted by the hidden value. Masking only what net A sanctioned makes the
///   ordering guard complete by construction — and makes the three engines
///   agree, since PostgreSQL and MySQL never reported through a view anyway.
///
/// `Unknown` still refuses in both modes — an unprovable column could be the
/// protected one and must not be handed over unmasked.
pub fn check_origins(
    rules: &PiiRules,
    columns: &[String],
    origins: &[Origin],
    pii_exempt: &[usize],
) -> Result<Vec<usize>, Refusal> {
    catching_panics(|| judge_origins(rules, columns, origins, pii_exempt))
        .unwrap_or_else(|detail| Err(internal_error_refusal(&detail)))
}

fn judge_origins(
    rules: &PiiRules,
    columns: &[String],
    origins: &[Origin],
    pii_exempt: &[usize],
) -> Result<Vec<usize>, Refusal> {
    // Panic injection for the boundary test; compiled out of the shipped binary.
    #[cfg(test)]
    if columns.iter().any(|c| c.contains("__nyet_test_panic__")) {
        panic!("injected net B panic");
    }
    let mut mask = Vec::new();
    if rules.is_empty() {
        return Ok(mask);
    }
    for (i, label) in columns.iter().enumerate() {
        match origins.get(i).unwrap_or(&Origin::Unknown) {
            Origin::Expression => {}
            Origin::Table { table, column } => {
                if rules.protects(table, column) {
                    // Masked ONLY where net A sanctioned this very column.
                    if rules.mode == PiiMode::Mask && pii_exempt.contains(&i) {
                        mask.push(i);
                        continue;
                    }
                    return Err(Refusal {
                        reason: DenyReason::PiiColumn,
                        message: format!(
                            "nyet: result column '{label}' resolves to '{}.{column}', which \
                             this connection's PII policy protects — the query reached it \
                             indirectly (through a view or a renaming layer), so nothing was \
                             returned",
                            bare_name(table)
                        ),
                        // NOT the generic hint: this refusal is about the layer,
                        // not the query, and the mask text ("select it plainly")
                        // would send an agent that DID select it plainly round in
                        // circles. Only the config owner can fix this one.
                        hint: pii_layer_hint(),
                    });
                }
            }
            Origin::Unknown => {
                return Err(Refusal {
                    reason: DenyReason::PiiUnprovable,
                    message: format!(
                        "nyet: the database would not say where result column '{label}' comes \
                         from, and this connection protects some columns as PII — nyet cannot \
                         prove the value is not protected data"
                    ),
                    hint: pii_hint(rules.mode),
                });
            }
        }
    }
    // THE PROMISE, the other half. Net A let a column through only because net B
    // was going to redact it; a column that was NOT redacted has to refuse, or
    // the mode turns a refusal into a full disclosure. Two agent-reachable ways
    // to get here, both found in review, both closed by this:
    //   - a rule on a VIEW's column while the driver resolves the origin to the
    //     BASE table (SQLite): net A protected `v_users.contact`, net B saw
    //     `users.email`, and nothing matched — the README's own "list the view"
    //     recipe used to hand the value over under `mask`;
    //   - a CTE shadowing the protected table's name: the scope is active, so
    //     the projection is exempted, but the value is an expression with no
    //     provenance at all.
    // The strict form ("an exempted column MUST come back masked") costs nothing
    // against `deny`: net A only ever exempts an occurrence it would otherwise
    // have refused. The index is trustworthy because net A refuses a WILDCARD
    // beside a maskable column — with only scalar items in the SELECT list, the
    // n-th item IS the n-th result column.
    if let Some(i) = pii_exempt.iter().find(|i| !mask.contains(i)) {
        return Err(Refusal {
            reason: DenyReason::PiiUnprovable,
            message: format!(
                "nyet: result column '{}' was allowed only because this connection masks \
                 protected columns, but the database did not report it as one of them — so \
                 nyet cannot prove the value it returned is redacted, and nothing was returned",
                columns.get(*i).map_or("?", String::as_str)
            ),
            hint: pii_hint(rules.mode),
        });
    }
    Ok(mask)
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
    // --- W7 audit, August 2026 ---------------------------------------------
    // Every name below was MEASURED against postgres:16-alpine the way the
    // nextval/setval entries were: run inside `BEGIN READ ONLY`, which is what
    // layer 2 gives us. All of them ran. Most are stopped by layer 3 (a
    // non-superuser role gets "permission denied"), but layer 3 is a
    // RECOMMENDATION nyet nags about, not something it can assume — which is
    // exactly why the validator exists as the local layer.
    //
    // XID assignment is the sharp one: it is the only family here that also
    // survives layer 3. Measured under the read-only role: three
    // `txid_current()` calls advanced the cluster's xmax by three, while three
    // plain SELECTs advanced it by none. A read-only tool that burns global
    // transaction ids moves the cluster towards wraparound — the nextval class,
    // one scope wider. (The `*_if_assigned` variants only report, and stay
    // allowed.)
    "txid_current",
    "pg_current_xact_id",
    // Cluster-level WAL and backup state. None of it is a read, none of it is
    // undone by ROLLBACK: a restore point and a WAL switch are written, and
    // pg_backup_start leaves the cluster IN backup mode until someone stops it.
    "pg_create_restore_point",
    "pg_switch_wal",
    "pg_switch_xlog", // pre-10 spelling, still reachable on old servers
    "pg_rotate_logfile",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_start_backup", // pre-15 spelling
    "pg_stop_backup",
    // Replication slots are durable objects that PIN WAL: an agent that
    // creates one can fill the server's disk without writing a single row, and
    // one that drops (or advances) another one breaks a live replica. The
    // `get_changes` pair CONSUMES from the slot, which advances it durably;
    // `peek_changes` does not and stays allowed.
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_copy_physical_replication_slot",
    "pg_copy_logical_replication_slot",
    "pg_drop_replication_slot",
    "pg_replication_slot_advance",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_get_binary_changes",
    // Replication origins: same story, durable catalog objects plus session
    // state. The `*_progress` readers are not here.
    "pg_replication_origin_create",
    "pg_replication_origin_drop",
    "pg_replication_origin_advance",
    "pg_replication_origin_session_setup",
    "pg_replication_origin_session_reset",
    "pg_replication_origin_xact_setup",
    "pg_replication_origin_xact_reset",
    // Statistics resets are irreversible for everyone using the server, and
    // the extension's own reset is spelled differently enough to need naming
    // (the rest are covered by the pg_stat_reset prefix below).
    "pg_stat_statements_reset",
    // Creates catalog objects (collations) — DDL wearing a function's clothes.
    "pg_import_system_collations",
    // Index maintenance: these WRITE to the index, and measured, they do it
    // right through `BEGIN READ ONLY`. Only index ownership stops them.
    "brin_summarize_new_values",
    "brin_summarize_range",
    "brin_desummarize_range",
    "gin_clean_pending_list",
    // NOTIFY through a function call. The statement form is refused already;
    // this one delivers the same message to every listener once the read-only
    // transaction commits, and a read has no business sending one.
    "pg_notify",
    // `SET` wearing a function's clothes: the statement form is refused as
    // TXN_CONTROL, so the wrapper cannot stay allowed. Measured: under the
    // read-only role it sets statement_timeout to 0 for the session. That does
    // NOT rescue the running query (the timer is already armed — measured too),
    // so today it only survives as long as the process; with the planned
    // connection daemon the session outlives the call and it becomes a real
    // way to disarm the timeout nyet configured.
    "set_config",
    "lo_import", // reads a server file into a large object
    "lo_export", // writes a large object to a server file
    // Advisory-lock family (all 11 pg_catalog names). Taking a lock is not a
    // read, and a read never needs one. The SESSION-scoped ones are the sharp
    // half: they are NOT released by ROLLBACK (measured — a lock taken inside
    // nyet's read-only transaction is still held after it aborts), only by the
    // backend dying. The blocking forms additionally hang the query until the
    // server's statement_timeout (the pg_sleep DoS class). The `_xact_` ones do
    // die with the transaction, and are denied with the rest so the rule is one
    // rule ("nyet never takes a lock") instead of a per-variant table the agent
    // has to learn — and because their blocking forms hang exactly like the
    // session ones. ENUMERATED, not prefixed (`*_to_xml` precedent): the family
    // has been closed since 9.1, and `validator.allow_functions` stays reachable.
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_unlock",
    "pg_advisory_unlock_shared",
    "pg_advisory_unlock_all",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
    // The `*_to_xml` family (built into pg_catalog since 8.3, no extension, no
    // DBA, available to a plain SELECT-only role). Two separate powers, both
    // fatal to layer 1:
    //   - `query_to_xml*` EXECUTES a SQL string the parser never sees, so it
    //     re-enables everything the validator refuses — verified:
    //     `query_to_xml('select pg_sleep(3)', ...)` slept 3s while `pg_sleep`
    //     itself is denied. Same class as `dblink`, only built in.
    //   - `table_to_xml*` / `schema_to_xml*` / `database_to_xml*` /
    //     `cursor_to_xml*` dump a whole relation, schema or database WITHOUT
    //     naming a single column, so net A has nothing to match and net B sees
    //     an `Expression`.
    // ENUMERATED rather than matched by substring: it reuses the existing
    // mechanism (prefixes cannot express a shared SUFFIX), the family has been
    // closed since 8.3, and enumeration keeps `validator.allow_functions` as
    // the documented escape hatch for someone who really wants `table_to_xml`
    // on a connection with no PII.
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
];

/// Prefix-matched denied families — fail closed on members we did not
/// enumerate (every current and future member is dangerous, none is a
/// legitimate agent read, so making them non-config-tunable is deliberate):
/// - `dblink*` — outbound connections / remote SQL (extension).
/// - `pg_read_*` — pg_read_file, pg_read_binary_file: arbitrary server-file read.
/// - `pg_ls_*` — pg_ls_dir, pg_ls_logdir, pg_ls_waldir, ...: server-dir listing.
/// - `pg_stat_reset*` — every member throws away statistics for everyone on
///   the server, irreversibly, and not one of them is a read (W7, measured:
///   they all run inside `BEGIN READ ONLY`). Unlike the rest of `pg_stat_*`,
///   which is pure introspection, the reset half has no legitimate agent use.
const POSTGRES_DENIED_PREFIXES: &[&str] = &["dblink", "pg_read_", "pg_ls_", "pg_stat_reset"];

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
            value_sampling_catalogs: SQLITE_VALUE_SAMPLING_CATALOGS,
            pii: PiiRules::default(),
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
            value_sampling_catalogs: POSTGRES_VALUE_SAMPLING_CATALOGS,
            pii: PiiRules::default(),
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
            value_sampling_catalogs: MYSQL_VALUE_SAMPLING_CATALOGS,
            pii: PiiRules::default(),
        }
    }

    /// Attach the connection's PII policy (`[connections.X.pii] columns`).
    /// A builder step rather than a fourth constructor argument: a connection
    /// without the section keeps the default empty policy and every existing
    /// call site — and behavior — unchanged (UX-5).
    pub fn with_pii(mut self, pii: PiiRules) -> Policy {
        self.pii = pii;
        self
    }

    /// The connection's PII policy, for net B (`check_origins`) and for the
    /// database-error redaction the cli applies when it is non-empty.
    pub fn pii(&self) -> &PiiRules {
        &self.pii
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

thread_local! {
    /// Set only while THIS thread sits inside the `catch_unwind` below.
    static CATCHING_PANIC: Cell<bool> = const { Cell::new(false) };
    /// Where the caught panic fired. The hook is the only place that can see it
    /// — `catch_unwind` hands back the payload alone — and "please report it"
    /// with no file:line is a bug report nobody can act on.
    static PANIC_LOCATION: Cell<Option<String>> = const { Cell::new(None) };
}

/// Keep a panic we are about to catch off stderr, without ever losing anybody
/// else's. Installed once and chained to the previous hook, so panics outside
/// this boundary (tests, the rest of the cli) still print exactly as before;
/// the flag is per-thread because take_hook/set_hook around each call is
/// process-global — two threads validating at once can interleave and leave the
/// silent hook installed for good.
fn hush_caught_panics() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if CATCHING_PANIC.with(Cell::get) {
                PANIC_LOCATION.with(|at| at.set(info.location().map(ToString::to_string)));
            } else {
                previous(info);
            }
        }));
    });
}

/// Run one validation boundary with a panic turned into a value: `Err` carries
/// the panic's message.
///
/// A panic anywhere in a check is a BUG, and it is treated as one — but not by
/// letting it out: an unwind escaping a boundary would kill the process past
/// every seam that makes nyet trustworthy (no NYET envelope, no exit code, no
/// audit line for what the agent tried). Caught, it stays a refusal like any
/// other, so the guarantee "nothing nyet did not understand reaches the database
/// — and nothing it could not judge reaches the agent" survives nyet's own bugs.
/// Every layer-1 boundary of the crate goes through here (SQL, MongoDB, net B),
/// so the policy cannot be forgotten at one of them.
///
/// `AssertUnwindSafe` is the caller's obligation: each `f` below only READS
/// shared borrows and owns everything it builds, so an unwind can leave no
/// half-written state behind for a later call to observe.
pub(crate) fn catching_panics<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    hush_caught_panics();
    // Saved and restored rather than set/cleared: should a boundary ever end up
    // inside another, the inner one must not un-hush the outer's panic.
    let outer = CATCHING_PANIC.with(|c| c.replace(true));
    let caught = panic::catch_unwind(AssertUnwindSafe(f));
    CATCHING_PANIC.with(|c| c.set(outer));
    // `&*`, not `&`: a `&Box<dyn Any>` unsizes to a `dyn Any` holding the BOX,
    // and both downcasts would miss the message inside it.
    caught.map_err(|payload| match PANIC_LOCATION.with(Cell::take) {
        Some(at) => format!("{} at {at}", panic_detail(&*payload)),
        None => panic_detail(&*payload),
    })
}

/// The panic's own message: quoted back because it is the only thing that makes
/// the bug report useful, and it is no more revealing than the parser errors
/// already echoed back — it comes from nyet's own code working on the caller's
/// own query.
fn panic_detail(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_string())
}

/// The hint a caught panic carries at every boundary. "No result" is the one
/// promise all of them keep: net A refuses before anything runs, net B withholds
/// what already ran.
pub(crate) const INTERNAL_ERROR_HINT: &str =
    "this is a bug in nyet, not a problem with your query; no result was returned (fail \
     closed) — please report it with the statement that triggered it";

/// Classify one query under the engine's policy (which carries the dialect).
pub fn validate(sql: &str, policy: &Policy) -> Verdict {
    catching_panics(|| classify(sql, policy)).unwrap_or_else(|detail| internal_error_deny(&detail))
}

fn classify(sql: &str, policy: &Policy) -> Verdict {
    // The only way to exercise the boundary above without a real bug; compiled
    // out of the shipped binary.
    #[cfg(test)]
    if sql.contains("__nyet_test_panic__") {
        panic!("injected validator panic");
    }
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
    // Net A needs to know WHICH tables the statement touches before it can judge
    // an unqualified column name, so the PII pass runs a cheap pre-scan of the
    // table factors first (skipped entirely when the connection has no rules).
    let pii = PiiScope::of(&policy.pii, &stmt);
    // An alias COLUMN list renames a protected table's columns positionally
    // (`users AS u (a, b, c)`); nyet does not know the real column order, so
    // which alias hides the protected column is unprovable — refuse (finding 4).
    if pii.alias_columns {
        return pii_alias_columns_deny(policy.pii.mode);
    }
    // A table source nyet could not classify at all: it may well be the
    // protected table under a spelling the parser renders differently — every
    // bypass found so far was exactly that.
    if pii.unresolved {
        return pii_unresolved_source_deny(policy.pii.mode);
    }
    let (maskable, wildcard_conflict) = maskable_projection(&policy.pii, &pii, &stmt);
    // A wildcard beside a column the mask would redact: net A cannot say which
    // result column is which, so the promise it hands net B would be checked
    // against the wrong one (measured leak). Refused, with the way out.
    if wildcard_conflict {
        return pii_mask_wildcard_deny();
    }
    // Sorting/grouping/dedup on a column the mask would redact reads the value
    // back out of the row order or the row count, so it is refused before the
    // walk — and with its own message, because the fix is "remove the clause",
    // not "do not name the column" (Д10).
    if let Some(clause) = mask_ordering_conflict(&stmt, &maskable) {
        return pii_mask_ordering_deny(clause);
    }
    let mut checker = Checker {
        policy,
        pii,
        maskable,
        pii_exempt: Vec::new(),
    };
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
        pii_exempt: checker.pii_exempt,
    }
}

struct Checker<'a> {
    policy: &'a Policy,
    pii: PiiScope,
    /// Projection expressions `mode = "mask"` relaxes: node address -> the
    /// RESULT-column index it will produce (empty under `mode = "deny"`, and
    /// empty for every statement shape that is not the exact one described on
    /// `maskable_projection`).
    maskable: BTreeMap<usize, usize>,
    /// The result columns actually relaxed while walking THIS statement — the
    /// promise handed to net B.
    pii_exempt: Vec<usize>,
}

/// Which expression nodes `mode = "mask"` lets through — **by identity**, not by
/// name: the same `email` is masked in the projection and refused in the WHERE
/// of the same statement, so the rule cannot be a property of the name (and it
/// cannot be a property of the value either: `WHERE email = 'x'` holds an
/// `Expr::Identifier` structurally EQUAL to the projected one). The AST is
/// borrowed for the whole walk, so a node's address identifies it exactly.
///
/// Masking is a promise net B has to keep, so net A relaxes only the shape whose
/// result column the driver provably resolves to `table.column`:
///
/// - the **root** select's projection, never a nested one. A derived table, a
///   CTE or a UNION arm hands its columns to another layer, and what a driver
///   reports THROUGH that layer is precisely the documented view limitation —
///   `SELECT x FROM (SELECT email AS x FROM users) t` must not become a way to
///   launder the value past net B;
/// - a **bare, unaliased** column reference. `upper(email)` carries no
///   provenance at all (net B would see an `Expression` and pass it through
///   unmasked), and an ALIAS is a second name for the same value that SQLite
///   accepts in WHERE (`SELECT email AS e FROM users WHERE e LIKE 'a%'`) — an
///   oracle net A can no longer see, because `e` is not a protected name.
///
/// Sorting, grouping and dedup are handled separately, by
/// `mask_ordering_conflict` — they are a property of the STATEMENT, not of the
/// projection node, and they get their own refusal so the agent is told what to
/// remove (Д10). The exemption itself is a PROMISE: the index is recorded and
/// `check_origins` refuses the result if the column did not come back masked.
///
/// Everything else — wildcards in every spelling, whole-row composites,
/// `TABLE t`, USING/NATURAL, the statistics catalogs — keeps the `deny`-mode
/// refusal, in both modes.
fn maskable_projection(
    rules: &PiiRules,
    scope: &PiiScope,
    stmt: &Statement,
) -> (BTreeMap<usize, usize>, bool) {
    let mut out = BTreeMap::new();
    if rules.mode != PiiMode::Mask || rules.is_empty() {
        return (out, false);
    }
    let Statement::Query(query) = stmt else {
        return (out, false);
    };
    let SetExpr::Select(select) = &*query.body else {
        return (out, false);
    };
    // A WILDCARD expands into N result columns, so everything to its right sits
    // somewhere net A cannot compute.
    // (`SelectItem` has FIVE variants in sqlparser 0.62: the two wildcards, the
    // two scalar ones, and `ExprWithAliases` (`expr AS (a, b)`) — which is ALSO
    // a multi-column expansion, but is parsed only by dialects whose
    // `supports_select_item_multi_column_alias()` is true (Spark/Databricks/
    // Generic). None of the three nyet ships is one, so it cannot reach here
    // today; if a dialect is ever added, it belongs in the match below.) — and the promise net B checks by index
    // would then be kept by the WRONG column while the exempted one goes out
    // raw (measured: `SELECT v.*, d.protected FROM v, d` returned the value).
    // A qualified `t.*` is NOT refused by the wildcard rule when `t` provably
    // carries no rules, so this cannot be left to that check. Refusing here is
    // what makes "the n-th item is the n-th result column" TRUE, which is the
    // whole basis of the promise; `mask_conflict` turns it into a refusal that
    // says so.
    for (index, item) in select.projection.iter().enumerate() {
        if let SelectItem::UnnamedExpr(expr) = item {
            if scope.names_protected_column(expr) {
                out.insert(std::ptr::from_ref(expr).addr(), index);
            }
        }
    }
    let wildcard = select.projection.iter().any(|item| {
        matches!(
            item,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
        )
    });
    // The map is DROPPED when a wildcard is present: keeping it would hand net B
    // indexes that do not exist. The flag is what the caller turns into a
    // refusal that explains itself.
    match wildcard && !out.is_empty() {
        true => (BTreeMap::new(), true),
        false => (out, false),
    }
}

/// Does this statement SORT, GROUP or DEDUPE on a column the mask would redact?
/// Those read the real value back out through the row ORDER or the row COUNT
/// even when every cell is `[REDACTED]`, so the statement is refused — with its
/// own message, because "remove the ORDER BY" is a different instruction from
/// "do not name this column" (Д10).
///
/// The check is a DENYLIST, not an allowlist, and that is the whole point.
/// While anything is maskable, a sort/group key is accepted ONLY when it is a
/// plain column NAME (`Expr::Identifier` / `Expr::CompoundIdentifier`) — those
/// are judged by `check_pii_expr` like every other name, in both modes, so a
/// protected one is refused there. Everything else is refused here.
///
/// The allowlist version was wrong three review rounds running, and it was wrong
/// in PRINCIPLE: "which expressions is this planner willing to fold into an
/// ordinal" is a per-engine, per-VERSION question nyet cannot answer from the
/// AST. Measured across 47 spellings on three servers, the ordinal forms include
/// `1`, `+1`, `(1)`, `-(-1)`, `0x1` (PostgreSQL 16 added non-decimal literals),
/// `0_1` (digit separators), and `1 COLLATE NOCASE` — while `1+0`, `1.0`, `'1'`,
/// `abs(1)` and `CAST(1 AS INT)` are NOT ordinals on any of them. Each of the
/// misses sorted the result by the real value of a redacted column, or handed
/// over its exact distinct count. A denylist needs none of that knowledge: a key
/// that is not a name cannot be checked, so it is not allowed.
///
/// `DISTINCT` needs no key at all — it dedupes on the values themselves — so it
/// conflicts whenever anything is maskable.
///
/// Cost, deliberate and documented: under `mode = "mask"`, and only in a
/// statement that plainly projects a protected column, `ORDER BY`/`GROUP BY`
/// takes column names only — no positions and no expressions. `ORDER BY id`,
/// `ORDER BY u.created_at DESC` and `GROUP BY id` are unaffected, which is the
/// case this guard was narrowed for in the first place.
fn mask_ordering_conflict(
    stmt: &Statement,
    maskable: &BTreeMap<usize, usize>,
) -> Option<&'static str> {
    if maskable.is_empty() {
        return None;
    }
    let Statement::Query(query) = stmt else {
        return None;
    };
    let is_name = |expr: &Expr| matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_));
    if let Some(order_by) = &query.order_by {
        match &order_by.kind {
            // `ORDER BY ALL` sorts by every column, the masked one included.
            // (No dialect nyet ships parses it — fail closed anyway.)
            OrderByKind::All(_) => return Some("ORDER BY ALL"),
            OrderByKind::Expressions(exprs) => {
                if !exprs.iter().all(|e| is_name(&e.expr)) {
                    return Some("ORDER BY <a position or an expression>");
                }
            }
        }
    }
    if let SetExpr::Select(select) = &*query.body {
        if select.distinct.is_some() {
            return Some("DISTINCT");
        }
        match &select.group_by {
            GroupByExpr::All(_) => return Some("GROUP BY ALL"),
            // A modifier (WITH ROLLUP / CUBE) adds grouping sets over the same
            // keys; refused with them for the same reason (fail closed).
            GroupByExpr::Expressions(exprs, modifiers) => {
                if !exprs.iter().all(is_name) || !modifiers.is_empty() {
                    return Some("GROUP BY <a position or an expression>");
                }
            }
        }
    }
    None
}

/// What the PII policy means for THIS statement (net A), computed from a
/// pre-scan of every table factor in scope.
///
/// Scopes are deliberately NOT tracked per sub-select for COLUMN names: every
/// protected table anywhere in the statement contributes to one flat set, so an
/// unqualified `email` is refused wherever it appears. Without the database's
/// schema nyet cannot prove which relation an unqualified name belongs to, and a
/// `WHERE email LIKE 'a%'` oracle leaks the value one character at a time —
/// over-denial is the only safe direction (UX-1). Wildcards are the exception:
/// `*` expands exactly ONE source, so it is judged against a scope built from
/// that select's own FROM (finding 9).
#[derive(Default)]
struct PiiScope {
    /// Lowercased protected column names of the protected tables in scope.
    columns: BTreeSet<String>,
    /// Lowercased names that stand for a protected relation here: the table
    /// names AND their aliases (`FROM users u` -> "users", "u").
    handles: BTreeSet<String>,
    /// Every relation name/alias in scope, protected or not — lets a qualified
    /// wildcard prefix be told apart from an unresolvable one (fail closed).
    relations: BTreeSet<String>,
    /// A protected relation carried an alias COLUMN list (`users AS u (a,b,c)`),
    /// which renames its columns positionally. nyet does not know the table's
    /// real column order, so the rename is unprovable -> refuse (finding 4).
    alias_columns: bool,
    /// nyet could not classify a table factor. Deliberately distinct from "no
    /// protected relation in scope": that is the same empty scope, and it means
    /// the opposite.
    unresolved: bool,
}

impl PiiScope {
    /// The scope of a whole statement.
    fn of(rules: &PiiRules, stmt: &Statement) -> PiiScope {
        PiiScope::build(rules, |scan| {
            // TableScan never breaks, so the ControlFlow is Continue by construction.
            let _ = stmt.visit(scan);
        })
    }

    /// The scope of ONE select's FROM — what a wilddcard in that select actually
    /// expands. Deliberately NOT a visitor walk: recursing would drag in the
    /// bodies of derived tables and the subqueries inside ON conditions, whose
    /// columns this wildcard cannot reach (those are judged by their own
    /// `pre_visit_select` and by the flat column scope).
    fn of_from(rules: &PiiRules, from: &[TableWithJoins]) -> PiiScope {
        PiiScope::build(rules, |scan| scan.push_sources(from))
    }

    fn build(rules: &PiiRules, walk: impl FnOnce(&mut TableScan)) -> PiiScope {
        let mut scope = PiiScope::default();
        if rules.is_empty() {
            return scope;
        }
        let mut scan = TableScan::default();
        walk(&mut scan);
        scope.unresolved = scan.unresolved;
        // An opaque source's alias resolves a qualifier without ever making it
        // protected: `s.email` over `(SELECT ...) s` provably is not the
        // protected table's column, because a derived table's columns can only
        // come from its own body — which net A judges on its own.
        scope.relations.extend(scan.opaque_aliases);
        for relation in scan.relations {
            scope.relations.insert(relation.table.clone());
            scope.relations.extend(relation.alias.iter().cloned());
            if !rules.protects_table(&relation.table) {
                continue;
            }
            scope.columns.extend(
                rules
                    .pairs
                    .iter()
                    .filter(|(t, _)| *t == relation.table)
                    .map(|(_, c)| c.clone()),
            );
            // The alias becomes a handle only once the PHYSICAL table is known
            // to be protected: `FROM orders AS users` is orders, whatever it is
            // called here.
            scope.handles.insert(relation.table);
            scope.handles.extend(relation.alias);
            scope.alias_columns |= relation.alias_columns;
        }
        scope
    }

    /// True when at least one protected relation is in scope — or when a source
    /// could not be classified at all, which is NOT the same thing and must not
    /// read as "nothing to protect here".
    fn active(&self) -> bool {
        !self.handles.is_empty() || self.unresolved
    }

    /// Can `prefix` (of `prefix.*` or `prefix.col`) be shown to name a
    /// NON-protected source? Unknown prefixes fail closed while a protected
    /// relation is in scope.
    fn prefix_is_safe(&self, prefix: &str) -> bool {
        !self.handles.contains(prefix) && self.relations.contains(prefix)
    }

    /// Is this expression a plain reference to a column this scope protects —
    /// i.e. exactly the case `check_pii_expr` refuses on the `columns` branch?
    /// Shared so `maskable_projection` marks the nodes that WILL be exempted and
    /// nothing else: a candidate list wider than the deny rule made
    /// `ORDER BY 1` over an unprotected first column read as an oracle.
    fn names_protected_column(&self, expr: &Expr) -> bool {
        let name = match expr {
            Expr::Identifier(ident) => &ident.value,
            Expr::CompoundIdentifier(parts) => {
                let qualifier = parts.len().checked_sub(2).and_then(|i| parts.get(i));
                if qualifier.is_some_and(|q| self.prefix_is_safe(&q.value.to_lowercase())) {
                    return false;
                }
                match parts.last() {
                    Some(part) => &part.value,
                    None => return false,
                }
            }
            _ => return false,
        };
        self.columns.contains(&name.to_lowercase())
    }
}

/// One relation in a FROM clause: its PHYSICAL name (the terminal component of
/// the parsed table name), the alias it also answers to here, and whether that
/// alias renamed its columns.
struct ScannedRelation {
    table: String,
    alias: Option<String>,
    alias_columns: bool,
}

/// Pre-pass: every plain table in scope. A `TableFactor::Table` carrying `args`
/// is a function call, not a table, and is left to the function denylist.
#[derive(Default)]
struct TableScan {
    relations: Vec<ScannedRelation>,
    /// Aliases of sources that are not named relations (derived tables, table
    /// functions, ...). They make a qualifier resolvable, never protected.
    opaque_aliases: Vec<String>,
    /// A factor nyet could not classify at all. Kept apart from "no protected
    /// relation here": the two states used to be the same empty scope, and the
    /// second one switches net A off.
    unresolved: bool,
}

impl TableScan {
    /// Classify ONE table factor. **Exhaustive on purpose** (no `_` arm): a
    /// factor nyet silently ignored used to leave `PiiScope` empty, and an
    /// empty scope means "no protected relation here", which switched net A off
    /// wholesale — columns, wildcards, USING/NATURAL, whole-row and the catalog
    /// denylist at once. Every bypass found across three review rounds
    /// (`FROM ONLY t`, `FROM ONLY (t)`, `SetExpr::Table`, a parenthesised join)
    /// was an instance of that one default. Without an `_` arm, a new
    /// `TableFactor` in a future sqlparser breaks the BUILD instead of quietly
    /// opening the hole again.
    ///
    /// Three outcomes, and nothing else:
    /// - a NAMED relation -> `ScannedRelation` (its columns can be judged);
    /// - a WRAPPER around another factor -> recurse (the inner one decides);
    /// - an OPAQUE row source (derived table, table function, UNNEST, JSON/XML
    ///   table) -> only its alias is remembered, as a resolvable prefix, never
    ///   as a protected handle. Their columns come from their own body or
    ///   arguments, which the rest of net A judges; what a *server-side* opaque
    ///   source returns is the documented view limitation (README).
    fn push_factor(&mut self, table_factor: &TableFactor) {
        match table_factor {
            TableFactor::Table {
                name, alias, args, ..
            } => match relation_name(name, args.as_ref(), alias.as_ref()) {
                Some(table) => self.relations.push(ScannedRelation {
                    alias: alias.as_ref().map(|a| a.name.value.to_lowercase()),
                    table,
                    alias_columns: alias.as_ref().is_some_and(|a| !a.columns.is_empty()),
                }),
                // A real table function: opaque, like a derived table.
                None if args.is_some() => self.push_opaque(alias.as_ref()),
                // A plain table whose NAME could not be read. That is the one
                // "cannot classify" left, and it fails closed.
                None => self.unresolved = true,
            },
            // Wrappers: the relation is one level in. `push_sources` recurses
            // for the local (wildcard) scope; the visitor reaches them too, so
            // the global scope sees them either way.
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => {
                self.push_opaque(alias.as_ref());
                self.push_sources(std::slice::from_ref(&**table_with_joins));
            }
            TableFactor::Pivot { table, alias, .. }
            | TableFactor::Unpivot { table, alias, .. }
            | TableFactor::MatchRecognize { table, alias, .. } => {
                self.push_opaque(alias.as_ref());
                self.push_factor(table);
            }
            // Opaque row sources. Their alias is a resolvable prefix (so
            // `s.email` over a derived table is provably not the protected
            // table's column) but never a handle.
            TableFactor::Derived { alias, .. }
            | TableFactor::TableFunction { alias, .. }
            | TableFactor::Function { alias, .. }
            | TableFactor::UNNEST { alias, .. }
            | TableFactor::JsonTable { alias, .. }
            | TableFactor::OpenJsonTable { alias, .. }
            | TableFactor::XmlTable { alias, .. }
            | TableFactor::SemanticView { alias, .. } => self.push_opaque(alias.as_ref()),
        }
    }

    /// A source with no name nyet can reason about: remember the alias only.
    fn push_opaque(&mut self, alias: Option<&TableAlias>) {
        if let Some(alias) = alias {
            self.opaque_aliases.push(alias.name.value.to_lowercase());
        }
    }

    /// The sources of a FROM clause and nothing below them: the joined
    /// relations plus, recursively, the ones inside wrapping factors.
    fn push_sources(&mut self, from: &[TableWithJoins]) {
        for item in from {
            for factor in
                std::iter::once(&item.relation).chain(item.joins.iter().map(|j| &j.relation))
            {
                self.push_factor(factor);
            }
        }
    }
}

/// The physical relation a `TableFactor::Table` names, lowercased and bare.
/// `None` = this is a table FUNCTION, not a named relation.
///
/// PostgreSQL's `FROM ONLY tbl` (do not descend into inheritance children) has
/// no representation in sqlparser, and it arrives in two disguises, both of
/// which the server nonetheless runs as a plain read of `tbl`:
/// `ONLY tbl` becomes a table called `ONLY` aliased `tbl`, and `ONLY (tbl)`
/// becomes a *table function* called `ONLY` with `tbl` as its argument. Undo
/// both here, in the one place every caller (the scan and the catalog denylist)
/// resolves a name.
fn relation_name(
    name: &ObjectName,
    args: Option<&TableFunctionArgs>,
    alias: Option<&TableAlias>,
) -> Option<String> {
    let bare = terminal_ident(name)?.value.to_lowercase();
    match args {
        // `ONLY tbl`: the real relation landed in the ALIAS slot.
        None if bare == "only" => Some(alias.map_or(bare, |a| a.name.value.to_lowercase())),
        None => Some(bare),
        Some(args) if bare == "only" => match args.args.as_slice() {
            [FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))] => match expr {
                Expr::Identifier(ident) => Some(ident.value.to_lowercase()),
                Expr::CompoundIdentifier(parts) => Some(parts.last()?.value.to_lowercase()),
                _ => None,
            },
            _ => None,
        },
        Some(_) => None,
    }
}

impl Visitor for TableScan {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<()> {
        self.push_factor(table_factor);
        ControlFlow::Continue(())
    }

    /// `TABLE t` (a whole-relation read) keeps its name as a plain `String`
    /// inside `SetExpr`, not as a `TableFactor` — invisible to the hook above
    /// and to every other visitor hook.
    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        for name in set_expr_tables(&query.body) {
            self.relations.push(ScannedRelation {
                table: name,
                alias: None,
                alias_columns: false,
            });
        }
        ControlFlow::Continue(())
    }
}

/// Every `TABLE <name>` reachable from a query body without going through a
/// nested `Query` (those get their own `pre_visit_query`). Returns the terminal
/// component, lowercased.
fn set_expr_tables(body: &SetExpr) -> Vec<String> {
    fn walk(body: &SetExpr, out: &mut Vec<String>) {
        match body {
            SetExpr::Table(table) => {
                if let Some(name) = &table.table_name {
                    out.push(bare_name(name).to_lowercase());
                }
            }
            SetExpr::SetOperation { left, right, .. } => {
                walk(left, out);
                walk(right, out);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(body, &mut out);
    out
}

/// The join's column constraint, when it has one. The arms without a constraint
/// (CROSS/OUTER APPLY, ClickHouse ARRAY JOIN) carry no column names at all.
fn join_constraint(op: &JoinOperator) -> Option<&JoinConstraint> {
    match op {
        JoinOperator::Join(c)
        | JoinOperator::Inner(c)
        | JoinOperator::Left(c)
        | JoinOperator::LeftOuter(c)
        | JoinOperator::Right(c)
        | JoinOperator::RightOuter(c)
        | JoinOperator::FullOuter(c)
        | JoinOperator::CrossJoin(c)
        | JoinOperator::Semi(c)
        | JoinOperator::LeftSemi(c)
        | JoinOperator::RightSemi(c)
        | JoinOperator::Anti(c)
        | JoinOperator::LeftAnti(c)
        | JoinOperator::RightAnti(c)
        | JoinOperator::StraightJoin(c)
        | JoinOperator::AsOf { constraint: c, .. } => Some(c),
        _ => None,
    }
}

/// The terminal component of a (maybe qualified) object name — the thing the
/// name actually refers to (`pg_catalog.pg_stats` -> `pg_stats`).
fn terminal_ident(name: &ObjectName) -> Option<&Ident> {
    name.0.last().and_then(|p| p.as_ident())
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
        // `TABLE t` reads the WHOLE relation and hides its name in a plain
        // String inside SetExpr, where no other hook reaches it. Judged here
        // like the wildcard it is (`TABLE users` == `SELECT * FROM users`), and
        // the statistics catalogs are closed on the same path.
        if !self.policy.pii.is_empty() {
            for name in set_expr_tables(&query.body) {
                if self.policy.value_sampling_catalogs.contains(&name.as_str()) {
                    return break_deny(pii_catalog_deny(&name, self.policy.pii.mode));
                }
                if self.policy.pii.protects_table(&name) {
                    return break_deny(pii_wildcard_deny(self.policy.pii.mode));
                }
            }
        }
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
        if !self.policy.pii.is_empty() {
            // A wildcard expands exactly ONE source, so it is judged against
            // THIS select's own FROM — not the whole statement. Refusing
            // `SELECT * FROM orders WHERE uid IN (SELECT id FROM users)` would
            // be a false alarm: no protected column can come back (finding 9).
            let local = PiiScope::of_from(&self.policy.pii, &select.from);
            for item in &select.projection {
                let refused = match item {
                    SelectItem::Wildcard(_) => local.active(),
                    // A QUALIFIED wildcard names its own source, so it is
                    // judged against the WHOLE statement, not this select's
                    // FROM. A correlated sub-select has an empty FROM, which
                    // made the local scope read as "nothing to protect" while
                    // `LATERAL (SELECT u.*)` copied every protected column of
                    // the OUTER `users u` into a derived table — a working
                    // count oracle that cleared both nets.
                    SelectItem::QualifiedWildcard(kind, _) => match kind {
                        SelectItemQualifiedWildcardKind::ObjectName(name) => {
                            !self.qualified_wildcard_is_safe(name, &self.pii)
                        }
                        // `expr.*` over something that is not a plain name:
                        // nyet cannot resolve the source at all. (Unreachable
                        // today — only BigQuery/Snowflake parse it — kept as a
                        // fail-closed default.)
                        SelectItemQualifiedWildcardKind::Expr(_) => self.pii.active(),
                    },
                    _ => false,
                };
                if refused {
                    return break_deny(pii_wildcard_deny(self.policy.pii.mode));
                }
            }
            self.check_joins(&select.from, &local)?;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        // Net A, applied to EVERY expression in the tree — projection, WHERE,
        // JOIN ON, GROUP BY, HAVING, ORDER BY, subqueries and CTE bodies alike.
        // A protected column is refused wherever it is mentioned, not only where
        // it is returned: `WHERE email LIKE 'a%'` plus the row count is a
        // character-by-character oracle over the very value being protected.
        if self.pii.active() {
            if let Some(verdict) = self.check_pii_expr(expr) {
                return break_deny(verdict);
            }
        }
        if let Expr::Function(f) = expr {
            // `f(t.*)` expands the whole row inside a call (PostgreSQL
            // `json_agg(u.*)`), and it is a FunctionArgExpr — neither a
            // SelectItem nor an Expr, so neither wildcard check above sees it
            // (finding 5). A bare `*` argument is NOT this: `count(*)` counts
            // rows without reading a column, and must keep working.
            if let FunctionArguments::List(list) = &f.args {
                self.check_function_args(&list.args)?;
            }
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
        // Catalogs that publish sampled DATA VALUES are closed on any connection
        // with a PII policy, whatever the query asks of them: they hand out the
        // protected cells without ever naming the protected column.
        if !self.policy.pii.is_empty() {
            if let TableFactor::Table {
                name, args, alias, ..
            } = table_factor
            {
                // Resolved the same way the scan resolves it, so `ONLY (pg_stats)`
                // cannot slip past a check that only knew the plain spelling.
                if let Some(table) = relation_name(name, args.as_ref(), alias.as_ref()) {
                    if self
                        .policy
                        .value_sampling_catalogs
                        .contains(&table.as_str())
                    {
                        return break_deny(pii_catalog_deny(&table, self.policy.pii.mode));
                    }
                }
            }
        }
        match table_factor {
            // A parenthesised join keeps its own joins one level down and
            // produces no Select of its own — so the constraint check has to
            // happen HERE, where the visitor hands us the nested node. Between
            // this arm and pre_visit_select every TableWithJoins in the
            // statement is checked exactly once.
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                if !self.policy.pii.is_empty() {
                    let from = std::slice::from_ref(&**table_with_joins);
                    let local = PiiScope::of_from(&self.policy.pii, from);
                    self.check_joins(from, &local)?;
                }
                ControlFlow::Continue(())
            }
            // A function in TABLE-SOURCE position carries its arguments here,
            // not in an Expr::Function node — the other side of the AST for the
            // same `f(t.*)` row expansion.
            TableFactor::Table {
                name,
                args: Some(args),
                ..
            } => {
                self.check_function_args(&args.args)?;
                self.check_function_name(name)
            }
            TableFactor::Function { name, args, .. } => {
                self.check_function_args(args)?;
                self.check_function_name(name)
            }
            _ => ControlFlow::Continue(()),
        }
    }
}

impl Checker<'_> {
    /// Net A's per-expression rule. Only identifier-shaped expressions can name
    /// a column; everything else (function calls, casts, operators) is reached
    /// through its own sub-expressions, which the visitor also passes here — so
    /// `substr(email, 1, 3)`, `CAST(email AS TEXT)` and `email || 'x'` are all
    /// caught by the inner `email`.
    ///
    /// The column name is matched against the protected columns of the tables
    /// THIS statement touches, qualifier or not: without the database's schema
    /// nyet cannot prove that an unqualified `email` belongs to `orders` rather
    /// than to the `users` in the same FROM, so it refuses (fail closed).
    /// A `prefix.*` is safe only when `prefix` provably names a relation that
    /// carries no rules. An unknown prefix inside a scope that holds a protected
    /// relation fails closed.
    fn qualified_wildcard_is_safe(&self, name: &ObjectName, scope: &PiiScope) -> bool {
        if !scope.active() {
            return true;
        }
        terminal_ident(name).is_some_and(|ident| scope.prefix_is_safe(&ident.value.to_lowercase()))
    }

    /// `USING (col)` and `NATURAL` name join columns OUTSIDE the `Expr` tree —
    /// `JoinConstraint::Using` holds `ObjectName`s and `Natural` holds nothing
    /// at all — so `pre_visit_expr` never sees them. Both are a working equality
    /// oracle over the protected value (the agent brings its own dictionary).
    /// `from` is ONE level of joins; the callers between them cover every level.
    fn check_joins(&self, from: &[TableWithJoins], local: &PiiScope) -> ControlFlow<Box<Verdict>> {
        for item in from {
            for join in &item.joins {
                match join_constraint(&join.join_operator) {
                    Some(JoinConstraint::Using(names)) => {
                        for name in names {
                            if let Some(ident) = terminal_ident(name) {
                                let lower = ident.value.to_lowercase();
                                if self.pii.columns.contains(&lower) {
                                    return break_deny(pii_column_deny(
                                        &lower,
                                        self.policy.pii.mode,
                                    ));
                                }
                            }
                        }
                    }
                    // NATURAL joins on every same-named column pair, which nyet
                    // cannot enumerate without the schema.
                    Some(JoinConstraint::Natural) if local.active() => {
                        return break_deny(pii_natural_join_deny(self.policy.pii.mode))
                    }
                    _ => {}
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Function ARGUMENTS, wherever the function sits: an expression
    /// (`SELECT json_agg(u.*)`) or a table source (`FROM f(u.*)`,
    /// `FROM LATERAL f(u.*)`). `FunctionArgExpr` is neither a `SelectItem` nor
    /// an `Expr`, so neither wildcard check reaches it. A bare `*` argument is
    /// NOT this: `count(*)` counts rows without reading a column.
    fn check_function_args(&self, args: &[FunctionArg]) -> ControlFlow<Box<Verdict>> {
        if !self.pii.active() {
            return ControlFlow::Continue(());
        }
        for arg in args {
            let arg_expr = match arg {
                FunctionArg::Unnamed(e) => e,
                FunctionArg::Named { arg, .. } | FunctionArg::ExprNamed { arg, .. } => arg,
            };
            if let FunctionArgExpr::QualifiedWildcard(name) = arg_expr {
                if !self.qualified_wildcard_is_safe(name, &self.pii) {
                    return break_deny(pii_wildcard_deny(self.policy.pii.mode));
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn check_pii_expr(&mut self, expr: &Expr) -> Option<Verdict> {
        let name = match expr {
            // `SELECT *` inside an expression position (rare, but it exists);
            // `count(*)` is a FunctionArgExpr, not an Expr, so it never lands here.
            Expr::Wildcard(_) | Expr::QualifiedWildcard(..) => {
                return Some(pii_wildcard_deny(self.policy.pii.mode))
            }
            Expr::Identifier(ident) => &ident.value,
            Expr::CompoundIdentifier(parts) => {
                // A qualifier that provably names an unruled source settles
                // ownership — the same proof `prefix.*` already relies on.
                // Without it the strict rule forbade `o.email` while allowing
                // `o.*`, which returns that very column.
                let qualifier = parts.len().checked_sub(2).and_then(|i| parts.get(i));
                if qualifier.is_some_and(|q| self.pii.prefix_is_safe(&q.value.to_lowercase())) {
                    return None;
                }
                &parts.last()?.value
            }
            _ => return None,
        };
        let lower = name.to_lowercase();
        if self.pii.columns.contains(&lower) {
            // mode = "mask": a plain projection of the column is allowed here
            // and REDACTED by net B, which is the only layer that can prove the
            // result column is the protected one (see `maskable_projection`).
            // The index is REMEMBERED: net B must refuse the result if it did
            // not in fact mask this column (an exemption is a promise).
            if let Some(index) = self.maskable.get(&std::ptr::from_ref(expr).addr()) {
                self.pii_exempt.push(*index);
                return None;
            }
            return Some(pii_column_deny(&lower, self.policy.pii.mode));
        }
        // A bare table name or alias used as a VALUE is a whole-row composite
        // (`SELECT u FROM users u` in PostgreSQL) — every column at once.
        if self.pii.handles.contains(&lower) {
            return Some(pii_whole_row_deny(&lower, self.policy.pii.mode));
        }
        None
    }

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
                    "'{lower}' does more than read — the denylist covers calls that \
                     take locks, reach the filesystem or the server, write durably, or \
                     run code nyet never sees. If the query works without it, drop the \
                     call; otherwise add it to validator.allow_functions for this \
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

/// The one hint every PII refusal carries (Д10: what to do instead). It must
/// also close the door on the obvious next move — there is no flag, and asking
/// nyet again in another shape will not help; the policy belongs to whoever owns
/// the config file, exactly like the guardrail's ceiling.
fn pii_hint(mode: PiiMode) -> String {
    // The two modes need DIFFERENT instructions, and mixing them is a real
    // defect: under `deny`, "name the columns you need" IS what was refused, so
    // the deny text must keep saying that the protected column is off limits in
    // every clause INCLUDING SELECT (it said so before mask mode existed).
    let sanction = match mode {
        PiiMode::Deny => {
            "nyet refuses the whole query rather than returning or filtering on them, and \
             there is no CLI flag to override it — the policy belongs to whoever owns the \
             config file. Select the OTHER columns of that table instead: a protected \
             column is off limits in every clause, SELECT included (SELECT, WHERE, JOIN \
             ON, JOIN USING, GROUP BY, HAVING, ORDER BY, DISTINCT, subqueries and `*` all \
             count — filtering on a protected column leaks it one character at a time)"
        }
        // Under mask the agent CAN get the row back — it just has to ask for the
        // column plainly, which is the one shape nyet can prove and redact.
        PiiMode::Mask => {
            "this connection masks them (mode = \"mask\"), and there is no CLI flag to \
             override that — the policy belongs to whoever owns the config file. A \
             protected column may be SELECTed PLAINLY, on its own: `SELECT id, email FROM \
             users` returns [REDACTED] in every row of `email`, with a PII_MASKED warning. \
             Any other use is refused — an alias (`AS e`), an expression around it \
             (`substr(email,1,3)`), `*`/`t.*`, WHERE, JOIN ON, JOIN USING, GROUP BY, \
             HAVING, ORDER BY, DISTINCT, and projecting it inside a subquery or CTE — \
             because comparing, sorting or grouping by the real value reads it back out \
             of the row count or the row order"
        }
    };
    format!(
        "this connection's config marks some columns as personal data in \
         [connections.<alias>.pii]; {sanction}. Use `nyet schema <alias>` to see which \
         columns exist (protected ones are marked), and ask the config owner if you \
         genuinely need the protected data."
    )
}

/// `mode = "mask"`, and the SELECT list mixes a wildcard with a column the mask
/// would redact. Its own refusal (Д10): the fix is "list the columns", which is
/// not what any other PII message says.
/// A result column that turns out to come from a protected column through a
/// layer the policy does not name (a view, a renaming select). No rewrite of the
/// QUERY helps — the fix is in the config, so say that instead of repeating the
/// generic advice (Д10).
fn pii_layer_hint() -> String {
    "the column reached the result through a layer this connection's PII policy does not \
     name — a view or another renaming layer over a protected table — and nyet refuses \
     what it cannot check against a rule rather than guessing. Rewriting the query \
     will not change that, and there is no CLI flag: the config owner has to list that \
     layer's own columns as well (`columns = [\"users.email\", \"v_users.contact\"]`), or \
     hide the column from the database role. Read the other columns of that view in the \
     meantime, and see `nyet schema <alias>` for what exists."
        .to_string()
}

fn pii_mask_wildcard_deny() -> Verdict {
    deny(
        DenyReason::PiiColumn,
        "the SELECT list mixes a wildcard ('*' or 'alias.*') with a column this connection's \
         PII policy masks — a wildcard expands into as many columns as the source has, so \
         nyet cannot tell which column of the RESULT is the protected one, and it will not \
         guess"
            .to_string(),
        "list the columns you need explicitly instead of the wildcard — the protected ones \
         then come back as [REDACTED] with a PII_MASKED warning (`SELECT id, name, email \
         FROM users`). `nyet schema <alias>` shows the column list, protected columns \
         marked.",
    )
}

/// `mode = "mask"`, and the statement SORTS, GROUPS or DEDUPES on a column the
/// mask would redact. Its own refusal on purpose (Д10): the agent removed
/// nothing useful by dropping the column — what it has to drop is the clause,
/// and the ordinary "do not name this column" message would send it in circles.
fn pii_mask_ordering_deny(clause: &str) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        format!(
            "this query uses {clause} while projecting a column this connection's PII policy \
             masks — the values would come back as [REDACTED], but the row ORDER and the row \
             COUNT would still be the real ones, which reads the hidden value back out"
        ),
        "while a masked column is in the SELECT list, ORDER BY and GROUP BY take plain column \
         NAMES only — no positions (`ORDER BY 1`) and no expressions, because nyet cannot \
         tell which of those the server folds into a reference to the hidden column. \
         `SELECT id, email FROM users ORDER BY id` works and returns `email` as [REDACTED]; \
         DISTINCT over a masked column is refused outright. Sort the rows yourself if you \
         need another order — and there is no CLI flag to override this.",
    )
}

fn pii_column_deny(column: &str, mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        format!(
            "the query references '{column}', which this connection's PII policy protects \
             on one of the tables it reads"
        ),
        &pii_hint(mode),
    )
}

fn pii_wildcard_deny(mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        "the query projects a whole row ('*', 'alias.*' or 'f(alias.*)') from a source that \
         either has columns this connection's PII policy protects, or that nyet cannot \
         resolve to a source without them — so it could return the protected columns"
            .to_string(),
        &pii_hint(mode),
    )
}

fn pii_whole_row_deny(handle: &str, mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        format!(
            "'{handle}' is used as a whole-row value, which expands to every column of a \
             table this connection's PII policy protects"
        ),
        &pii_hint(mode),
    )
}

fn pii_natural_join_deny(mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        "a NATURAL JOIN silently joins on every column the two relations share, and one of \
         them has columns this connection's PII policy protects — whether a protected column \
         is part of the join condition cannot be told without the schema"
            .to_string(),
        &pii_hint(mode),
    )
}

fn pii_alias_columns_deny(mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        "the query renames the columns of a table this connection's PII policy protects with \
         an alias column list (`table AS t (a, b, c)`), which maps names by POSITION — nyet \
         cannot tell which alias now stands for the protected column"
            .to_string(),
        &pii_hint(mode),
    )
}

fn pii_unresolved_source_deny(mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiUnprovable,
        "nyet could not work out what one of the query's table sources is, and this \
         connection protects some columns as PII — an unidentified source may well be the \
         protected table under a spelling nyet reads differently"
            .to_string(),
        &pii_hint(mode),
    )
}

fn pii_catalog_deny(catalog: &str, mode: PiiMode) -> Verdict {
    deny(
        DenyReason::PiiColumn,
        format!(
            "'{catalog}' publishes sampled column VALUES (most common values, histogram \
             bounds), so reading it would expose the data this connection's PII policy \
             protects — without naming a protected column"
        ),
        &pii_hint(mode),
    )
}

/// The refusal a panic caught in net A becomes.
fn internal_error_deny(detail: &str) -> Verdict {
    deny(
        DenyReason::InternalError,
        format!("internal error while classifying the query: {detail}"),
        INTERNAL_ERROR_HINT,
    )
}

/// The same, for net B — where the query already ran, so the refusal is about
/// the RESULT being withheld rather than the statement being rejected.
fn internal_error_refusal(detail: &str) -> Refusal {
    Refusal {
        reason: DenyReason::InternalError,
        message: format!("nyet: internal error while checking the result's columns: {detail}"),
        hint: INTERNAL_ERROR_HINT.to_string(),
    }
}

fn deny(reason: DenyReason, message: String, hint: &str) -> Verdict {
    Verdict::Deny {
        reason,
        message: format!("nyet: {message}"),
        hint: hint.to_string(),
    }
}

/// Property-based companion to the golden corpus: a generator that composes
/// write nodes into read scaffolding and asserts the one guarantee (see the
/// module's own doc comment).
#[cfg(test)]
mod property;

/// Differential companion to both: the same corpus and the same generator, but
/// the verdict comes from a live server held read-only (see the module doc).
/// Needs Docker for two of its three dialects — excluded from `just test-fast`.
#[cfg(test)]
mod differential;

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

    /// A panic in the validator is a bug, and the bug is worth fixing — but at
    /// this boundary it must first become an ordinary refusal: an escaping
    /// unwind would take the process down instead of producing the NYET the
    /// audit trail and the exit code are built on.
    #[test]
    fn a_panic_inside_the_validator_becomes_an_ordinary_refusal() {
        let Verdict::Deny {
            reason,
            message,
            hint,
        } = validate_default("SELECT '__nyet_test_panic__'")
        else {
            panic!("a panic must never pass as an allow");
        };
        assert_eq!(reason.as_str(), "INTERNAL_ERROR");
        assert!(message.contains("injected validator panic"), "{message}");
        // Without the file:line there is nothing to report.
        assert!(message.contains("validator.rs:"), "{message}");
        assert!(hint.contains("bug in nyet"), "{hint}");
        // The silencing must not outlive the call it was meant for.
        assert!(!CATCHING_PANIC.with(Cell::get));
        assert!(matches!(
            validate_default("SELECT 1"),
            Verdict::Allow { .. }
        ));
    }

    /// The same policy on the other side of execution: net B judges rows that
    /// already exist, so a panic here must withhold them through the ordinary
    /// refusal — never abort with the result half-written to stdout.
    #[test]
    fn a_panic_inside_net_b_becomes_an_ordinary_refusal() {
        let rules = PiiRules::parse(&["users.email".to_string()], PiiMode::Deny).unwrap();
        let cols = vec!["__nyet_test_panic__".to_string()];
        match check_origins(&rules, &cols, &[Origin::Expression], &[]) {
            Err(Refusal {
                reason,
                message,
                hint,
            }) => {
                assert_eq!(reason.as_str(), "INTERNAL_ERROR");
                assert!(message.contains("injected net B panic"), "{message}");
                assert!(hint.contains("bug in nyet"), "{hint}");
            }
            Ok(_) => panic!("a panic must never pass as a clean result"),
        }
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
        /// Comma-separated `[connections.X.pii] columns` rules for this case. A
        /// `pii:` line BEFORE the first `- query:` sets the file-wide default
        /// (a whole file of PII cases shares one policy); a per-case `pii:`
        /// overrides it, and `pii: none` turns the policy off for that one case
        /// (so a file can pin both sides of the same query). Absent everywhere =
        /// no PII policy, as before.
        pii: String,
        /// `[connections.X.pii] mode` for this case — `deny` (default) or
        /// `mask`. Same two levels as `pii:`: a file-wide line before the first
        /// case, overridable per case, so the mask twins of a deny case can sit
        /// next to it.
        pii_mode: String,
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
        let mut default_pii = String::new();
        let mut default_pii_mode = String::new();
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
                    pii: default_pii.clone(),
                    pii_mode: default_pii_mode.clone(),
                });
                continue;
            }
            if cases.is_empty() {
                if let Some(m) = line.strip_prefix("pii_mode: ") {
                    default_pii_mode = m.to_string();
                    continue;
                }
                let p = line
                    .strip_prefix("pii: ")
                    .unwrap_or_else(|| panic!("{name}:{}: key before first '- query:'", idx + 1));
                default_pii = p.to_string();
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
            } else if let Some(p) = line.strip_prefix("pii: ") {
                case.pii = p.to_string();
            } else if let Some(m) = line.strip_prefix("pii_mode: ") {
                case.pii_mode = m.to_string();
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
                let rules: Vec<String> = case
                    .pii
                    .split(',')
                    .map(str::trim)
                    .filter(|r| !r.is_empty() && *r != "none")
                    .map(str::to_string)
                    .collect();
                let mode = match case.pii_mode.as_str() {
                    "" => PiiMode::Deny,
                    other => PiiMode::parse(other).unwrap_or_else(|e| panic!("{at}: {e}")),
                };
                let pii = PiiRules::parse(&rules, mode).unwrap_or_else(|e| panic!("{at}: {e}"));
                let policy = match case.dialect.as_str() {
                    "sqlite" => Policy::sqlite(&[], &[]),
                    "postgres" => Policy::postgres(&[], &[]),
                    "mysql" => Policy::mysql(&[], &[]),
                    other => panic!("{at}: unknown dialect {other:?}"),
                };
                let verdict = validate(&case.query, &policy.with_pii(pii));
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
        assert!(total >= 550, "corpus suspiciously small: {total} cases");
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
    fn executable_comment_line_boundary_cannot_hide_an_opener() {
        // Security boundary: a `/*! ... */` executable comment is run by the
        // MySQL server even though the SQL parser discards it, so the scanner
        // must never mistake non-comment text for a `--` line comment and skip
        // a later opener. A lone `-` is subtraction (i+1 is not `-`), and a `--`
        // NOT followed by whitespace (`--x`) is not a comment in MySQL; in each
        // case the later `/*! ... */` is REAL and must still be flagged.
        for sql in [
            "SELECT 2-  /*! SLEEP(5) */ 1",
            "SELECT 1 --x /*! SLEEP(5) */",
        ] {
            assert!(has_mysql_executable_comment(sql), "must flag: {sql}");
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
    fn pii_rules_parse_normalizes_and_rejects_garbage() {
        // table.column and schema.table.column; case and schema are ignored.
        let rules = PiiRules::parse(
            &[
                "Users.Email".to_string(),
                "app.customers.SSN".to_string(),
                " users . phone ".to_string(),
            ],
            PiiMode::Deny,
        )
        .unwrap();
        assert!(rules.protects("users", "email"));
        assert!(rules.protects("USERS", "EMAIL"));
        assert!(rules.protects("public.users", "email"));
        assert!(rules.protects("customers", "ssn"));
        // the schema in the RULE is not required in the query either way
        assert!(rules.protects("app.customers", "ssn"));
        assert!(rules.protects("users", "phone"));
        // and nothing else
        assert!(!rules.protects("users", "id"));
        assert!(!rules.protects("orders", "email"));
        // no rules at all = the historical behavior
        assert!(PiiRules::parse(&[], PiiMode::Deny).unwrap().is_empty());
        // garbage fails loud, naming the offender (Д3/Д10)
        for bad in [
            "",
            "email",
            "users.",
            ".email",
            "a.b.c.d",
            "users..email",
            "   ",
        ] {
            let err = PiiRules::parse(&[bad.to_string()], PiiMode::Deny).unwrap_err();
            assert!(err.contains("table.column"), "{bad:?}: {err}");
        }
    }

    /// Both spellings of PostgreSQL's `FROM ONLY` resolve to the real relation.
    /// sqlparser renders them completely differently — `ONLY t` as a table
    /// called ONLY aliased `t`, `ONLY (t)` as a table FUNCTION called ONLY —
    /// and each one, left unresolved, emptied the scope and switched net A off.
    #[test]
    fn only_resolves_to_the_real_relation_in_both_spellings() {
        let policy = Policy::postgres(&[], &[])
            .with_pii(PiiRules::parse(&["users.email".into()], PiiMode::Deny).unwrap());
        for sql in [
            "SELECT email FROM ONLY users",
            "SELECT email FROM ONLY (users)",
            "SELECT email FROM ONLY(users)",
            "SELECT email FROM ONLY (public.users)",
            "SELECT * FROM ONLY (users)",
            "SELECT count(*) FROM ONLY (users) WHERE email LIKE 'a%'",
        ] {
            assert!(
                matches!(
                    validate(sql, &policy),
                    Verdict::Deny {
                        reason: DenyReason::PiiColumn,
                        ..
                    }
                ),
                "{sql} must be denied"
            );
        }
        // A real table function is NOT the ONLY form and stays usable.
        assert!(matches!(
            validate("SELECT * FROM generate_series(1, 3)", &policy),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn net_b_judges_the_reported_provenance() {
        let rules = PiiRules::parse(&["users.email".to_string()], PiiMode::Deny).unwrap();
        let cols = vec!["x".to_string()];
        let table = |t: &str, c: &str| {
            vec![Origin::Table {
                table: t.to_string(),
                column: c.to_string(),
            }]
        };
        // A protected column reached through a rename/view -> PII_COLUMN.
        for (t, c) in [("users", "email"), ("public.users", "EMAIL")] {
            match check_origins(&rules, &cols, &table(t, c), &[]) {
                Err(Refusal { reason, hint, .. }) => {
                    assert_eq!(reason, DenyReason::PiiColumn);
                    assert!(hint.contains("config"), "{hint}");
                }
                _ => panic!("{t}.{c} must be denied"),
            }
        }
        // An unmarked column and a computed value pass, and mask NOTHING.
        for origins in [table("users", "id"), vec![Origin::Expression]] {
            assert!(check_origins(&rules, &cols, &origins, &[])
                .unwrap()
                .is_empty());
        }
        // An origin the driver would not state, and a MISSING origin, both fail
        // closed with PII_UNPROVABLE.
        for origins in [vec![Origin::Unknown], Vec::new()] {
            match check_origins(&rules, &cols, &origins, &[]) {
                Err(Refusal { reason, hint, .. }) => {
                    assert_eq!(reason, DenyReason::PiiUnprovable);
                    assert!(!hint.is_empty());
                }
                _ => panic!("{origins:?} must be denied"),
            }
        }
        // No PII policy -> net B is a no-op, whatever the driver says.
        let none = PiiRules::default();
        assert!(check_origins(&none, &cols, &table("users", "email"), &[]).is_ok());
        assert!(check_origins(&none, &cols, &[Origin::Unknown], &[]).is_ok());
    }

    /// mode = "mask": the same provenance that REFUSES under deny now names the
    /// columns to redact — and the unprovable case still refuses, in both modes.
    #[test]
    fn net_b_masks_instead_of_refusing_under_mask_mode() {
        let rules = PiiRules::parse(&["users.email".to_string()], PiiMode::Mask).unwrap();
        let cols = vec!["id".to_string(), "e".to_string()];
        let origins = vec![
            Origin::Table {
                table: "users".to_string(),
                column: "id".to_string(),
            },
            Origin::Table {
                table: "public.users".to_string(),
                column: "EMAIL".to_string(),
            },
        ];
        assert_eq!(
            check_origins(&rules, &cols, &origins, &[1]).unwrap(),
            vec![1]
        );
        // ...and ONLY where net A sanctioned it: unsanctioned, the protected
        // column refuses exactly as `deny` does. Net B knows MORE than net A
        // (a view resolved to its base table), and a column net A never saw is
        // one it could not judge the ORDER BY / DISTINCT over.
        match check_origins(&rules, &cols, &origins, &[]) {
            Err(Refusal { reason, .. }) => assert_eq!(reason, DenyReason::PiiColumn),
            Ok(masked) => panic!("an unsanctioned protected column must refuse, got {masked:?}"),
        }
        // Unprovable is unprovable whatever the mode: an Unknown column could BE
        // the protected one, and nyet cannot mask what it cannot identify.
        let unknown = vec![Origin::Unknown, Origin::Expression];
        match check_origins(&rules, &cols, &unknown, &[]) {
            Err(Refusal { reason, .. }) => assert_eq!(reason, DenyReason::PiiUnprovable),
            Ok(masked) => panic!("an Unknown origin must refuse, masked {masked:?}"),
        }
    }

    /// Net A's exemption is a PROMISE, and an unkept promise refuses: the two
    /// live cases (a rule on a view's column while the driver reports the base
    /// table's, and a CTE shadowing the protected table) both arrive here as
    /// "column 1 was exempted but nothing masked it".
    #[test]
    fn net_b_refuses_an_exempted_column_it_did_not_mask() {
        let rules = PiiRules::parse(&["v_users.contact".to_string()], PiiMode::Mask).unwrap();
        let cols = vec!["id".to_string(), "contact".to_string()];
        for origins in [
            // SQLite resolves the view column to its BASE table, which no rule
            // names — so nothing was masked, and the value must not be returned.
            vec![
                Origin::Table {
                    table: "users".to_string(),
                    column: "id".to_string(),
                },
                Origin::Table {
                    table: "users".to_string(),
                    column: "email".to_string(),
                },
            ],
            // A computed value carries no provenance at all.
            vec![Origin::Expression, Origin::Expression],
        ] {
            match check_origins(&rules, &cols, &origins, &[1]) {
                Err(Refusal {
                    reason, message, ..
                }) => {
                    assert_eq!(reason, DenyReason::PiiUnprovable);
                    assert!(message.contains("'contact'"), "{message}");
                }
                Ok(masked) => panic!("an unkept promise must refuse, masked {masked:?}"),
            }
        }
        // The promise KEPT (the policy names what the driver reports) passes.
        let rules = PiiRules::parse(&["users.email".to_string()], PiiMode::Mask).unwrap();
        let kept = vec![
            Origin::Expression,
            Origin::Table {
                table: "users".to_string(),
                column: "email".to_string(),
            },
        ];
        assert_eq!(check_origins(&rules, &cols, &kept, &[1]).unwrap(), vec![1]);
    }

    /// The mask relaxation is per OCCURRENCE, not per name: the very same
    /// `email` is allowed in the projection and refused in the WHERE of one
    /// statement — and the refusal has to teach the mask (Д10).
    #[test]
    fn mask_mode_relaxes_the_projection_and_nothing_else() {
        let policy = Policy::sqlite(&[], &[])
            .with_pii(PiiRules::parse(&["users.email".to_string()], PiiMode::Mask).unwrap());
        assert!(matches!(
            validate("SELECT id, email FROM users LIMIT 5", &policy),
            Verdict::Allow { .. }
        ));
        let Verdict::Deny { reason, hint, .. } =
            validate("SELECT email FROM users WHERE email LIKE 'a%'", &policy)
        else {
            panic!("a filter on the protected column must stay refused")
        };
        assert_eq!(reason, DenyReason::PiiColumn);
        assert!(hint.contains("REDACTED"), "{hint}");
        assert!(hint.contains("no CLI flag"), "{hint}");
        // Deny mode is untouched by the new code path.
        let deny_policy = Policy::sqlite(&[], &[])
            .with_pii(PiiRules::parse(&["users.email".to_string()], PiiMode::Deny).unwrap());
        assert!(matches!(
            validate("SELECT id, email FROM users LIMIT 5", &deny_policy),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn pii_refusals_say_there_is_no_override() {
        // Д10 + the guardrail's rule: an agent that can lift its own limit does
        // not have one, so every PII hint must close that door explicitly.
        let policy = Policy::postgres(&[], &[])
            .with_pii(PiiRules::parse(&["users.email".to_string()], PiiMode::Deny).unwrap());
        for sql in [
            "SELECT email FROM users",
            "SELECT * FROM users",
            "SELECT u FROM users u",
            "SELECT * FROM pg_stats",
        ] {
            let Verdict::Deny {
                reason,
                message,
                hint,
            } = validate(sql, &policy)
            else {
                panic!("{sql} must be denied")
            };
            assert_eq!(reason, DenyReason::PiiColumn, "{sql}");
            assert!(!message.is_empty(), "{sql}");
            assert!(hint.contains("no CLI flag"), "{sql}: {hint}");
            assert!(hint.contains("config file"), "{sql}: {hint}");
            // A refusal must never echo data; it names schema only.
            assert!(!message.contains('@'), "{sql}: {message}");
        }
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
