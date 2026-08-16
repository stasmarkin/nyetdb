//! Auto-guardrail: estimate what a query will cost from its PLAN, before the
//! database runs it, and refuse the monsters (ROADMAP v0.3).
//!
//! Pure (D1/D2): plan parsing, the threshold comparison and the refusal texts
//! live here and are unit-tested on fixture plans without a live database. The
//! engines only do the IO — run the EXPLAIN, hand the rows/JSON over — and the
//! cli decides what to do with the verdict. The comparison strategy is
//! deliberately OUTSIDE the engines so the three cannot drift.
//!
//! **The EXPLAIN is never ANALYZE.** ANALYZE *executes* the statement, which is
//! the one thing a guardrail must not do; every prefix here is a constant, and
//! the SQL appended to it is the text the validator already accepted (which
//! refuses an agent's own `EXPLAIN ANALYZE`, reason `EXPLAIN_ANALYZE`).

use crate::output::Estimate;
use serde_json::Value;
use std::collections::BTreeMap;

/// What an engine reads out of a query plan (`nyet explain`, and the guardrail
/// before `nyet query` runs). `cost`/`rows` are `None` when this engine's plan
/// carries no such number — SQLite has neither, MySQL/MariaDB have no portable
/// cost — or when the number would be a lie (a recursive CTE, see
/// `postgres_estimate`).
#[derive(Debug)]
pub struct CostEstimate {
    /// The plan as the engine reports it: PostgreSQL's `FORMAT JSON` tree,
    /// MySQL/MariaDB's classic EXPLAIN rows as objects, SQLite's
    /// EXPLAIN QUERY PLAN lines as strings.
    pub plan: Value,
    pub cost: Option<f64>,
    pub rows: Option<u64>,
    /// The numbers are a LOWER BOUND: part of this plan is not estimated by the
    /// planner at all (a `Recursive Union`). Above the threshold they still
    /// refuse — the real statement is only bigger — but below it they cannot
    /// promise "ok", so the verdict degrades to `no_estimate`.
    pub lower_bound: bool,
}

/// What the guardrail compares against the threshold. Per-engine support is
/// resolved in [`Guardrail::resolve`]: PostgreSQL has both, MySQL/MariaDB only
/// `rows`, SQLite neither (its plan carries no numbers at all).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// The planner's own cost model (PostgreSQL `Total Cost`).
    Cost,
    /// Estimated rows (PostgreSQL `Plan Rows`; MySQL/MariaDB the classic
    /// EXPLAIN `rows` column, joined per select and combined across selects).
    Rows,
    /// No guardrail: the query runs unchecked (timeout + row limit still apply).
    Off,
}

impl Mode {
    /// Part of the agent-facing envelope (`estimate.mode`).
    fn as_str(self) -> &'static str {
        match self {
            Mode::Cost => "cost",
            Mode::Rows => "rows",
            Mode::Off => "off",
        }
    }

    fn parse(s: &str) -> Option<Mode> {
        match s {
            "cost" => Some(Mode::Cost),
            "rows" => Some(Mode::Rows),
            "off" => Some(Mode::Off),
            _ => None,
        }
    }
}

/// Default cost ceiling (PostgreSQL cost units). Deliberately generous — the
/// guardrail exists to stop obvious monsters, not to second-guess legitimate
/// analytics (UX-1: a false refusal is annoying, and a guardrail nobody trusts
/// gets turned off). See docs/dev/DEV.md for the arithmetic behind the number.
pub const DEFAULT_MAX_COST: f64 = 1_000_000.0;

/// Default row ceiling (estimated rows examined / produced). Same spirit.
pub const DEFAULT_MAX_ROWS: u64 = 10_000_000;

/// A connection's resolved guardrail: the mode plus the threshold it compares
/// against. Built once from the config (validated at config parse, D3).
#[derive(Debug)]
pub struct Guardrail {
    mode: Mode,
    max_cost: f64,
    max_rows: u64,
}

/// The guardrail's answer for one estimate.
#[derive(Debug, PartialEq)]
pub enum Check {
    /// Under the threshold — run it.
    Ok,
    /// Over the threshold — do not run it.
    Expensive { value: f64 },
    /// Nothing to compare: the mode is `off`, or the plan carried no usable
    /// number. Best effort by design — see `docs/dev/DEV.md`.
    NoEstimate,
}

impl Guardrail {
    /// No guardrail. Used for engines that cannot be estimated and by tests.
    pub const OFF: Guardrail = Guardrail {
        mode: Mode::Off,
        max_cost: DEFAULT_MAX_COST,
        max_rows: DEFAULT_MAX_ROWS,
    };

    /// `[connections.X.guardrail]` -> the effective guardrail, or the config
    /// error message (the cli turns it into CONFIG_INVALID, exit 3 — fail loud,
    /// a mode the engine cannot honor must never silently degrade to "off").
    /// Pure; `config::guardrail` is the single caller.
    pub fn resolve(
        engine: &str,
        mode: Option<&str>,
        max_cost: Option<f64>,
        max_rows: Option<u64>,
    ) -> Result<Guardrail, String> {
        let (default_mode, supported) = engine_modes(engine);
        let mode = match mode {
            None => default_mode,
            Some(name) => Mode::parse(name).ok_or_else(|| {
                format!("unknown guardrail mode \"{name}\"; supported: cost, rows, off")
            })?,
        };
        if !supported.contains(&mode) {
            return Err(format!(
                "guardrail mode \"{}\" is not supported by engine \"{engine}\" ({}); \
                 supported modes for this engine: {}",
                mode.as_str(),
                why_unsupported(engine),
                supported
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // A threshold the active mode never reads is a silent misconfiguration:
        // the human believes there is a limit where there is none. Fail loud —
        // the same reflex as an unknown key.
        let unread = |key: &str, reader: Mode| {
            format!(
                "guardrail {key} is set, but the active mode is \"{}\", which never reads it; \
                 remove {key} or set mode = \"{}\"",
                mode.as_str(),
                reader.as_str()
            )
        };
        if max_cost.is_some() && mode != Mode::Cost {
            return Err(unread("max_cost", Mode::Cost));
        }
        if max_rows.is_some() && mode != Mode::Rows {
            return Err(unread("max_rows", Mode::Rows));
        }
        let max_cost = max_cost.unwrap_or(DEFAULT_MAX_COST);
        // A non-positive or non-finite threshold would refuse every query (and a
        // non-finite one cannot even be serialized into the envelope).
        if !(max_cost.is_finite() && max_cost > 0.0) {
            return Err("guardrail max_cost must be a positive, finite number".to_string());
        }
        let max_rows = max_rows.unwrap_or(DEFAULT_MAX_ROWS);
        if max_rows == 0 {
            return Err("guardrail max_rows must be at least 1".to_string());
        }
        Ok(Guardrail {
            mode,
            max_cost,
            max_rows,
        })
    }

    /// Is there anything to ask the planner for? `false` skips the EXPLAIN
    /// entirely — the engines never look at the mode themselves.
    pub fn plans(&self) -> bool {
        self.mode != Mode::Off
    }

    pub fn check(&self, estimate: &CostEstimate) -> Check {
        let measured = match self.mode {
            Mode::Off => Check::NoEstimate,
            Mode::Cost => compare(estimate.cost, self.max_cost),
            // Compared as u64, not through f64: past 2^53 two different row
            // counts round to the same float, and a monster must not tie with
            // its threshold. `value` is f64 for the message only.
            #[allow(clippy::cast_precision_loss)] // display only
            Mode::Rows => match estimate.rows {
                None => Check::NoEstimate,
                Some(rows) if rows > self.max_rows => Check::Expensive { value: rows as f64 },
                Some(_) => Check::Ok,
            },
        };
        match measured {
            // A lower bound that ALREADY exceeds the limit is proof enough: the
            // unestimated part only adds. This is what stops "glue a two-row
            // recursive CTE onto the monster" from switching the guardrail off.
            Check::Expensive { value } => Check::Expensive { value },
            // Under the limit, but part of the plan was never estimated: we
            // cannot promise "ok", so we say we do not know (the query runs,
            // with the warning; the timeout is the backstop).
            _ if estimate.lower_bound => Check::NoEstimate,
            other => other,
        }
    }

    /// The offending value when this estimate must stop the query, `None` when
    /// it may run. The engines call exactly this — the policy stays here, they
    /// only obey it.
    pub fn refuses(&self, estimate: &CostEstimate) -> Option<f64> {
        match self.check(estimate) {
            Check::Expensive { value } => Some(value),
            Check::Ok | Check::NoEstimate => None,
        }
    }

    /// The limit the active mode compares against (`None` when it compares
    /// nothing).
    fn threshold(&self) -> Option<Value> {
        match self.mode {
            Mode::Cost => Some(Value::from(self.max_cost)),
            Mode::Rows => Some(Value::from(self.max_rows)),
            Mode::Off => None,
        }
    }

    /// The envelope body shared by `nyet explain` and the refusal (one shape,
    /// one documented contract).
    pub fn describe(&self, estimate: CostEstimate) -> Estimate {
        let check = self.check(&estimate);
        Estimate {
            mode: self.mode.as_str(),
            verdict: match check {
                Check::Ok => "ok",
                Check::Expensive { .. } => "expensive",
                Check::NoEstimate => "no_estimate",
            },
            cost: estimate.cost,
            rows: estimate.rows,
            // Absent when nothing was compared, so the agent never reads a
            // threshold that had no say in the verdict.
            threshold: match check {
                Check::NoEstimate => None,
                Check::Ok | Check::Expensive { .. } => self.threshold(),
            },
            plan: estimate.plan,
        }
    }

    /// The refusal texts (D10: what happened -> why -> what to do instead).
    /// The way out names the HUMAN's config key on purpose: the threshold
    /// belongs to the config owner, and nyet ships no CLI override (UX-7 — an
    /// agent that can lift its own guardrail is theatre).
    #[allow(clippy::cast_precision_loss)] // display only
    pub fn refusal(&self, alias: &str, value: f64) -> (String, String) {
        let (what, key, threshold) = match self.mode {
            Mode::Rows => ("estimated rows", "max_rows", self.max_rows as f64),
            Mode::Cost | Mode::Off => ("estimated cost", "max_cost", self.max_cost),
        };
        (
            format!(
                "nyet: the query plan's {what} is {value:.0}, above the guardrail limit of \
                 {threshold:.0} for connection '{alias}' — the query was NOT executed"
            ),
            format!(
                "narrow the query (add a WHERE filter or a LIMIT, join on an indexed column) \
                 — the plan is in `estimate` of this envelope; if the query really is \
                 legitimate, ask the person who owns the config to raise \
                 [connections.{alias}.guardrail] {key}"
            ),
        )
    }
}

/// The guardrail could not obtain a plan inside its own budget. Fail CLOSED:
/// planning time is agent-controllable (PostgreSQL folds `IMMUTABLE` expressions
/// at plan time; a MySQL EXPLAIN over `information_schema` can take tens of
/// seconds), so "no plan in time" must not become a way to switch the guard off
/// — it is itself evidence that the statement is expensive. Reuses the
/// `EXPENSIVE_QUERY` reason: same verdict, no new contract code.
#[allow(clippy::cast_precision_loss)] // display only
pub fn planning_too_slow(alias: &str, budget_ms: u64) -> (String, String) {
    (
        format!(
            "nyet: the guardrail could not obtain a plan estimate within its budget \
             ({:.1}s) — planning this statement is itself that expensive, so it was NOT \
             executed",
            budget_ms as f64 / 1000.0
        ),
        format!(
            "simplify the query (fewer joins, fewer computed expressions in the SELECT \
             list) — a statement whose PLAN takes seconds will not be cheap to run; if it \
             really is legitimate, the person who owns the config can raise \
             [connections.{alias}.guardrail] max_cost / max_rows, or set mode = \"off\" \
             for this connection"
        ),
    )
}

/// (default mode, supported modes) per engine. An engine nyet does not ship yet
/// gets `off` only — fail closed on a mode we cannot honor.
fn engine_modes(engine: &str) -> (Mode, &'static [Mode]) {
    match engine {
        "postgres" => (Mode::Cost, &[Mode::Cost, Mode::Rows, Mode::Off]),
        "mysql" | "mariadb" => (Mode::Rows, &[Mode::Rows, Mode::Off]),
        // `EXPLAIN ESTIMATE` publishes rows and marks a MergeTree query will
        // READ, from part metadata, without touching a row — the cheapest true
        // estimate of any engine here. It publishes no cost model at all.
        "clickhouse" => (Mode::Rows, &[Mode::Rows, Mode::Off]),
        _ => (Mode::Off, &[Mode::Off]),
    }
}

/// The honest reason a mode is missing, so the config error teaches (D10).
fn why_unsupported(engine: &str) -> &'static str {
    match engine {
        "mysql" | "mariadb" => {
            "MySQL/MariaDB report no portable plan cost — the classic EXPLAIN has \
             row estimates only"
        }
        "sqlite" => "SQLite's EXPLAIN QUERY PLAN carries no cost or row estimates at all",
        "redis" | "valkey" => {
            "Redis publishes no query plan and no estimate of any kind — there is nothing to \
             ask it before running a command"
        }
        "clickhouse" => {
            "ClickHouse publishes no planner cost model; EXPLAIN ESTIMATE gives rows and marks, \
             and only for MergeTree tables (system tables and table functions come back empty, \
             which nyet reports as no estimate rather than as zero)"
        }
        "mongodb" => {
            "MongoDB's explain publishes no cost and no row estimate in queryPlanner mode, \
             and its executionStats mode RUNS the query — which is the one thing a guardrail \
             must never do"
        }
        _ => "this engine has no query planner nyet can read",
    }
}

fn compare(value: Option<f64>, threshold: f64) -> Check {
    match value {
        None => Check::NoEstimate,
        Some(v) if v > threshold => Check::Expensive { value: v },
        Some(_) => Check::Ok,
    }
}

/// A plan number as f64, or None when it is absent/not a number/not finite. The
/// plan is EXTERNAL input (D3): a surprising shape must never panic, it just
/// means "no estimate".
///
/// A numeric STRING counts as a number too: MariaDB 11.4 sends the classic
/// EXPLAIN `rows` column as a string over the binary protocol (`"4000"`, seen
/// against the real server), so a number-only reader would give up on that whole
/// flavor. Both forms are parsed, and both are pinned by the fixtures below.
fn number(value: Option<&Value>) -> Option<f64> {
    let parsed = match value? {
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        other => other.as_f64()?,
    };
    parsed.is_finite().then_some(parsed)
}

fn rows_from(value: Option<&Value>) -> Option<u64> {
    number(value).map(clamp_rows)
}

/// A row count as u64. Saturating on both ends: a plan may claim more rows than
/// u64 holds (a big enough cross join overflows to infinity), and that is still
/// just "enormous" — never a panic or a wrapped-around small number.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn clamp_rows(value: f64) -> u64 {
    value.clamp(0.0, u64::MAX as f64) as u64
}

/// PostgreSQL `EXPLAIN (FORMAT JSON)`: an array with one element per statement,
/// each `{"Plan": {"Total Cost": f, "Plan Rows": n, ...}}`. Both numbers come
/// from the TOP node — the total for the whole statement.
///
/// **A recursive CTE makes the numbers a LOWER BOUND, it does not erase them.**
/// PostgreSQL does not estimate the iteration of a `Recursive Union`, so
/// `WITH RECURSIVE t AS (... UNION ALL SELECT n + 1 FROM t WHERE n < 1e11) ...`
/// plans at a cost near zero while the backend burns CPU until the timeout — a
/// confident "ok" there would be a lie. But dropping the numbers ENTIRELY was
/// worse: gluing a two-row recursive CTE onto a monster then switched the
/// guardrail off for the whole statement (verified live). So the numbers are
/// kept and flagged: above the threshold they still refuse (the unestimated part
/// only adds), below it the verdict degrades to `no_estimate` — the query runs
/// with `GUARDRAIL_SKIPPED` and the timeout as the backstop, because refusing
/// every recursive CTE would be a false refusal for ordinary hierarchy walks.
pub fn postgres_estimate(plan: Value) -> CostEstimate {
    let top = plan.get(0).and_then(|p| p.get("Plan"));
    CostEstimate {
        // Cost: the TOP node's total, which already includes its children.
        cost: number(top.and_then(|p| p.get("Total Cost"))),
        // Rows: the LARGEST `Plan Rows` anywhere in the tree, not the top
        // node's. The top node is routinely an Aggregate or a Result returning
        // ONE row over a scan of millions — reading only it let every
        // `SELECT count(*) FROM huge` through in rows mode. The maximum is the
        // conservative direction (rows mode is a proxy for work done, and the
        // row limit already bounds what is returned).
        rows: max_plan_rows(&plan),
        lower_bound: contains_node_type(&plan, "Recursive Union"),
        plan,
    }
}

/// The largest `Plan Rows` anywhere in the plan tree.
fn max_plan_rows(value: &Value) -> Option<u64> {
    let here = match value {
        Value::Object(fields) => rows_from(fields.get("Plan Rows")),
        _ => None,
    };
    let children = match value {
        Value::Object(fields) => fields.values().filter_map(max_plan_rows).max(),
        Value::Array(items) => items.iter().filter_map(max_plan_rows).max(),
        _ => None,
    };
    here.max(children)
}

/// Does any node of this plan tree carry that `Node Type`? Walks the whole JSON
/// value rather than the documented `Plan`/`Plans` path, so it does not depend
/// on where in the tree the node sits (or on a future server moving it). Depth
/// is bounded by serde_json's own parse recursion limit.
fn contains_node_type(value: &Value, name: &str) -> bool {
    match value {
        Value::Object(fields) => {
            fields.get("Node Type").and_then(Value::as_str) == Some(name)
                || fields.values().any(|v| contains_node_type(v, name))
        }
        Value::Array(items) => items.iter().any(|v| contains_node_type(v, name)),
        _ => false,
    }
}

/// One `id` group of a classic MySQL EXPLAIN: one SELECT of the statement.
struct SelectSteps {
    /// Product of the steps' row estimates — this select's join fan-out.
    rows: f64,
    /// A DEPENDENT / UNCACHEABLE subquery is re-run for every row of its
    /// parent, so its work MULTIPLIES the outer estimate instead of adding.
    dependent: bool,
}

/// MySQL/MariaDB classic `EXPLAIN` — one row per access step, on BOTH flavors
/// (`EXPLAIN FORMAT=JSON` differs between them; the tabular form does not).
///
/// Rows sharing an `id` belong to one select and are JOINED, so their estimates
/// multiply — that product is what makes a cross join enormous, and is the whole
/// point. Across selects: independent ones (UNION arms, cached subqueries) ADD,
/// while `DEPENDENT`/`UNCACHEABLE` ones MULTIPLY the rest, because the server
/// re-runs them per outer row (adding them understated a correlated subquery by
/// orders of magnitude: 5000 + 5000 for real work of 2.5e7). Formally
/// `(Σ independent, plus every dependent group estimated at 1) × (Π dependent
/// groups estimated above 1)` — a dependent group of one row is added rather
/// than multiplied, because `×1` would erase it and k such groups would read as
/// a single row. `filtered` is ignored on purpose: it only ever lowers the
/// number, and over-estimating is the safe direction here.
///
/// A step with no numeric `rows` contributes nothing — EXCEPT a tableless step
/// (`table` NULL: "No tables used", "Impossible WHERE", "Select tables optimized
/// away"), which is a plan that reads nothing rather than a plan we failed to
/// read: it counts as one row, so `SELECT 1` gets a verdict instead of a
/// spurious "could not check" warning on every call.
pub fn mysql_estimate(columns: &[String], rows: &[Vec<Value>]) -> CostEstimate {
    let plan = plan_rows(columns, rows);
    let (id_at, rows_at) = (column_index(columns, "id"), column_index(columns, "rows"));
    let table_at = column_index(columns, "table");
    let kind_at = column_index(columns, "select_type");
    // Keyed by the select id rendered as text: NULL and unexpected types become
    // their own group rather than merging silently.
    let mut selects: BTreeMap<String, SelectSteps> = BTreeMap::new();
    for row in rows {
        let cell = |at: Option<usize>| at.and_then(|i| row.get(i));
        let step = match number(cell(rows_at)) {
            Some(estimate) => estimate.max(1.0),
            None if cell(table_at).is_some_and(Value::is_null) => 1.0,
            None => continue,
        };
        let id = cell(id_at).map_or_else(|| "?".to_string(), Value::to_string);
        let select = selects.entry(id).or_insert(SelectSteps {
            rows: 1.0,
            dependent: false,
        });
        select.rows *= step;
        select.dependent |= cell(kind_at)
            .and_then(Value::as_str)
            .is_some_and(is_dependent);
    }
    let mut independent = 0.0;
    let mut dependent = 1.0;
    for select in selects.values() {
        // A dependent group MULTIPLIES the outer work — unless its own estimate
        // is 1, where multiplying would make it vanish: k such groups would read
        // as one row instead of k (a k-fold under-count). Those add, like an
        // independent select.
        if select.dependent && select.rows > 1.0 {
            dependent *= select.rows;
        } else {
            independent += select.rows;
        }
    }
    CostEstimate {
        rows: (!selects.is_empty()).then(|| clamp_rows(independent.max(1.0) * dependent)),
        cost: None,
        lower_bound: false,
        plan,
    }
}

/// `DEPENDENT SUBQUERY`, `DEPENDENT UNION`, `UNCACHEABLE SUBQUERY`, ... — the
/// select types the server re-evaluates per outer row.
fn is_dependent(select_type: &str) -> bool {
    let kind = select_type.to_ascii_uppercase();
    kind.contains("DEPENDENT") || kind.contains("UNCACHEABLE")
}

/// SQLite `EXPLAIN QUERY PLAN`: the `detail` column is the human-readable plan.
/// There are NO numbers — SQLite's planner does not publish cost or row
/// estimates — so the guardrail is unsupported for SQLite and says so instead of
/// inventing a pseudo-metric (UX-7).
pub fn sqlite_estimate(columns: &[String], rows: &[Vec<Value>]) -> CostEstimate {
    let plan = match column_index(columns, "detail") {
        // The compact form: one plan line per entry.
        Some(i) => Value::Array(
            rows.iter()
                .map(|r| r.get(i).cloned().unwrap_or(Value::Null))
                .collect(),
        ),
        None => plan_rows(columns, rows),
    };
    CostEstimate {
        plan,
        cost: None,
        rows: None,
        lower_bound: false,
    }
}

/// Tabular plan -> an array of objects, keys in column order (same shape the
/// query envelope gives rows).
fn plan_rows(columns: &[String], rows: &[Vec<Value>]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                Value::Object(
                    columns
                        .iter()
                        .zip(row)
                        .map(|(c, v)| (c.clone(), v.clone()))
                        .collect(),
                )
            })
            .collect(),
    )
}

/// Column lookup by name, case-insensitive: MySQL 8 and MariaDB agree on the
/// EXPLAIN column names but not on their case in every version.
fn column_index(columns: &[String], name: &str) -> Option<usize> {
    columns.iter().position(|c| c.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate(cost: Option<f64>, rows: Option<u64>) -> CostEstimate {
        CostEstimate {
            plan: Value::Null,
            cost,
            rows,
            lower_bound: false,
        }
    }

    fn pg(mode: &str) -> Guardrail {
        Guardrail::resolve("postgres", Some(mode), None, None).unwrap()
    }

    fn mysql() -> Guardrail {
        Guardrail::resolve("mysql", None, None, None).unwrap()
    }

    #[test]
    fn postgres_plan_takes_top_cost_and_the_biggest_row_count() {
        let plan: Value = serde_json::from_str(
            r#"[{"Plan":{"Node Type":"Aggregate","Total Cost":12500000.5,"Plan Rows":1,
                 "Plans":[{"Node Type":"Seq Scan","Total Cost":42.0,"Plan Rows":9999}]}}]"#,
        )
        .unwrap();
        let est = postgres_estimate(plan);
        // Cost: the top node's total (it already includes the children).
        assert_eq!(est.cost, Some(12_500_000.5));
        // Rows: the BIGGEST node, not the top one — an Aggregate returning a
        // single row over a scan of millions must not read as "1 row".
        assert_eq!(est.rows, Some(9999));
        assert!(est.plan.get(0).is_some(), "the plan travels verbatim");
        // The shape that made this a bypass: `SELECT count(*) FROM huge`.
        let count_star: Value = serde_json::from_str(
            r#"[{"Plan":{"Node Type":"Aggregate","Total Cost":9.0,"Plan Rows":1,
                 "Plans":[{"Node Type":"Seq Scan","Total Cost":8.0,"Plan Rows":9000000}]}}]"#,
        )
        .unwrap();
        let est = postgres_estimate(count_star);
        assert_eq!(est.rows, Some(9_000_000));
        assert!(
            pg("rows").refuses(&est).is_none(),
            "under the default limit"
        );
        assert_eq!(
            Guardrail::resolve("postgres", Some("rows"), None, Some(1_000_000))
                .unwrap()
                .refuses(&est),
            Some(9_000_000.0)
        );
    }

    /// Row counts are compared as integers: past 2^53 two different u64 values
    /// round to the SAME f64, which would let a monster tie with its threshold.
    #[test]
    fn row_comparison_is_exact_past_the_f64_mantissa() {
        let threshold = (1u64 << 53) + 1;
        let over = threshold + 1; // equal to `threshold` as an f64
        let guard = Guardrail::resolve("mysql", None, None, Some(threshold)).unwrap();
        assert_eq!(guard.check(&estimate(None, Some(threshold))), Check::Ok);
        assert!(matches!(
            guard.check(&estimate(None, Some(over))),
            Check::Expensive { .. }
        ));
    }

    /// A recursive CTE is the sharpest way to melt a backend with a plan that
    /// claims to cost nothing: PostgreSQL does not estimate the iteration, so a
    /// 10^11-step recursion plans at ~3.35. It must not read as "ok" — and it
    /// must not become an OFF SWITCH either: gluing a two-row recursive CTE onto
    /// a monster used to erase the monster's own estimate (verified live).
    #[test]
    fn a_recursive_union_lowers_the_verdict_but_never_hides_a_monster() {
        let cheap: Value = serde_json::from_str(
            r#"[{"Plan":{"Node Type":"Aggregate","Total Cost":3.35,"Plan Rows":1,
                 "Plans":[{"Node Type":"CTE Scan","Total Cost":2.0,"Plan Rows":100,
                   "Plans":[{"Node Type":"Recursive Union","Total Cost":1.7,"Plan Rows":31}]}]}}]"#,
        )
        .unwrap();
        let est = postgres_estimate(cheap);
        // The numbers survive, but they are only a LOWER bound...
        assert_eq!(est.cost, Some(3.35));
        assert!(est.lower_bound);
        // ...so under the limit there is no verdict to give (the query runs with
        // GUARDRAIL_SKIPPED; the timeout is the backstop).
        assert_eq!(pg("cost").check(&est), Check::NoEstimate);
        assert_eq!(pg("rows").check(&est), Check::NoEstimate);
        assert!(est.plan.to_string().contains("Recursive Union"));

        // THE ATTACK: a monster with a trivial recursive CTE glued on. The cost
        // is still enormous, so it is still refused — a lower bound above the
        // limit is proof, the unestimated part only adds.
        let monster: Value = serde_json::from_str(
            r#"[{"Plan":{"Node Type":"Aggregate","Total Cost":22500000000.0,"Plan Rows":1,
                 "Plans":[{"Node Type":"Nested Loop","Total Cost":22000000000.0,
                   "Plan Rows":1000000000000,
                   "Plans":[{"Node Type":"Recursive Union","Total Cost":1.7,"Plan Rows":2}]}]}}]"#,
        )
        .unwrap();
        let est = postgres_estimate(monster);
        assert!(est.lower_bound);
        assert_eq!(pg("cost").refuses(&est), Some(22_500_000_000.0));
        assert!(pg("rows").refuses(&est).is_some());

        // A plan without recursion is judged normally (no over-reaction).
        let plain: Value =
            serde_json::from_str(r#"[{"Plan":{"Node Type":"Seq Scan","Total Cost":3.35}}]"#)
                .unwrap();
        let est = postgres_estimate(plain);
        assert!(!est.lower_bound);
        assert_eq!(pg("cost").check(&est), Check::Ok);
    }

    /// D3: the plan is external input — a surprising shape degrades to "no
    /// estimate", never a panic and never an invented number.
    #[test]
    fn a_surprising_postgres_plan_is_no_estimate_not_a_panic() {
        for text in [
            "null",
            "[]",
            "[{}]",
            r#"[{"Plan":{}}]"#,
            r#"[{"Plan":{"Total Cost":"cheap"}}]"#,
            r#"{"Plan":{"Total Cost":1.0}}"#, // object, not the documented array
            r#"[{"Plan":{"Total Cost":null,"Plan Rows":null}}]"#,
        ] {
            let est = postgres_estimate(serde_json::from_str(text).unwrap());
            assert_eq!(est.cost, None, "{text}");
            assert_eq!(est.rows, None, "{text}");
            assert_eq!(pg("cost").check(&est), Check::NoEstimate, "{text}");
        }
    }

    fn columns(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    /// MySQL 8 columns: `partitions`/`filtered` present, `rows` numeric.
    fn mysql8_columns() -> Vec<String> {
        columns(&[
            "id",
            "select_type",
            "table",
            "partitions",
            "type",
            "possible_keys",
            "key",
            "key_len",
            "ref",
            "rows",
            "filtered",
            "Extra",
        ])
    }

    fn mysql8_row(id: Value, kind: &str, table: Value, rows: Value, extra: &str) -> Vec<Value> {
        vec![
            id,
            Value::from(kind),
            table,
            Value::Null,
            Value::from("ALL"),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            rows,
            Value::from(100.0),
            Value::from(extra),
        ]
    }

    /// The row counts of one select multiply: that is what makes a cross join
    /// enormous.
    #[test]
    fn mysql8_classic_explain_multiplies_a_join() {
        let est = mysql_estimate(
            &mysql8_columns(),
            &[
                mysql8_row(
                    Value::from(1),
                    "SIMPLE",
                    Value::from("a"),
                    Value::from(20_000),
                    "",
                ),
                mysql8_row(
                    Value::from(1),
                    "SIMPLE",
                    Value::from("b"),
                    Value::from(30_000),
                    "Using join buffer",
                ),
            ],
        );
        assert_eq!(est.rows, Some(600_000_000));
        assert_eq!(est.cost, None, "no portable cost on this engine");
        // The plan travels as one object per step, keys in column order.
        assert_eq!(est.plan[0]["table"], Value::from("a"));
        assert_eq!(est.plan[1]["rows"], Value::from(30_000));
    }

    /// A correlated subquery is re-executed per outer row, so its estimate
    /// MULTIPLIES the outer one. Adding them (the naive reading) understated
    /// real work by orders of magnitude: 5000 + 5000 for 2.5e7 rows examined.
    #[test]
    fn mysql_dependent_subquery_multiplies_the_outer_select() {
        let outer = || {
            mysql8_row(
                Value::from(1),
                "PRIMARY",
                Value::from("a"),
                Value::from(5000),
                "",
            )
        };
        let inner = |kind: &str| {
            mysql8_row(
                Value::from(2),
                kind,
                Value::from("b"),
                Value::from(5000),
                "Using where",
            )
        };
        for kind in [
            "DEPENDENT SUBQUERY",
            "UNCACHEABLE SUBQUERY",
            "DEPENDENT UNION",
        ] {
            let est = mysql_estimate(&mysql8_columns(), &[outer(), inner(kind)]);
            assert_eq!(est.rows, Some(25_000_000), "{kind}");
        }
        // ...while an independent (cached) subquery still adds.
        let est = mysql_estimate(&mysql8_columns(), &[outer(), inner("SUBQUERY")]);
        assert_eq!(est.rows, Some(10_000));

        // A dependent group whose own estimate is 1 must NOT be multiplied in:
        // three of them would otherwise vanish into x1 and read as the outer
        // select alone (5000 instead of 5003).
        let single = |id: u64| {
            mysql8_row(
                Value::from(id),
                "DEPENDENT SUBQUERY",
                Value::from("k"),
                Value::from(1),
                "",
            )
        };
        let est = mysql_estimate(
            &mysql8_columns(),
            &[outer(), single(2), single(3), single(4)],
        );
        assert_eq!(est.rows, Some(5003));
    }

    /// A plan that reads no table at all ("No tables used", "Impossible WHERE",
    /// "Select tables optimized away") is a KNOWN trivial plan, not an
    /// unreadable one: `SELECT 1` must get a verdict, not a "could not check"
    /// warning on every call.
    #[test]
    fn mysql_tableless_plan_is_trivial_not_unreadable() {
        for extra in [
            "No tables used",
            "Impossible WHERE",
            "Select tables optimized away",
        ] {
            let est = mysql_estimate(
                &mysql8_columns(),
                &[mysql8_row(
                    Value::from(1),
                    "SIMPLE",
                    Value::Null,
                    Value::Null,
                    extra,
                )],
            );
            assert_eq!(est.rows, Some(1), "{extra}");
            assert_eq!(mysql().check(&est), Check::Ok, "{extra}");
        }
        // A NAMED table whose row count we could not read stays unreadable —
        // the UNION RESULT bookkeeping row, and any future surprise.
        let est = mysql_estimate(
            &mysql8_columns(),
            &[mysql8_row(
                Value::Null,
                "UNION RESULT",
                Value::from("<union1,2>"),
                Value::Null,
                "",
            )],
        );
        assert_eq!(est.rows, None);
        assert_eq!(mysql().check(&est), Check::NoEstimate);
    }

    /// MariaDB `EXPLAIN`: no `partitions`/`filtered` columns, and `rows` arrives
    /// as a STRING (what the real 11.4 server sends — the numeric form is pinned
    /// by the MySQL 8 fixtures above). Same parser, and separate select ids ADD
    /// instead of multiplying, so a UNION of two ordinary scans is not mistaken
    /// for a monster.
    #[test]
    fn mariadb_classic_explain_sums_union_arms() {
        let cols = columns(&[
            "id",
            "select_type",
            "table",
            "type",
            "possible_keys",
            "key",
            "key_len",
            "ref",
            "rows",
            "Extra",
        ]);
        let row = |id: Value, kind: &str, table: Value, rows: Value| {
            vec![
                id,
                Value::from(kind),
                table,
                Value::from("ALL"),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                rows,
                Value::Null,
            ]
        };
        let est = mysql_estimate(
            &cols,
            &[
                row(
                    Value::from(1),
                    "PRIMARY",
                    Value::from("t"),
                    Value::from("4000"),
                ),
                row(
                    Value::from(2),
                    "UNION",
                    Value::from("t"),
                    Value::from("4000"),
                ),
                row(
                    Value::Null,
                    "UNION RESULT",
                    Value::from("<union1,2>"),
                    Value::Null,
                ),
            ],
        );
        assert_eq!(est.rows, Some(8000));
        // No usable `rows` anywhere -> no estimate (guardrail skipped, not zero).
        let est = mysql_estimate(
            &cols,
            &[row(Value::from(1), "SIMPLE", Value::from("t"), Value::Null)],
        );
        assert_eq!(est.rows, None);
        assert_eq!(mysql_estimate(&cols, &[]).rows, None);
    }

    #[test]
    fn sqlite_plan_is_text_only_and_never_estimates() {
        let cols = columns(&["id", "parent", "notused", "detail"]);
        let rows = vec![vec![
            Value::from(2),
            Value::from(0),
            Value::from(0),
            Value::from("SCAN users"),
        ]];
        let est = sqlite_estimate(&cols, &rows);
        assert_eq!(est.plan, serde_json::json!(["SCAN users"]));
        assert_eq!((est.cost, est.rows), (None, None));
        // Which is exactly why sqlite is off-only (see resolve below).
        assert_eq!(Guardrail::OFF.check(&est), Check::NoEstimate);
    }

    #[test]
    fn thresholds_decide_and_only_the_active_mode_counts() {
        let est = estimate(Some(2_000_000.0), Some(5));
        assert_eq!(pg("cost").refuses(&est), Some(2_000_000.0));
        // rows mode looks at rows only: the huge cost is irrelevant there.
        assert_eq!(pg("rows").refuses(&est), None);
        assert_eq!(pg("rows").check(&est), Check::Ok);
        // Exactly at the threshold passes (only ABOVE is refused).
        let at = estimate(Some(DEFAULT_MAX_COST), None);
        assert_eq!(pg("cost").check(&at), Check::Ok);
        // off never blocks, never plans and never claims a verdict.
        assert_eq!(Guardrail::OFF.check(&est), Check::NoEstimate);
        assert_eq!(Guardrail::OFF.refuses(&est), None);
        assert!(!Guardrail::OFF.plans() && pg("cost").plans());
        // A missing number is not a free pass to "ok": it is "no estimate".
        assert_eq!(
            pg("cost").check(&estimate(None, Some(5))),
            Check::NoEstimate
        );
    }

    #[test]
    fn config_resolution_defaults_per_engine_and_fails_loud() {
        // Defaults: postgres -> cost, mysql/mariadb -> rows, sqlite -> off.
        assert_eq!(
            Guardrail::resolve("postgres", None, None, None)
                .unwrap()
                .mode,
            Mode::Cost
        );
        for engine in ["mysql", "mariadb"] {
            assert_eq!(
                Guardrail::resolve(engine, None, None, None).unwrap().mode,
                Mode::Rows
            );
        }
        assert_eq!(
            Guardrail::resolve("sqlite", None, None, None).unwrap().mode,
            Mode::Off
        );
        // Explicit thresholds win.
        let g = Guardrail::resolve("postgres", Some("cost"), Some(42.0), None).unwrap();
        assert_eq!(g.max_cost, 42.0);
        assert_eq!(g.max_rows, DEFAULT_MAX_ROWS);
        // A mode the engine cannot honor is a config error, never a silent
        // downgrade to "off" (that would be a false sense of protection).
        for (engine, mode) in [
            ("mysql", "cost"),
            ("mariadb", "cost"),
            ("sqlite", "cost"),
            ("sqlite", "rows"),
        ] {
            let err = Guardrail::resolve(engine, Some(mode), None, None).unwrap_err();
            assert!(err.contains("not supported"), "{engine}/{mode}: {err}");
            assert!(err.contains("off"), "{engine}/{mode}: {err}");
        }
        // ...but an explicit "off" is fine everywhere.
        for engine in ["sqlite", "mysql", "postgres", "redis"] {
            assert_eq!(
                Guardrail::resolve(engine, Some("off"), None, None)
                    .unwrap()
                    .mode,
                Mode::Off
            );
        }
        // A threshold the active mode never reads is a silent lie about being
        // protected -> config error naming the mode that WOULD read it.
        for (engine, mode, cost, rows) in [
            ("postgres", Some("rows"), Some(1.0), None),
            ("postgres", Some("off"), Some(1.0), None),
            ("postgres", Some("cost"), None, Some(1)),
            ("mysql", Some("off"), None, Some(1)),
            ("sqlite", None, Some(1.0), None),
        ] {
            let err = Guardrail::resolve(engine, mode, cost, rows).unwrap_err();
            assert!(err.contains("never reads it"), "{engine}/{mode:?}: {err}");
        }
        // Typos and thresholds that would refuse everything fail loud.
        assert!(Guardrail::resolve("postgres", Some("Cost"), None, None).is_err());
        assert!(Guardrail::resolve("postgres", Some("cheap"), None, None).is_err());
        assert!(Guardrail::resolve("postgres", None, Some(0.0), None).is_err());
        assert!(Guardrail::resolve("postgres", None, Some(-1.0), None).is_err());
        assert!(Guardrail::resolve("postgres", None, Some(f64::NAN), None).is_err());
        assert!(Guardrail::resolve("mysql", None, None, Some(0)).is_err());
    }

    #[test]
    fn describe_reports_the_threshold_that_actually_decided() {
        let g = Guardrail::resolve("postgres", Some("cost"), Some(100.0), None).unwrap();
        let e = g.describe(estimate(Some(250.0), Some(7)));
        assert_eq!((e.mode, e.verdict), ("cost", "expensive"));
        assert_eq!(e.threshold, Some(Value::from(100.0)));
        // rows mode reports the row threshold, as an integer.
        let g = Guardrail::resolve("mysql", None, None, Some(50)).unwrap();
        let e = g.describe(estimate(None, Some(7)));
        assert_eq!((e.mode, e.verdict), ("rows", "ok"));
        assert_eq!(e.threshold, Some(Value::from(50u64)));
        // Nothing compared -> no threshold is claimed.
        let e = Guardrail::OFF.describe(estimate(Some(1.0), Some(1)));
        assert_eq!(
            (e.mode, e.verdict, e.threshold),
            ("off", "no_estimate", None)
        );
    }

    /// D10: the refusal says what happened, and the way out is the HUMAN's
    /// config key — nyet ships no override flag on purpose (UX-7).
    #[test]
    fn refusal_texts_name_the_number_and_the_config_key() {
        let (message, hint) = pg("cost").refusal("prod", 2_500_000.0);
        assert!(
            message.contains("2500000") && message.contains("1000000"),
            "{message}"
        );
        assert!(message.contains("NOT executed"), "{message}");
        assert!(
            hint.contains("[connections.prod.guardrail] max_cost"),
            "{hint}"
        );
        let (message, hint) = mysql().refusal("shop", 2.0e10);
        assert!(hint.contains("max_rows"), "{hint}");
        assert!(message.contains("10000000"), "{message}");
    }
}
