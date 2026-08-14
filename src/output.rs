//! JSON envelope v1 and table rendering. Pure: values in, strings out.
//! Compact serialization only — agent tokens are the user's money.

use serde::Serialize;
use serde_json::Value;

/// Envelope version; bumped only on breaking contract changes.
const ENVELOPE_V: u8 = 1;

#[derive(Serialize)]
pub struct ConnectionInfo {
    pub alias: String,
    pub engine: String,
}

#[derive(Serialize)]
struct ListEnvelope<'a> {
    v: u8,
    ok: bool,
    connections: &'a [ConnectionInfo],
}

#[derive(Serialize)]
struct BareEnvelope {
    v: u8,
    ok: bool,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    v: u8,
    ok: bool,
    error: ErrorBody<'a>,
    /// Only on an `EXPENSIVE_QUERY` refusal: the plan the guardrail judged, so
    /// the agent can fix the query without a second round trip (UX-2).
    #[serde(skip_serializing_if = "Option::is_none")]
    estimate: Option<&'a Estimate>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    /// Only for validator refusals (`code = "NYET"`): the closed reason list.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    message: &'a str,
    // Mandatory: an error without an actionable hint does not ship (Д10).
    hint: &'a str,
}

/// Contract part: `warnings[].code` is a closed, append-only list.
#[derive(Serialize)]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

#[derive(Serialize)]
pub struct QueryMeta {
    pub row_count: u64,
    pub truncated: bool,
    pub duration_ms: u64,
    pub connection: String,
}

#[derive(Serialize)]
pub struct SchemaMeta {
    pub table_count: u64,
    pub duration_ms: u64,
    pub connection: String,
}

/// Above this many tables+views `nyet schema <alias>` answers with names and
/// kinds only (plus a `SCHEMA_TRUNCATED` warning): a full dump of a 500-table
/// database would burn the agent's context for nothing (UX-4). An output
/// policy, so it lives with the output model; not configurable on purpose
/// (Д5) — `nyet schema <alias> <table>` is the escape hatch.
pub const DETAIL_LIMIT: usize = 50;

/// `nyet schema` payload. The shape is the contract (Д7): fields are only
/// added, never renamed or dropped without a `v` bump.
#[derive(Serialize)]
pub struct Schema {
    pub tables: Vec<SchemaTable>,
}

impl Schema {
    /// True for the names-only answer past `DETAIL_LIMIT` — derived from the
    /// payload itself (no `columns` were collected) rather than carried as a
    /// second copy of the same state.
    pub fn is_listing(&self) -> bool {
        self.tables.first().is_some_and(|t| t.columns.is_none())
    }
}

#[derive(Serialize, Default)]
pub struct SchemaTable {
    pub name: String,
    /// `"table"` or `"view"` — and `"collection"` for MongoDB, which has no
    /// tables and where calling one a table would be the first small lie of an
    /// answer that is already an inference (UX-7).
    pub kind: &'static str,
    /// `None` in the names-only listing; views carry columns but never
    /// indexes/fks (the engines do not collect either for a view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<SchemaColumn>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub indexes: Vec<SchemaIndex>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fks: Vec<SchemaFk>,
    /// MongoDB only: how many documents the collection holds, from the
    /// collection's own metadata (`$collStats`), not from a scan. Absent when
    /// the role may not read it, and for views (which have no count of their
    /// own).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// MongoDB only: how many documents were actually sampled to infer the
    /// fields below. Its presence is the marker that some of this answer is a
    /// GUESS: read it together with each column's `source`/`seen`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled: Option<u32>,
}

/// `nullable` is always explicit (an agent writing a query needs it); the flags
/// are serialized only when true and `default` only when the engine reports one
/// — every omitted byte is the user's money (UX-4).
#[derive(Serialize, Default)]
pub struct SchemaColumn {
    pub name: String,
    /// The type as the engine reports it (pg `format_type`, MySQL
    /// `COLUMN_TYPE`, SQLite's declared type). For MongoDB: the BSON type
    /// name(s) — the same spelling `{$type: "..."}` takes — joined by `|` when
    /// the documents disagree.
    #[serde(rename = "type")]
    pub ty: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub pk: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub unique: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// `"deny"` / `"mask"` when this connection's `[pii]` policy covers the
    /// column, absent otherwise. Filled by `mark_pii` in the cli, never by an
    /// engine: the policy is config, not catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<&'static str>,
    /// Where this line comes from, and therefore how much it may be trusted.
    /// Absent for the SQL engines (a catalog IS the schema). MongoDB has no
    /// schema, so it says which of the two it is: `"validator"` — the
    /// collection's own declared `$jsonSchema`, a rule the SERVER enforces on
    /// every write; `"sample"` — inferred by nyet from `sampled` documents,
    /// i.e. a guess about the rest of the collection (UX-7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// `source = "sample"` only: in how many of the table's `sampled` documents
    /// this field was present. A field seen in 3 of 100 is not "a field of this
    /// collection" in the way a column is, and the agent has to be able to tell.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen: Option<u32>,
}

/// Mark the columns a PII policy covers, so the agent does not spend a round
/// trip discovering them by refusal (UX-2/UX-3). Runs on the schema the engine
/// already filtered by privilege, so a column the role cannot read is never
/// marked — it is not there at all.
///
/// `protects` is passed in rather than `PiiRules` so this module keeps its one
/// dependency (serde); the cli owns the policy and knows both.
pub fn mark_pii(schema: &mut Schema, mode: &'static str, protects: impl Fn(&str, &str) -> bool) {
    for table in &mut schema.tables {
        for column in table.columns.iter_mut().flatten() {
            if protects(&table.name, &column.name) {
                column.pii = Some(mode);
            }
        }
    }
}

/// What a masked cell reads as (`[connections.X.pii] mode = "mask"`). Deliberately
/// NOT configurable (Д5) and deliberately not a partial mask: `j***@gmail.com`
/// leaks the value piece by piece and a stable token is an equality oracle over
/// it, so the whole cell goes, in every type.
pub const REDACTED: &str = "[REDACTED]";

/// Replace every value of the listed COLUMNS with `REDACTED` (net B's masking
/// half — the indexes come from the provenance check, this is only the edit).
///
/// The replacement is the same string for every type, NULL included: leaving a
/// NULL as itself would answer "is this row's protected value set?" for every
/// row, which is exactly the oracle the mask exists to close. The JSON type of a
/// masked column therefore becomes `string` whatever the column's real type is —
/// an intended consequence, announced by the `PII_MASKED` warning.
pub fn redact(rows: &mut [Vec<Value>], columns: &[usize]) {
    for row in rows {
        for i in columns {
            if let Some(cell) = row.get_mut(*i) {
                *cell = Value::String(REDACTED.to_string());
            }
        }
    }
}

/// What an expression key part renders as when the catalog gives no text. Only
/// a serialization detail — the code tells key parts apart by type, never by
/// this string.
const EXPRESSION_KEY: &str = "(expression)";

/// One key part of an index. A type, not a magic string: the fold and the
/// privilege filter both have to tell a column name from an expression, and a
/// string cannot — a column may be literally named `(expression)`, and a
/// PostgreSQL expression text may read exactly like a column name.
pub enum KeyPart {
    /// A plain column of the table.
    Named(String),
    /// An expression key (`CREATE INDEX ... (lower(x))`). `Some` when the
    /// catalog hands over the expression text (PostgreSQL), `None` when it does
    /// not (SQLite, MySQL) — the part is still kept, or a two-part unique index
    /// would masquerade as a single-column one.
    Expression(Option<String>),
}

impl KeyPart {
    /// What the envelope shows for this part.
    pub fn text(&self) -> &str {
        match self {
            KeyPart::Named(name) => name,
            KeyPart::Expression(Some(text)) => text,
            KeyPart::Expression(None) => EXPRESSION_KEY,
        }
    }

    fn named(&self) -> Option<&str> {
        match self {
            KeyPart::Named(name) => Some(name),
            KeyPart::Expression(_) => None,
        }
    }
}

/// The wire format is a plain string per part — the type is internal only.
impl Serialize for KeyPart {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.text())
    }
}

#[derive(Serialize)]
pub struct SchemaIndex {
    pub name: String,
    pub columns: Vec<KeyPart>,
    /// Only set for an index that enforces uniqueness unconditionally: a
    /// partial/filtered or invalid unique index is reported without it (its
    /// uniqueness holds for some rows only).
    #[serde(skip_serializing_if = "is_false")]
    pub unique: bool,
}

#[derive(Serialize)]
pub struct SchemaFk {
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if shape
fn is_false(b: &bool) -> bool {
    !*b
}

/// The single owner of the pk/unique presentation rules, so the three engines
/// cannot drift — they differ only in how they read their catalog:
///
/// - every member of a (possibly composite) primary key gets `pk: true`;
/// - a unique index/constraint over exactly one *named* column becomes
///   `unique: true` on that column and its index entry is dropped (the flag
///   already says it);
/// - anything else stays an index entry, `unique` only when true.
///
/// Only an unconditional unique index reaches here with `unique: true` (the
/// engines clear it for partial/invalid ones), and only a `KeyPart::Named` part
/// can fold — an expression key never becomes a column flag, whatever its text
/// happens to look like.
///
/// The index that backs the PRIMARY KEY is dropped by the engines (each catalog
/// names it differently) — `indexes` arrives here already free of it.
///
/// `full_columns = false` says the column list may be incomplete — a PostgreSQL
/// or MySQL column-level `GRANT` — while the catalogs still report keys over
/// columns the role cannot read (`pg_index`/`pg_constraint` and MySQL's
/// STATISTICS/KEY_COLUMN_USAGE are not privilege-filtered). Then every key
/// touching an invisible column is dropped WHOLE (see `key_parts_visible`),
/// never shortened: a composite PRIMARY KEY missing its hidden half would read
/// as a one-column key — a wrong schema, which costs more than a missing one
/// (UX-1) — and a shortened index list would re-open the false fold.
pub fn build_table(
    name: String,
    kind: &'static str,
    mut columns: Vec<SchemaColumn>,
    pk: &[String],
    indexes: Vec<SchemaIndex>,
    fks: Vec<SchemaFk>,
    full_columns: bool,
) -> SchemaTable {
    let (pk, indexes, fks) = if full_columns {
        (pk, indexes, fks)
    } else {
        (
            if names_visible(pk, &columns) {
                pk
            } else {
                &[][..]
            },
            indexes
                .into_iter()
                .filter(|i| key_parts_visible(&i.columns, &columns))
                .collect(),
            // Only the child's own columns are checked here: `ref_table`/
            // `ref_columns` name the parent, which is a documented, accepted
            // exposure (the constraint belongs to this table's definition).
            fks.into_iter()
                .filter(|f| names_visible(&f.columns, &columns))
                .collect(),
        )
    };
    for column in &mut columns {
        column.pk = pk.contains(&column.name);
        // A primary-key column reads as non-nullable on every engine: Postgres
        // and MySQL enforce it, and SQLite's rowid alias auto-assigns a value
        // (its declared type carries no NOT NULL, which is why this is
        // normalized here — SQLite's legacy "NULL allowed in a non-rowid PK"
        // quirk is deliberately not represented).
        if column.pk {
            column.nullable = false;
        }
    }
    let mut kept = Vec::new();
    for index in indexes {
        let single = match index.columns.as_slice() {
            [part] => part.named(),
            _ => None,
        };
        let folded = index.unique
            && match single.and_then(|name| columns.iter_mut().find(|c| c.name == name)) {
                Some(column) => {
                    column.unique = true;
                    true
                }
                None => false,
            };
        if !folded {
            kept.push(index);
        }
    }
    SchemaTable {
        name,
        kind,
        columns: Some(columns),
        indexes: kept,
        fks,
        // Set by the MongoDB engine after the fold; no catalog has them.
        count: None,
        sampled: None,
    }
}

/// Plain column names (a primary key, a foreign key's own columns) against the
/// visible column list.
fn names_visible(names: &[String], columns: &[SchemaColumn]) -> bool {
    names
        .iter()
        .all(|name| columns.iter().any(|c| c.name == *name))
}

/// Can every part of this index key be shown when the column list is partial?
/// A `Named` part must be a visible column. An expression WITH text can carry
/// identifiers or literals from a column the role may not read, so it counts as
/// invisible; an expression without text names nothing at all and is harmless.
fn key_parts_visible(parts: &[KeyPart], columns: &[SchemaColumn]) -> bool {
    parts.iter().all(|part| match part {
        KeyPart::Named(name) => columns.iter().any(|c| c.name == *name),
        KeyPart::Expression(text) => text.is_none(),
    })
}

/// The `estimate` object of the envelope — the SAME shape in a `nyet explain`
/// success and in an `EXPENSIVE_QUERY` refusal, so an agent parses one thing.
/// Built by `guardrail::Guardrail::describe`.
#[derive(Serialize)]
pub struct Estimate {
    /// The connection's guardrail mode: `cost` | `rows` | `off`.
    pub mode: &'static str,
    /// `ok` (under the threshold) | `expensive` (above it, refused) |
    /// `no_estimate` (nothing was compared: mode `off`, an engine without
    /// estimates, or a plan that carried no usable number).
    pub verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    /// The limit the verdict was made against; absent when nothing was compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Value>,
    pub plan: Value,
}

#[derive(Serialize)]
pub struct ExplainMeta {
    pub duration_ms: u64,
    pub connection: String,
}

#[derive(Serialize)]
struct ExplainEnvelope<'a> {
    v: u8,
    ok: bool,
    /// Absent in the data-less (stderr) envelope of the table format.
    #[serde(skip_serializing_if = "Option::is_none")]
    estimate: Option<&'a Estimate>,
    meta: &'a ExplainMeta,
    #[serde(skip_serializing_if = "<[Warning]>::is_empty")]
    warnings: &'a [Warning],
}

pub fn explain_json(estimate: &Estimate, meta: &ExplainMeta, warnings: &[Warning]) -> String {
    to_json(&ExplainEnvelope {
        v: ENVELOPE_V,
        ok: true,
        estimate: Some(estimate),
        meta,
        warnings,
    })
}

pub fn explain_meta_json(meta: &ExplainMeta, warnings: &[Warning]) -> String {
    to_json(&ExplainEnvelope {
        v: ENVELOPE_V,
        ok: true,
        estimate: None,
        meta,
        warnings,
    })
}

/// Human rendering of a plan (the `table` format): the verdict line, then the
/// plan itself — one line per entry for the array-of-strings plans (SQLite),
/// indented JSON otherwise (the engines' own plan structures).
pub fn explain_text(estimate: &Estimate) -> String {
    let mut out = format!("verdict: {} (mode {})", estimate.verdict, estimate.mode);
    if let Some(cost) = estimate.cost {
        out.push_str(&format!("  cost {cost}"));
    }
    if let Some(rows) = estimate.rows {
        out.push_str(&format!("  rows {rows}"));
    }
    if let Some(threshold) = &estimate.threshold {
        out.push_str(&format!("  limit {threshold}"));
    }
    out.push('\n');
    out.push_str(&plan_text(&estimate.plan));
    out
}

fn plan_text(plan: &Value) -> String {
    match plan.as_array() {
        // SQLite: already one plain line per plan step.
        Some(lines) if lines.iter().all(Value::is_string) => lines
            .iter()
            .filter_map(Value::as_str)
            .map(|l| format!("{l}\n"))
            .collect(),
        // Serialization of our own already-parsed Value cannot fail; a
        // pretty-print that somehow did would still not be worth a panic.
        _ => serde_json::to_string_pretty(plan).unwrap_or_else(|_| plan.to_string()) + "\n",
    }
}

#[derive(Serialize)]
struct SchemaEnvelope<'a> {
    v: u8,
    ok: bool,
    /// Absent for the data-less (stderr) envelope of the table format.
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<&'a Schema>,
    meta: &'a SchemaMeta,
    #[serde(skip_serializing_if = "<[Warning]>::is_empty")]
    warnings: &'a [Warning],
}

pub fn schema_json(schema: &Schema, meta: &SchemaMeta, warnings: &[Warning]) -> String {
    to_json(&SchemaEnvelope {
        v: ENVELOPE_V,
        ok: true,
        schema: Some(schema),
        meta,
        warnings,
    })
}

pub fn schema_meta_json(meta: &SchemaMeta, warnings: &[Warning]) -> String {
    to_json(&SchemaEnvelope {
        v: ENVELOPE_V,
        ok: true,
        schema: None,
        meta,
        warnings,
    })
}

/// Human-readable rendering of a schema (the `table` format). One object per
/// block, columns aligned; agents get the json envelope.
pub fn schema_text(schema: &Schema) -> String {
    let mut out = String::new();
    for table in &schema.tables {
        out.push_str(&format!("{} {}", table.name, table.kind));
        if let Some(count) = table.count {
            out.push_str(&format!("  {count} documents"));
        }
        if let Some(sampled) = table.sampled {
            out.push_str(&format!("  ({sampled} sampled)"));
        }
        out.push('\n');
        let Some(columns) = &table.columns else {
            continue;
        };
        let name_w = columns.iter().map(|c| c.name.len()).max().unwrap_or(0);
        let type_w = columns.iter().map(|c| c.ty.len()).max().unwrap_or(0);
        for c in columns {
            let mut line = format!(
                "  {:name_w$}  {:type_w$}  {}",
                c.name,
                c.ty,
                if c.nullable { "null" } else { "not null" }
            );
            if c.pk {
                line.push_str("  pk");
            }
            if c.unique {
                line.push_str("  unique");
            }
            if let Some(d) = &c.default {
                line.push_str(&format!("  default {d}"));
            }
            if let Some(mode) = c.pii {
                line.push_str(&format!("  pii {mode}"));
            }
            // The provenance is never dropped from the human rendering either:
            // "seen in 3 of 100 sampled documents" is the whole difference
            // between a schema and a guess.
            match (c.source, c.seen) {
                (Some(source), Some(seen)) => line.push_str(&format!("  {source} {seen}")),
                (Some(source), None) => line.push_str(&format!("  {source}")),
                _ => {}
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        for index in &table.indexes {
            out.push_str(&format!(
                "  index{} {} ({})\n",
                if index.unique { " unique" } else { "" },
                index.name,
                index
                    .columns
                    .iter()
                    .map(KeyPart::text)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for fk in &table.fks {
            out.push_str(&format!(
                "  fk ({}) -> {} ({})\n",
                fk.columns.join(", "),
                fk.ref_table,
                fk.ref_columns.join(", ")
            ));
        }
    }
    out
}

/// `rows: None` is the data-less variant: for non-json formats the rows go
/// to stdout in their own format and this envelope goes to stderr.
#[derive(Serialize)]
struct QueryEnvelope<'a> {
    v: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<Rows<'a>>,
    meta: &'a QueryMeta,
    #[serde(skip_serializing_if = "<[Warning]>::is_empty")]
    warnings: &'a [Warning],
}

/// Rows serialized as objects with keys in column order (serde_json's own
/// Map would sort keys alphabetically — column order is part of the answer).
struct Rows<'a> {
    columns: &'a [String],
    rows: &'a [Vec<Value>],
}

impl Serialize for Rows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.rows.iter().map(|row| RowObject {
            columns: self.columns,
            row,
        }))
    }
}

struct RowObject<'a> {
    columns: &'a [String],
    row: &'a [Value],
}

impl Serialize for RowObject<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.columns.iter().zip(self.row))
    }
}

pub fn list_json(connections: &[ConnectionInfo]) -> String {
    to_json(&ListEnvelope {
        v: ENVELOPE_V,
        ok: true,
        connections,
    })
}

/// Data-less success envelope; goes to stderr for non-json data formats.
pub fn bare_success() -> String {
    to_json(&BareEnvelope {
        v: ENVELOPE_V,
        ok: true,
    })
}

/// `nyet agent-setup --format json`: the whole SKILL.md text inside the
/// envelope, for programmatic access. New append-only field `skill` (string);
/// serde escapes the markdown (newlines, quotes) into a valid JSON string.
#[derive(Serialize)]
struct SkillEnvelope<'a> {
    v: u8,
    ok: bool,
    skill: &'a str,
}

pub fn skill_json(skill: &str) -> String {
    to_json(&SkillEnvelope {
        v: ENVELOPE_V,
        ok: true,
        skill,
    })
}

pub fn error_json(
    code: &str,
    reason: Option<&str>,
    message: &str,
    hint: &str,
    estimate: Option<&Estimate>,
) -> String {
    to_json(&ErrorEnvelope {
        v: ENVELOPE_V,
        ok: false,
        error: ErrorBody {
            code,
            reason,
            message,
            hint,
        },
        estimate,
    })
}

pub fn query_json(
    columns: &[String],
    rows: &[Vec<Value>],
    meta: &QueryMeta,
    warnings: &[Warning],
) -> String {
    to_json(&QueryEnvelope {
        v: ENVELOPE_V,
        ok: true,
        rows: Some(Rows { columns, rows }),
        meta,
        warnings,
    })
}

pub fn query_meta_json(meta: &QueryMeta, warnings: &[Warning]) -> String {
    to_json(&QueryEnvelope {
        v: ENVELOPE_V,
        ok: true,
        rows: None,
        meta,
        warnings,
    })
}

/// jsonl data stream: one compact JSON object per row, keys in column order.
/// The envelope (without rows) goes to stderr — see emit() in the cli layer.
pub fn query_jsonl(columns: &[String], rows: &[Vec<Value>]) -> String {
    let mut out = String::new();
    for row in rows {
        out.push_str(&to_json(&RowObject { columns, row }));
        out.push('\n');
    }
    out
}

/// csv data stream: header + rows, RFC 4180 quoting (commas, quotes and
/// newlines in values), NULL as an empty field, \n record separator, plus
/// spreadsheet formula-injection defense (CWE-1236). ~20 lines by hand —
/// a csv crate is not worth the supply-chain surface (Д8).
pub fn query_csv(columns: &[String], rows: &[Vec<Value>]) -> String {
    if columns.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    // Headers and text cells can be attacker-influenced -> defuse formulas;
    // numbers/bool/NULL cannot be a formula, so they pass through verbatim
    // (defusing them would turn `-2` into the text `'-2`).
    let mut push_record = |fields: Vec<(String, bool)>| {
        let quoted: Vec<String> = fields
            .iter()
            .map(|(f, defuse)| csv_field(f, *defuse))
            .collect();
        out.push_str(&quoted.join(","));
        out.push('\n');
    };
    push_record(columns.iter().map(|c| (c.clone(), true)).collect());
    for row in rows {
        push_record(
            row.iter()
                .map(|v| (table_cell(v), matches!(v, Value::String(_))))
                .collect(),
        );
    }
    out
}

/// RFC 4180 quoting, plus (when `defuse`) spreadsheet formula-injection
/// defense (CWE-1236): database content can be attacker-influenced, and a
/// text value starting with `= + - @` (or a tab/CR that Excel trims to
/// reveal one) is executed as a formula on open. A leading `'` neutralizes
/// it — the standard mitigation — altering the value by one character; a
/// human-facing format trades exact fidelity for not running attacker
/// formulas. `defuse` is false for non-string cells (a number is never a
/// formula), so numeric output stays byte-exact.
fn csv_field(field: &str, defuse: bool) -> String {
    let defused = if defuse && field.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{field}")
    } else {
        field.to_string()
    };
    if defused.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", defused.replace('"', "\"\""))
    } else {
        defused
    }
}

pub fn query_table(columns: &[String], rows: &[Vec<Value>]) -> String {
    if columns.is_empty() {
        return String::new();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(table_cell).collect())
        .collect();
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, name)| {
            cells
                .iter()
                .map(|row| row[i].len())
                .max()
                .unwrap_or(0)
                .max(name.len())
        })
        .collect();
    let mut out = String::new();
    let mut push_row = |fields: Vec<&str>| {
        let line: Vec<String> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("{f:<width$}", width = widths[i]))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    };
    push_row(columns.iter().map(String::as_str).collect());
    for row in &cells {
        push_row(row.iter().map(String::as_str).collect());
    }
    out
}

/// NULL renders empty, strings render raw — the table is for human eyes;
/// agents get the json envelope.
fn table_cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn list_table(connections: &[ConnectionInfo]) -> String {
    let width = connections
        .iter()
        .map(|c| c.alias.len())
        .max()
        .unwrap_or(0)
        .max("ALIAS".len());
    let mut out = format!("{:width$}  ENGINE\n", "ALIAS");
    for c in connections {
        out.push_str(&format!("{:width$}  {}\n", c.alias, c.engine));
    }
    out
}

// ---------------------------------------------------------------------------
// nyet doctor — honest setup diagnostics (UX-7)
// ---------------------------------------------------------------------------

/// Which engine is being diagnosed. Drives the honest `na` messaging: SQLite
/// has no roles, no server and no network transport, so those checks do not
/// apply to it and nyet says so plainly instead of inventing a metric (UX-7).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Sqlite,
    Postgres,
    Mysql,
    /// MongoDB: roles and a network transport like the server engines, but
    /// layer 3 is read from the PRIVILEGES the server reports rather than
    /// probed with a write, and one check exists only here (`server_side_js`).
    Mongo,
}

/// Closed, append-only status list for a doctor check. `na` = the check does
/// not apply to this engine — never a faked pass, never a faked metric (UX-7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Na,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
            CheckStatus::Na => "na",
        }
    }
}

impl Serialize for CheckStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One diagnostic line. The shape is the contract (Д7): fields are only added,
/// never renamed or dropped without a `v` bump; `status` values are the closed
/// list above.
#[derive(Serialize)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: CheckStatus,
    pub message: String,
    /// Present for every `warn`/`fail` (Д10 — a diagnostic with no way forward
    /// is not a diagnostic) and omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Whether the connect attempt (through the ssh tunnel, if any) succeeded — a
/// FACT the engine gathers, turned into the `connectivity` check here.
pub enum ConnectFact {
    Ok { via_tunnel: bool },
    Failed { message: String, hint: String },
}

/// The layer-3 write probe result. The probe runs a write that is deliberately
/// NOT wrapped in nyet's layer-2 read-only session (the one place layer 2 is
/// removed), so it proves what the SERVER does with these very credentials.
///
/// Classification is the honesty crux (UX-1/UX-7): a KNOWN read-only refusal is
/// the only thing that reads as `ok`. Any other failure (connection loss,
/// timeout, name collision, ...) is `Unknown` -> `warn` ("could not verify"),
/// NOT a false `ok` — a false pass in a security tool is worse than a false warn.
pub enum ProbeFact {
    /// A KNOWN server read-only refusal — a direct connection is read-only. `ok`.
    /// `ddl_only` distinguishes the two sub-cases so the headline does not
    /// over-promise (UX-7): `false` = a read-only transaction / replica /
    /// read_only mode (the server rejects EVERY write); `true` = an access-denied
    /// on the probe CREATE, which proves only that the role lacks DDL — a role
    /// with table-level write grants but no CREATE would land here too.
    Blocked { detail: String, ddl_only: bool },
    /// The write succeeded — the role can write directly, bypassing every nyet
    /// layer. `fail`. `orphan` is the probe table that could not be cleaned up
    /// (MySQL only — PostgreSQL rolls back), surfaced for manual removal.
    Wrote { orphan: Option<String> },
    /// The write failed for a reason that does NOT prove read-only — could not
    /// verify. `warn`.
    Unknown { detail: String },
    /// MongoDB: no probe ran at all. `connectionStatus {showPrivileges: true}`
    /// lists every action these credentials hold on every resource of the
    /// cluster, so layer 3 is proven by ASKING — the only engine where nyet can
    /// answer "read-only" without writing a single byte.
    Grants(Box<Grants>),
}

/// What the privilege list said (MongoDB). Pure data: the verdict is made in
/// `mongo_grants_check` so it can be unit-tested without a server.
pub struct Grants {
    /// One entry per RESOURCE that carries write actions, as
    /// `"<resource> (<action>, <action>, ...)"` — wherever in the cluster it
    /// was granted. Capped for the agent's sake; the count below is honest.
    pub writes: Vec<String>,
    /// How many resources carry at least one write action.
    pub write_count: usize,
    /// Actions nyet cannot classify as read or write (a custom role, an action
    /// a newer MongoDB added). Not a pass: fail closed and name them. Capped
    /// like `writes`, with the honest total beside it.
    pub unknown: Vec<String>,
    pub unknown_count: usize,
    /// At least one write action covers the database this connection reads —
    /// or the whole cluster / every resource, which covers it too.
    pub this_database: bool,
    /// How many (resource, actions) entries the server listed.
    pub resources: usize,
    /// No user is authenticated on this connection at all.
    pub unauthenticated: bool,
}

/// Whether the SERVER evaluates JavaScript (`$where`, `$function`,
/// `$accumulator`, `mapReduce`). MongoDB only, and `None` for every other
/// engine — nyet does not probe it by running JavaScript, which is the very
/// thing it refuses to send (see `server_side_js_check`).
pub enum JsFact {
    /// The server runs with `--noscripting` / `security.javascriptEnabled:
    /// false`.
    Disabled,
    /// Scripting is on (MongoDB's default: the setting is simply absent).
    Enabled,
    /// nyet could not read the server's startup options — most often because a
    /// read-only role may not, which is the recommended setup.
    Unknown(String),
}

/// Whether the role is a superuser / holds dangerous global privileges. An
/// honesty-first four-way: a metadata failure is `Unknown` (-> `warn`), NEVER a
/// false `No`/`ok`; MySQL role/proxy grants nyet does not resolve are
/// `Unresolved` (-> `warn`), not a false `No`.
pub enum SuperuserFact {
    Yes(String),
    No(String),
    Unknown(String),
    /// MySQL only: the account has role/proxy grants nyet does not resolve, so
    /// its effective privileges are unknown — verify by hand.
    Unresolved(String),
}

/// Server-role facts. `None` for SQLite (no server) or when the connect failed.
pub struct ServerFacts {
    pub superuser: SuperuserFact,
    /// Why writes are (or may be) refused — a replica, a read-only default —
    /// folded into the `read_only_role` ok message when the probe was blocked.
    pub read_only_note: Option<String>,
    pub probe: ProbeFact,
    /// MongoDB only; `None` on every other engine (there is no server-side
    /// JavaScript to ask about).
    pub js: Option<JsFact>,
}

/// One `[pii]`-protected column, and whether the ROLE nyet connects as can read
/// it straight from the server. `None` = the server would not say (the object
/// does not exist under that name for this account, or the privilege query
/// failed) — reported as "could not verify", never as a pass (UX-1).
#[derive(Clone)]
pub struct PiiAccess {
    /// `table.column`, as the policy spells it.
    pub column: String,
    pub readable: Option<bool>,
}

pub struct Diagnosis {
    pub connect: ConnectFact,
    pub server: Option<ServerFacts>,
    /// One entry per configured PII rule; empty when the connection has no
    /// `[pii]` policy (or the engine has no privileges to ask about).
    pub pii: Vec<PiiAccess>,
    /// Views (and materialized views) that read a protected column and that
    /// THIS role may select from. A `[pii]` rule is keyed to a relation name,
    /// so a view over the protected table is a legitimate way around it — the
    /// policy simply does not apply to a name it was not given. Empty means
    /// "asked and found none"; `None` means the question was not asked (an
    /// engine or a server version that cannot answer it).
    pub pii_views: Option<Vec<String>>,
}

/// Transport guarantee, computed by the cli from the connection config alone.
pub enum Transport {
    Tunnel,
    TlsDirect,
    InsecureDirect,
    Na,
}

/// Config-file permission fact, computed by the cli from the file mode.
pub enum Permissions {
    Secure,
    Loose(String),
    Na,
}

/// Everything `doctor_checks` needs: engine facts plus the two the cli computes
/// without the database (transport guarantee, config-file permissions).
/// What the SSH tunnel left behind, when the connection has one. Gathered by the
/// cli from the live `Tunnel` guard.
pub struct ForwardFact {
    pub local_port: u16,
    /// The forward was already there — this run spawned no `ssh` to set it up.
    pub reused: bool,
    /// Age of the forward, when it is one that outlives the process.
    pub age_secs: Option<u64>,
    /// The command that removes it; `None` when nothing is left behind.
    pub kill_command: Option<String>,
}

pub struct DoctorInput {
    pub engine: EngineKind,
    pub diagnosis: Diagnosis,
    pub transport: Transport,
    /// `None` when the connection has no `[ssh]` section (no check emitted).
    pub forward: Option<ForwardFact>,
    pub permissions: Permissions,
    /// Whether the connection has a `[pii]` policy at all, and in which mode —
    /// config, so the cli computes it (the engine only reports privileges).
    pub pii_mode: Option<&'static str>,
    /// Where this connection's password comes from, when it has one. Reported
    /// as a plain fact, never a warning: an env var on a dev database is a
    /// deliberate choice, not a defect.
    pub secret: Option<SecretFact>,
}

/// What stands between the stored password and any other process running as
/// this user. Named after the property that matters, not after the vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFact {
    /// Written in the config file itself.
    InConfig,
    /// macOS Keychain: the OS checks the caller's code signature, so nyet can
    /// read it and another process of the same user cannot (without the human
    /// answering a keychain prompt).
    CallerVerified,
    /// An env var or a command: whatever nyet can read this way, so can any
    /// other process of this user — the agent included.
    Unguarded,
}

fn ok_check(name: &'static str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name,
        status: CheckStatus::Ok,
        message: message.into(),
        hint: None,
    }
}

fn na_check(name: &'static str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name,
        status: CheckStatus::Na,
        message: message.into(),
        hint: None,
    }
}

fn warn_check(
    name: &'static str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name,
        status: CheckStatus::Warn,
        message: message.into(),
        hint: Some(hint.into()),
    }
}

fn fail_check(
    name: &'static str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name,
        status: CheckStatus::Fail,
        message: message.into(),
        hint: Some(hint.into()),
    }
}

/// The full per-connection diagnosis (`nyet doctor <alias>`): compare the facts
/// with the expectation and build the verdicts. PURE (Д1) — unit-tested with no
/// database. Order is the contract's presentation order.
pub fn doctor_checks(input: &DoctorInput) -> Vec<DoctorCheck> {
    vec![
        connectivity_check(&input.diagnosis.connect, input.engine),
        transport_check(&input.transport),
        read_only_role_check(input),
        not_superuser_check(input),
    ]
    .into_iter()
    // Engine-specific checks are emitted only where they mean something: a
    // `na` line on every other engine would be noise (UX-4), and the closed
    // list of check NAMES is append-only either way (Д7).
    .chain((input.engine == EngineKind::Mongo).then(|| server_side_js_check(input)))
    // Only when there IS a policy: a check that reports `na` on every
    // connection without `[pii]` is pure noise in the common case (UX-4).
    .chain(input.forward.as_ref().map(ssh_forward_check))
    .chain(input.pii_mode.map(|mode| pii_columns_check(input, mode)))
    .chain(input.secret.map(secret_source_check))
    .chain(
        input
            .pii_mode
            .and(input.diagnosis.pii_views.as_ref())
            .map(|views| pii_views_check(views)),
    )
    .chain([permissions_check(&input.permissions)])
    .collect()
}

/// What the tunnel left running, and how to get rid of it. A forward that
/// outlives the process is the deal that makes the next call cheap, so it is
/// `ok` — but an `ok` that names the port, its age and the exact removal command,
/// because "it is discoverable" is an empty word without a way to look and kill
/// (UX-7).
fn ssh_forward_check(f: &ForwardFact) -> DoctorCheck {
    let Some(kill) = &f.kill_command else {
        return ok_check(
            "ssh_forward",
            format!(
                "the SSH forward on 127.0.0.1:{} is removed when this command exits, so every \
                 call pays two ssh spawns to set it up and take it down (reuse_forward = false, \
                 control_persist = \"no\", or no reusable ControlMaster here)",
                f.local_port
            ),
        );
    };
    let state = match (f.reused, f.age_secs) {
        (true, Some(age)) => format!("reused, opened {} ago", human_age(age)),
        (true, None) => "reused".to_string(),
        (false, _) => "opened by this command".to_string(),
    };
    ok_check(
        "ssh_forward",
        format!(
            "the SSH forward on 127.0.0.1:{} ({state}) is kept for the next `nyet` call and dies \
             with its ControlMaster (control_persist); while it lives, any local process can \
             reach the database through that loopback port. Remove it now with: {kill}",
            f.local_port
        ),
    )
}

fn human_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s => format!("{}h", s / 3600),
    }
}

/// Are the columns the config marks as PII actually out of the role's reach?
///
/// The honest answer matters more than the comfortable one (UX-7): if the role
/// CAN read them, nyet's `[pii]` policy is the ONLY thing standing between the
/// agent and that data — one `psql` away from being irrelevant (threat model:
/// an agent with shell access walks around nyet). That is a `warn` with the
/// server-side recipe, not a `fail`: the policy still works for every query that
/// goes through nyet, which is what the config owner asked for.
fn pii_columns_check(input: &DoctorInput, mode: &'static str) -> DoctorCheck {
    if input.engine == EngineKind::Mongo {
        // Not `na` like SQLite: the boundary CAN be made the server's, just not
        // with field-level grants — so this is an actionable warn, not a shrug.
        return warn_check(
            "pii_columns",
            format!(
                "MongoDB has no field-level privileges, so nyet cannot verify (and the \
                 server does not enforce) that this role is kept away from the protected \
                 fields: the [pii] policy (mode = \"{mode}\") is the only layer on this \
                 connection"
            ),
            "make the boundary the server's: create a view that removes the protected \
             fields (db.createView(\"<name>\", \"<collection>\", [{ $unset: [<the \
             fields>] }])) and grant the role find on the VIEW only, not on the \
             collection; the [pii] policy then becomes a second, local layer instead of \
             the only one",
        );
    }
    if input.engine == EngineKind::Sqlite {
        return na_check(
            "pii_columns",
            format!(
                "SQLite has no roles or column privileges, so the marked columns cannot be made \
                 unreadable at the database level: nyet's [pii] policy (mode = \"{mode}\") is the \
                 only thing between an agent and this data, and anything that opens the file \
                 directly reads it in full"
            ),
        );
    }
    if input.diagnosis.server.is_none() {
        return warn_check(
            "pii_columns",
            "could not verify: there is no connection to the database",
            "fix the connectivity check above, then re-run nyet doctor",
        );
    }
    let readable: Vec<&str> = input
        .diagnosis
        .pii
        .iter()
        .filter(|c| c.readable == Some(true))
        .map(|c| c.column.as_str())
        .collect();
    let unknown: Vec<&str> = input
        .diagnosis
        .pii
        .iter()
        .filter(|c| c.readable.is_none())
        .map(|c| c.column.as_str())
        .collect();
    if !readable.is_empty() {
        return warn_check(
            "pii_columns",
            format!(
                "the role can read {} of the {} marked column(s) directly ({}): nyet refuses or \
                 masks them (mode = \"{mode}\"), but the database itself does not — anything \
                 connecting with these credentials outside nyet gets the real values",
                readable.len(),
                input.diagnosis.pii.len(),
                readable.join(", ")
            ),
            "make the boundary the database's: REVOKE SELECT ON <table> FROM <role> and GRANT \
             SELECT (<the columns the agent may read>) ON <table> TO <role> (PostgreSQL/MySQL \
             both support column-level grants), or expose a curated view and grant only that. \
             The [pii] policy then becomes a second, local layer instead of the only one",
        );
    }
    if !unknown.is_empty() {
        return warn_check(
            "pii_columns",
            format!(
                "could not verify {} of the {} marked column(s) ({}): the database would not \
                 answer whether this role may read them — most often the table or column does \
                 not exist under that name for this account",
                unknown.len(),
                input.diagnosis.pii.len(),
                unknown.join(", ")
            ),
            "check the spelling against `nyet schema <alias>` — a rule that names a column which \
             is not there protects nothing; if the name is right, the account may lack any \
             privilege on the table at all, which is the safe case",
        );
    }
    ok_check(
        "pii_columns",
        format!(
            "the role cannot read any of the {} marked column(s) directly — the database enforces \
             the same boundary the [pii] policy (mode = \"{mode}\") does",
            input.diagnosis.pii.len()
        ),
    )
}

/// The config-level diagnosis (`nyet doctor` with no alias): the file
/// permissions plus which connections are reachable from here.
pub fn doctor_config_checks(permissions: &Permissions, aliases: &[String]) -> Vec<DoctorCheck> {
    let connections = if aliases.is_empty() {
        warn_check(
            "connections",
            "no connections are reachable from this directory",
            "cd into a directory listed in a connection's allowed_dirs, or run \
             `nyet doctor <alias>` to diagnose a specific connection regardless of directory",
        )
    } else {
        ok_check(
            "connections",
            format!(
                "{} connection(s) reachable from here: {} — run `nyet doctor <alias>` for a \
                 full per-connection diagnosis",
                aliases.len(),
                aliases.join(", ")
            ),
        )
    };
    vec![connections, permissions_check(permissions)]
}

fn connectivity_check(connect: &ConnectFact, engine: EngineKind) -> DoctorCheck {
    match connect {
        ConnectFact::Ok { via_tunnel } => ok_check(
            "connectivity",
            match (engine, via_tunnel) {
                (EngineKind::Sqlite, _) => "opened the SQLite database file read-only".to_string(),
                (_, true) => "connected to the database through the SSH tunnel".to_string(),
                (_, false) => "connected to the database".to_string(),
            },
        ),
        ConnectFact::Failed { message, hint } => {
            fail_check("connectivity", message.clone(), hint.clone())
        }
    }
}

fn transport_check(transport: &Transport) -> DoctorCheck {
    match transport {
        Transport::Tunnel => ok_check(
            "transport_encrypted",
            "traffic to the bastion is encrypted by the SSH tunnel (the bastion→database hop \
             is a separate plaintext TCP connection — keep the database on a segment trusted \
             relative to the bastion)",
        ),
        Transport::TlsDirect => ok_check(
            "transport_encrypted",
            "the direct connection requires TLS (the url's sslmode/ssl-mode is require or stricter)",
        ),
        Transport::InsecureDirect => warn_check(
            "transport_encrypted",
            "the transport is not guaranteed encrypted or verified: the url's \
             sslmode/ssl-mode/tls is below require and there is no ssh tunnel, so nyet may talk \
             to the server in plaintext",
            "set sslmode=verify-full (Postgres), ssl-mode=VERIFY_IDENTITY (MySQL) or tls=true \
             (MongoDB) in the url to encrypt and authenticate the connection, or route it \
             through an ssh tunnel",
        ),
        Transport::Na => na_check(
            "transport_encrypted",
            "SQLite is a local file — there is no network transport to encrypt",
        ),
    }
}

fn read_only_role_check(input: &DoctorInput) -> DoctorCheck {
    if input.engine == EngineKind::Sqlite {
        return na_check(
            "read_only_role",
            "SQLite has no database roles; nyet opens the file read-only (mode=ro), so there \
             is no role to make read-only — layer 3 does not apply",
        );
    }
    match &input.diagnosis.server {
        None => warn_check(
            "read_only_role",
            "could not verify: there is no connection to the database",
            "fix the connectivity check above, then re-run nyet doctor",
        ),
        Some(server) => match &server.probe {
            // MongoDB: no probe write ever ran — the verdict comes from the
            // privilege list the server itself published for these credentials.
            ProbeFact::Grants(grants) => mongo_grants_check(grants),
            ProbeFact::Blocked { detail, ddl_only } => {
                // Honest headline (UX-7): only a real read-only refusal claims
                // "every write is rejected"; an access-denied on CREATE proves
                // only the DDL right is missing, so it says so.
                let mut message = if *ddl_only {
                    format!(
                        "the server refused a probe CREATE with these credentials (probe: {detail}) \
                         — this proves the role cannot run DDL (CREATE), but DML write capability \
                         (INSERT/UPDATE/DELETE on existing tables) was NOT separately probed: a \
                         role with table-level write grants but no CREATE would also read as ok here"
                    )
                } else {
                    format!(
                        "the server refused a probe write with these credentials, so an agent that \
                         bypassed nyet and connected directly would still be read-only (probe: {detail})"
                    )
                };
                if let Some(note) = &server.read_only_note {
                    message.push_str(&format!("; {note}"));
                }
                ok_check("read_only_role", message)
            }
            ProbeFact::Wrote { orphan } => {
                let mut message = "these credentials CAN write to the database directly: a probe \
                     CREATE TABLE succeeded, so an agent with shell access could bypass nyet and \
                     modify data — layer 3 is not in place"
                    .to_string();
                if let Some(name) = orphan {
                    // "may remain", not "does remain": a transport loss AFTER a
                    // successful server-side DROP means the outcome is unknown, not
                    // that the table is definitely still there (symmetric with the
                    // lost-ACK CREATE wording).
                    message.push_str(&format!(
                        " (the cleanup DROP of the probe table `{name}` was not acknowledged — it \
                         may remain in the database, so check for it and DROP it manually)"
                    ));
                }
                fail_check("read_only_role", message, read_only_role_hint(input.engine))
            }
            // NOT ok: an error that does not prove read-only is "could not
            // verify", never a false pass (UX-1 — a false ok is the worst outcome
            // for a security tool).
            ProbeFact::Unknown { detail } => warn_check(
                "read_only_role",
                format!(
                    "could not verify the server rejects writes with these credentials: {detail}"
                ),
                "check connectivity and the account's privileges, re-run nyet doctor, or verify by \
                 hand that a direct write is refused",
            ),
        },
    }
}

/// The MongoDB `read_only_role` verdict, from the privilege list alone.
///
/// The rule is fail-closed twice over. It looks at EVERY resource the server
/// listed, not just this connection's database — measured: a role that is
/// `read` on `app` and `readWrite` on `scratch` can copy a whole collection out
/// of `app` with `$out: {db: "scratch", ...}`. nyet's own layer 1 refuses
/// `$out`, but doctor's job is the SETUP, and a role wider than the reads it
/// serves is a finding whatever nyet does with it. And an action nyet cannot
/// classify is reported, never assumed harmless: the list of write actions
/// grows with every MongoDB release.
fn mongo_grants_check(g: &Grants) -> DoctorCheck {
    // No authenticated user at all. Not "could not verify": there is provably
    // no read-only role in place, because there is no role in place.
    if g.unauthenticated {
        return fail_check(
            "read_only_role",
            "no user is authenticated on this connection, so there is no role that could be \
             read-only — and a MongoDB server that serves an unauthenticated client is one \
             where any client on the network can also write",
            mongo_read_only_hint(),
        );
    }
    let shown = |list: &[String]| list.join(", ");
    if g.write_count > 0 {
        let where_ = if g.this_database {
            "including the database this connection reads"
        } else {
            "in another database of the same cluster — from which `$out`/`$merge` can copy \
             this connection's data out (nyet refuses those stages, another client does not)"
        };
        let message = format!(
            "these credentials hold write actions on {} resource(s) {where_}: {}{} — an agent \
             that bypassed nyet and connected directly could modify data, and MongoDB has no \
             read-only session to fall back on, so this role IS the whole of layer 3",
            g.write_count,
            shown(&g.writes),
            if g.write_count > g.writes.len() {
                ", ..."
            } else {
                ""
            }
        );
        return if g.this_database {
            fail_check("read_only_role", message, mongo_read_only_hint())
        } else {
            warn_check("read_only_role", message, mongo_read_only_hint())
        };
    }
    if !g.unknown.is_empty() {
        return warn_check(
            "read_only_role",
            format!(
                "no known write action is granted, but nyet cannot classify {} action(s), \
                 among them {}{}: they are not on its list of read actions either, so it will \
                 not call this role read-only",
                g.unknown_count,
                shown(&g.unknown),
                if g.unknown_count > g.unknown.len() {
                    ", ..."
                } else {
                    ""
                }
            ),
            "check what that action allows (`db.getRole(<role>, {showPrivileges: true})`); if \
             the account only needs to read, replace its roles with a plain \
             { role: \"read\", db: \"<db>\" }",
        );
    }
    ok_check(
        "read_only_role",
        format!(
            "the server reports only read actions for these credentials on all {} resource(s) \
             it listed, so a client that bypassed nyet with them would still be read-only \
             (proven from connectionStatus — nyet writes nothing to find this out)",
            g.resources
        ),
    )
}

/// Server-side JavaScript (`$where`, `$function`, `$accumulator`, `mapReduce`).
///
/// nyet refuses all of it in layer 1, so this check is not about nyet: it is
/// about everything ELSE holding the same credentials. The honest part is the
/// `Unknown` arm — reading the server's startup options needs a privilege the
/// recommended read-only role does not have, and nyet will NOT probe by
/// running a piece of JavaScript, because sending JavaScript to the server is
/// exactly what it promises never to do (UX-7).
fn server_side_js_check(input: &DoctorInput) -> DoctorCheck {
    let why = "the plain `read` role is allowed to run $where/$function/$accumulator, and \
               maxTimeMS does not budget them (measured: 8 s and 12 s under a 500 ms limit), so \
               they are arbitrary code in the database process with no time bound";
    let hint = "restart mongod with --noscripting (or security.javascriptEnabled: false) if \
                nothing on this server needs stored/aggregation JavaScript — nyet's own refusal \
                protects only what goes through nyet";
    let Some(server) = &input.diagnosis.server else {
        return warn_check(
            "server_side_js",
            "could not verify: there is no connection to the database",
            "fix the connectivity check above, then re-run nyet doctor",
        );
    };
    match &server.js {
        Some(JsFact::Disabled) => ok_check(
            "server_side_js",
            "the server runs with scripting disabled (--noscripting), so $where / $function / \
             $accumulator / mapReduce are refused by MongoDB itself — for every client, not \
             just for nyet",
        ),
        Some(JsFact::Enabled) => warn_check(
            "server_side_js",
            format!(
                "server-side JavaScript is ENABLED on this server: {why}. nyet never sends it \
                 (its allowlist refuses $where/$function/$accumulator/mapReduce), but any \
                 other client using these credentials can"
            ),
            hint,
        ),
        // "Could not check" is never an `ok` (UX-1).
        other => {
            let detail = match other {
                Some(JsFact::Unknown(detail)) => detail.as_str(),
                _ => "nyet did not ask this server",
            };
            warn_check(
                "server_side_js",
                format!(
                    "could not check whether server-side JavaScript is enabled ({detail}). \
                     MongoDB exposes no runtime parameter for it, and nyet will not probe by \
                     RUNNING JavaScript — that is the one thing it promises never to send. It \
                     matters because {why}"
                ),
                "ask the server's operator whether mongod runs with --noscripting; if it does \
                 not, adding it costs nothing unless something on the server needs JavaScript",
            )
        }
    }
}

/// The MongoDB layer-3 remedy (Д10), straight from the README recipe.
fn mongo_read_only_hint() -> String {
    "create a read-only user for exactly this database and point the url at it:\n\
     use <db>\n\
     db.createUser({ user: \"nyet_ro\", pwd: \"...\", roles: [ { role: \"read\", db: \"<db>\" } ] })\n\
     — no role on any other database, because a write grant ANYWHERE in the cluster is a way \
     out for this connection's data ($out/$merge). MongoDB has no read-only session (layer 2), \
     so this role is the only server-side barrier."
        .to_string()
}

fn not_superuser_check(input: &DoctorInput) -> DoctorCheck {
    if input.engine == EngineKind::Sqlite {
        return na_check("not_superuser", "SQLite has no roles or superuser concept");
    }
    match &input.diagnosis.server {
        None => warn_check(
            "not_superuser",
            "could not verify: there is no connection to the database",
            "fix the connectivity check above, then re-run nyet doctor",
        ),
        Some(server) => match &server.superuser {
            SuperuserFact::Yes(detail) => fail_check(
                "not_superuser",
                format!(
                    "{detail}: a superuser / all-privileges role has full administrative power and \
                     bypasses every read-only layer"
                ),
                not_superuser_hint(input.engine),
            ),
            SuperuserFact::No(detail) => {
                ok_check("not_superuser", format!("the role is not a superuser ({detail})"))
            }
            // Unknown metadata is NOT ok (UX-1): say so and point at the fix.
            SuperuserFact::Unknown(detail) => warn_check(
                "not_superuser",
                format!("could not determine superuser status: {detail}"),
                "check connectivity and re-run nyet doctor, or verify the role's privileges by hand",
            ),
            // Roles/proxy grants nyet does not resolve: honestly incomplete, not
            // a false pass (Д5 — no role resolver, just flag the gap).
            SuperuserFact::Unresolved(detail) => warn_check(
                "not_superuser",
                detail.clone(),
                "nyet checks direct grants only — verify the effective (role/proxy) privileges by \
                 hand, and prefer an account with only the SELECT grants the agent needs",
            ),
        },
    }
}

/// A statement of fact, deliberately never a warning (UX-7 honesty without
/// nagging): only the human knows whether this database's password is worth
/// keeping out of reach of their own agent.
fn secret_source_check(secret: SecretFact) -> DoctorCheck {
    match secret {
        SecretFact::CallerVerified => ok_check(
            "secret_source",
            "the password comes from the keychain, which hands it to nyet and to no other \
             process of this user without asking you first",
        ),
        SecretFact::Unguarded => na_check(
            "secret_source",
            "the password comes from an environment variable or a command, so any process \
             running as you can read it just as easily — the agent included; on macOS \
             `nyet secret-set <item>` plus password = { keychain = \"<item>\" } keeps it \
             out of their reach",
        ),
        SecretFact::InConfig => na_check(
            "secret_source",
            "the password is written in the config file, so anything that can read the \
             file has it — the agent included; on macOS `nyet secret-set <item>` plus \
             password = { keychain = \"<item>\" } keeps it out of their reach",
        ),
    }
}

/// A `[pii]` rule names one relation, so a view over the protected table is not
/// covered by it — and unlike the oracle channels, this one hands over the
/// value itself. nyet cannot fix that for the human (widening the policy to
/// every dependent view would be nyet deciding what their data model means),
/// but it can refuse to let them find out the hard way.
fn pii_views_check(views: &[String]) -> DoctorCheck {
    if views.is_empty() {
        return ok_check(
            "pii_views",
            "no view this role can read exposes a protected column",
        );
    }
    warn_check(
        "pii_views",
        format!(
            "the [pii] policy is keyed to the table it names, so these views over a \
             protected column are NOT covered and this role can read them: {}",
            views.join(", ")
        ),
        "name each view in [pii] columns as well (\"<view>.<column>\"), or revoke this \
         role's SELECT on it — a rule on the table does not follow the data into a view",
    )
}

fn permissions_check(permissions: &Permissions) -> DoctorCheck {
    match permissions {
        Permissions::Secure => ok_check(
            "config_permissions",
            "the config file is readable only by its owner (mode 0600)",
        ),
        Permissions::Loose(message) => warn_check(
            "config_permissions",
            message.clone(),
            "run `chmod 600` on the config file so only you can read it — it may hold credentials",
        ),
        Permissions::Na => na_check(
            "config_permissions",
            "config-file permission checks are not available on this platform",
        ),
    }
}

/// The layer-3 remedy per engine, straight from the README recipe (Д10).
fn read_only_role_hint(engine: EngineKind) -> String {
    match engine {
        EngineKind::Postgres => {
            "create a read-only role and point the url at it:\n\
             CREATE ROLE nyet_ro LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE;\n\
             GRANT CONNECT ON DATABASE <db> TO nyet_ro;\n\
             GRANT USAGE ON SCHEMA public TO nyet_ro;\n\
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO nyet_ro;\n\
             ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO nyet_ro;\n\
             (see the README layer-3 recipe)"
        }
        EngineKind::Mysql => {
            "create a SELECT-only user and point the url at it:\n\
             CREATE USER 'nyet_ro'@'%' IDENTIFIED BY '...';\n\
             GRANT SELECT ON app.* TO 'nyet_ro'@'%';\n\
             FLUSH PRIVILEGES;\n\
             (see the README layer-3 recipe)"
        }
        // Never reached: MongoDB answers through `mongo_grants_check`, which
        // carries its own recipe, and SQLite short-circuits to `na` above.
        EngineKind::Mongo | EngineKind::Sqlite => {
            "open the SQLite file read-only (nyet already does)"
        }
    }
    .to_string()
}

fn not_superuser_hint(engine: EngineKind) -> String {
    match engine {
        EngineKind::Postgres => {
            "use a dedicated NOSUPERUSER role with only the SELECT grants the agent needs \
             (see the read-only role recipe in the README), not a superuser"
        }
        EngineKind::Mysql => {
            "grant only SELECT on the specific database(s) the agent needs; do not use an \
             account with ALL PRIVILEGES ON *.* or SUPER"
        }
        EngineKind::Mongo => {
            "use an account whose only role is { role: \"read\", db: \"<db>\" } on the database \
             in the url — root / dbOwner / userAdminAnyDatabase and friends can grant \
             themselves anything, so no other layer can hold"
        }
        EngineKind::Sqlite => "not applicable to SQLite",
    }
    .to_string()
}

#[derive(Serialize)]
pub struct DoctorMeta {
    /// Absent for the config-level (`nyet doctor` with no alias) run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    pub duration_ms: u64,
}

#[derive(Serialize)]
struct DoctorEnvelope<'a> {
    v: u8,
    ok: bool,
    /// Absent in the data-less (stderr) envelope of the table format.
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<&'a [DoctorCheck]>,
    meta: &'a DoctorMeta,
}

pub fn doctor_json(checks: &[DoctorCheck], meta: &DoctorMeta) -> String {
    to_json(&DoctorEnvelope {
        v: ENVELOPE_V,
        // doctor ran, so the envelope is a success; the per-check verdicts live
        // in `checks`, and even a `fail` there is exit 0 (a diagnosis, not a
        // refusal).
        ok: true,
        checks: Some(checks),
        meta,
    })
}

pub fn doctor_meta_json(meta: &DoctorMeta) -> String {
    to_json(&DoctorEnvelope {
        v: ENVELOPE_V,
        ok: true,
        checks: None,
        meta,
    })
}

/// Human rendering of the checks (the default `table` format): one aligned line
/// per check, with each warn/fail hint on indented continuation lines.
pub fn doctor_text(checks: &[DoctorCheck]) -> String {
    let name_w = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in checks {
        out.push_str(&format!(
            "{:<6}{:<name_w$}  {}\n",
            c.status.as_str(),
            c.name,
            c.message
        ));
        if let Some(hint) = &c.hint {
            for line in hint.lines() {
                out.push_str(&format!("{:<6}{:<name_w$}  → {line}\n", "", ""));
            }
        }
    }
    out
}

fn to_json<T: Serialize>(value: &T) -> String {
    // Internal invariant (fail-fast, Д3): serde_json only fails on non-string
    // map keys / failing Serialize impls; ours are plain structs.
    serde_json::to_string(value).expect("envelope serialization cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_envelope_is_compact_and_stable() {
        let items = [ConnectionInfo {
            alias: "prod".into(),
            engine: "postgres".into(),
        }];
        assert_eq!(
            list_json(&items),
            r#"{"v":1,"ok":true,"connections":[{"alias":"prod","engine":"postgres"}]}"#
        );
        assert_eq!(list_json(&[]), r#"{"v":1,"ok":true,"connections":[]}"#);
    }

    #[test]
    fn error_envelope_is_compact_and_stable() {
        assert_eq!(
            error_json("CONFIG_INVALID", None, "boom", "fix it", None),
            r#"{"v":1,"ok":false,"error":{"code":"CONFIG_INVALID","message":"boom","hint":"fix it"}}"#
        );
    }

    #[test]
    fn skill_envelope_wraps_the_markdown_and_escapes_it() {
        // A markdown fragment with the two characters that must be escaped in a
        // JSON string — a newline and a double quote — serialized into `skill`.
        assert_eq!(
            skill_json("---\nname: nyet\n\"ok\":true"),
            r#"{"v":1,"ok":true,"skill":"---\nname: nyet\n\"ok\":true"}"#
        );
    }

    #[test]
    fn nyet_refusal_envelope_carries_reason() {
        assert_eq!(
            error_json("NYET", Some("WRITE_OPERATION"), "no", "rewrite", None),
            r#"{"v":1,"ok":false,"error":{"code":"NYET","reason":"WRITE_OPERATION","message":"no","hint":"rewrite"}}"#
        );
    }

    fn plan() -> Value {
        serde_json::json!([{"Plan": {"Node Type": "Seq Scan", "Total Cost": 2500000.0}}])
    }

    fn expensive() -> Estimate {
        Estimate {
            mode: "cost",
            verdict: "expensive",
            cost: Some(2_500_000.0),
            rows: Some(9_000_000),
            threshold: Some(Value::from(1_000_000.0)),
            plan: plan(),
        }
    }

    /// The guardrail refusal: a normal NYET envelope PLUS the plan that
    /// justified it, so the agent can fix the query without asking again.
    #[test]
    fn expensive_query_refusal_envelope_carries_the_plan() {
        assert_eq!(
            error_json(
                "NYET",
                Some("EXPENSIVE_QUERY"),
                "too big",
                "narrow it",
                Some(&expensive())
            ),
            r#"{"v":1,"ok":false,"error":{"code":"NYET","reason":"EXPENSIVE_QUERY","message":"too big","hint":"narrow it"},"estimate":{"mode":"cost","verdict":"expensive","cost":2500000.0,"rows":9000000,"threshold":1000000.0,"plan":[{"Plan":{"Node Type":"Seq Scan","Total Cost":2500000.0}}]}}"#
        );
    }

    fn explain_meta() -> ExplainMeta {
        ExplainMeta {
            duration_ms: 7,
            connection: "prod".into(),
        }
    }

    #[test]
    fn explain_envelope_is_compact_and_stable() {
        // A cheap query: the same shape, verdict ok.
        let ok = Estimate {
            mode: "cost",
            verdict: "ok",
            cost: Some(12.5),
            rows: Some(3),
            threshold: Some(Value::from(1_000_000.0)),
            plan: plan(),
        };
        assert_eq!(
            explain_json(&ok, &explain_meta(), &[]),
            r#"{"v":1,"ok":true,"estimate":{"mode":"cost","verdict":"ok","cost":12.5,"rows":3,"threshold":1000000.0,"plan":[{"Plan":{"Node Type":"Seq Scan","Total Cost":2500000.0}}]},"meta":{"duration_ms":7,"connection":"prod"}}"#
        );
        // The expensive verdict is informational here (nothing was executed
        // either way — explain never runs the query).
        assert_eq!(
            explain_json(&expensive(), &explain_meta(), &[]),
            r#"{"v":1,"ok":true,"estimate":{"mode":"cost","verdict":"expensive","cost":2500000.0,"rows":9000000,"threshold":1000000.0,"plan":[{"Plan":{"Node Type":"Seq Scan","Total Cost":2500000.0}}]},"meta":{"duration_ms":7,"connection":"prod"}}"#
        );
    }

    /// SQLite (and any off-mode connection): the plan is real, the numbers are
    /// absent, and nyet says so instead of inventing a metric (UX-7).
    #[test]
    fn explain_envelope_without_numbers_omits_them() {
        let none = Estimate {
            mode: "off",
            verdict: "no_estimate",
            cost: None,
            rows: None,
            threshold: None,
            plan: serde_json::json!(["SCAN users", "USE TEMP B-TREE FOR ORDER BY"]),
        };
        assert_eq!(
            explain_json(&none, &explain_meta(), &[]),
            r#"{"v":1,"ok":true,"estimate":{"mode":"off","verdict":"no_estimate","plan":["SCAN users","USE TEMP B-TREE FOR ORDER BY"]},"meta":{"duration_ms":7,"connection":"prod"}}"#
        );
        // table format: data on stdout, this envelope (payload dropped) on stderr.
        let warnings = [Warning {
            code: "GUARDRAIL_SKIPPED",
            message: "no usable estimate".into(),
        }];
        assert_eq!(
            explain_meta_json(&explain_meta(), &warnings),
            r#"{"v":1,"ok":true,"meta":{"duration_ms":7,"connection":"prod"},"warnings":[{"code":"GUARDRAIL_SKIPPED","message":"no usable estimate"}]}"#
        );
        // ...and the human rendering: verdict line, then one plan line each.
        assert_eq!(
            explain_text(&none),
            "verdict: no_estimate (mode off)\nSCAN users\nUSE TEMP B-TREE FOR ORDER BY\n"
        );
        assert_eq!(
            explain_text(&expensive()),
            "verdict: expensive (mode cost)  cost 2500000  rows 9000000  limit 1000000.0\n\
             [\n  {\n    \"Plan\": {\n      \"Node Type\": \"Seq Scan\",\n      \
             \"Total Cost\": 2500000.0\n    }\n  }\n]\n"
        );
    }

    fn sample() -> (Vec<String>, Vec<Vec<Value>>, QueryMeta) {
        (
            vec!["id".into(), "email".into()],
            vec![
                vec![Value::from(1), Value::from("a@b.c")],
                vec![Value::from(2), Value::Null],
            ],
            QueryMeta {
                row_count: 2,
                truncated: false,
                duration_ms: 42,
                connection: "localdev".into(),
            },
        )
    }

    /// The mask replaces the WHOLE cell of every type, NULL included: a
    /// surviving NULL would answer "is this row's protected value set?" for
    /// every row, and a surviving type/length narrows the value.
    #[test]
    fn redact_replaces_every_type_including_null() {
        let mut rows = vec![
            vec![
                Value::from(1),
                Value::from("a@b.c"),
                Value::from(7),
                Value::Null,
            ],
            vec![
                Value::from(2),
                Value::Null,
                Value::from(1.5),
                serde_json::json!({"k": "v"}),
            ],
            vec![
                Value::from(3),
                Value::Bool(true),
                serde_json::json!([1, 2]),
                Value::from("keep"),
            ],
        ];
        // Columns 1 and 2 are protected; 0 and 3 are not.
        redact(&mut rows, &[1, 2]);
        for row in &rows {
            for i in [1, 2] {
                assert_eq!(row[i], Value::from(REDACTED), "{row:?}");
            }
        }
        assert_eq!(rows[0][0], Value::from(1));
        assert_eq!(rows[0][3], Value::Null);
        assert_eq!(rows[1][3], serde_json::json!({"k": "v"}));
        assert_eq!(rows[2][3], Value::from("keep"));
        // An index past the row width cannot panic (Д3).
        redact(&mut rows, &[99]);
        // No indexes = no edit.
        let before = rows.clone();
        redact(&mut rows, &[]);
        assert_eq!(rows, before);
    }

    #[test]
    fn mark_pii_marks_only_the_protected_columns() {
        let mut schema = sample_schema();
        mark_pii(&mut schema, "mask", |t, c| t == "users" && c == "email");
        let users = schema.tables.iter().find(|t| t.name == "users").unwrap();
        for column in users.columns.as_ref().unwrap() {
            let want = (column.name == "email").then_some("mask");
            assert_eq!(column.pii, want, "{}", column.name);
        }
        // The mark reaches the text form too (the human/`--format table` path).
        assert!(schema_text(&schema).contains("pii mask"));
        // JSON: present only on the marked column.
        let json = to_json(&schema);
        assert_eq!(json.matches("\"pii\":\"mask\"").count(), 1, "{json}");
    }

    #[test]
    fn query_envelope_is_compact_and_stable() {
        let (columns, rows, meta) = sample();
        // Column order is preserved in row objects ("id" before "email" —
        // not alphabetical); empty warnings are omitted entirely.
        assert_eq!(
            query_json(&columns, &rows, &meta, &[]),
            r#"{"v":1,"ok":true,"rows":[{"id":1,"email":"a@b.c"},{"id":2,"email":null}],"meta":{"row_count":2,"truncated":false,"duration_ms":42,"connection":"localdev"}}"#
        );
    }

    #[test]
    fn truncated_query_envelope_carries_warning() {
        let (columns, rows, mut meta) = sample();
        meta.truncated = true;
        let warnings = [Warning {
            code: "TRUNCATED",
            message: "result truncated to 2 rows".into(),
        }];
        assert_eq!(
            query_json(&columns, &rows, &meta, &warnings),
            r#"{"v":1,"ok":true,"rows":[{"id":1,"email":"a@b.c"},{"id":2,"email":null}],"meta":{"row_count":2,"truncated":true,"duration_ms":42,"connection":"localdev"},"warnings":[{"code":"TRUNCATED","message":"result truncated to 2 rows"}]}"#
        );
    }

    #[test]
    fn query_meta_envelope_has_no_rows() {
        let (_, _, meta) = sample();
        assert_eq!(
            query_meta_json(&meta, &[]),
            r#"{"v":1,"ok":true,"meta":{"row_count":2,"truncated":false,"duration_ms":42,"connection":"localdev"}}"#
        );
    }

    #[test]
    fn query_jsonl_is_one_compact_object_per_row_in_column_order() {
        let (columns, rows, _) = sample();
        assert_eq!(
            query_jsonl(&columns, &rows),
            "{\"id\":1,\"email\":\"a@b.c\"}\n{\"id\":2,\"email\":null}\n"
        );
        assert_eq!(query_jsonl(&columns, &[]), "");
    }

    #[test]
    fn query_csv_quotes_per_rfc4180_and_renders_null_empty() {
        let columns = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let rows = vec![vec![
            Value::from("plain"),
            Value::from("com,ma"),
            Value::from("qu\"ote"),
            Value::from("line\nbreak"),
        ]];
        assert_eq!(
            query_csv(&columns, &rows),
            "a,b,c,d\nplain,\"com,ma\",\"qu\"\"ote\",\"line\nbreak\"\n"
        );
        // NULL -> empty field; numbers unquoted; header only for empty results.
        let (columns, rows, _) = sample();
        assert_eq!(query_csv(&columns, &rows), "id,email\n1,a@b.c\n2,\n");
        assert_eq!(query_csv(&columns, &[]), "id,email\n");
        assert_eq!(query_csv(&[], &[]), "");
        // A column NAME with a comma is quoted too.
        assert_eq!(query_csv(&["x,y".to_string()], &[]), "\"x,y\"\n");
    }

    #[test]
    fn query_csv_defuses_formula_injection() {
        // CWE-1236: values starting with =/+/-/@ (or tab/CR) get a leading
        // apostrophe so a spreadsheet does not execute them as formulas.
        let columns = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let rows = vec![vec![
            Value::from("=1+2"),
            Value::from("+cmd"),
            Value::from("-2"),
            Value::from("@ref"),
        ]];
        // "'-2" contains no quoting trigger -> bare; the others likewise.
        assert_eq!(
            query_csv(&columns, &rows),
            "a,b,c,d\n'=1+2,'+cmd,'-2,'@ref\n"
        );
        // A tab-led value both defuses AND (via the CR/comma-free bare path)
        // stays unquoted; a CR-led value gets defused then quoted (CR trigger).
        assert_eq!(
            query_csv(&["x".to_string()], &[vec![Value::from("\rboom")]]),
            "x\n\"'\rboom\"\n"
        );
    }

    #[test]
    fn query_csv_defuse_only_touches_strings_not_numbers() {
        // A negative NUMBER must stay `-2`, not become the text `'-2` — only
        // string cells (and headers) can carry a formula.
        let columns = vec!["balance".into(), "note".into()];
        let rows = vec![vec![Value::from(-2), Value::from("=SUM(A1)")]];
        assert_eq!(query_csv(&columns, &rows), "balance,note\n-2,'=SUM(A1)\n");
        // A string that merely looks like a negative number is still defused.
        assert_eq!(
            query_csv(&["x".to_string()], &[vec![Value::from("-2")]]),
            "x\n'-2\n"
        );
    }

    #[test]
    fn query_table_renders_nulls_empty_and_aligns() {
        let (columns, rows, _) = sample();
        assert_eq!(query_table(&columns, &rows), "id  email\n1   a@b.c\n2\n");
        assert_eq!(query_table(&[], &[]), "");
    }

    fn named(names: &[&str]) -> Vec<KeyPart> {
        names
            .iter()
            .map(|n| KeyPart::Named(n.to_string()))
            .collect()
    }

    fn column(name: &str, ty: &str, nullable: bool) -> SchemaColumn {
        SchemaColumn {
            name: name.into(),
            ty: ty.into(),
            nullable,
            pk: false,
            unique: false,
            default: None,
            pii: None,
            source: None,
            seen: None,
        }
    }

    fn sample_schema() -> Schema {
        let users = build_table(
            "users".into(),
            "table",
            vec![
                column("id", "bigint", false),
                column("email", "text", false),
                column("org_id", "bigint", true),
            ],
            &["id".to_string()],
            vec![
                // Single-column unique -> folded into the column flag.
                SchemaIndex {
                    name: "users_email_key".into(),
                    columns: named(&["email"]),
                    unique: true,
                },
                SchemaIndex {
                    name: "users_org_idx".into(),
                    columns: named(&["org_id"]),
                    unique: false,
                },
            ],
            vec![SchemaFk {
                columns: vec!["org_id".into()],
                ref_table: "orgs".into(),
                ref_columns: vec!["id".into()],
            }],
            true,
        );
        let view = build_table(
            "v_active".into(),
            "view",
            vec![column("id", "bigint", true)],
            &[],
            vec![],
            vec![],
            true,
        );
        Schema {
            tables: vec![users, view],
        }
    }

    fn schema_meta(table_count: u64) -> SchemaMeta {
        SchemaMeta {
            table_count,
            duration_ms: 12,
            connection: "prod".into(),
        }
    }

    #[test]
    fn schema_envelope_is_compact_and_stable() {
        assert_eq!(
            schema_json(&sample_schema(), &schema_meta(2), &[]),
            r#"{"v":1,"ok":true,"schema":{"tables":[{"name":"users","kind":"table","columns":[{"name":"id","type":"bigint","nullable":false,"pk":true},{"name":"email","type":"text","nullable":false,"unique":true},{"name":"org_id","type":"bigint","nullable":true}],"indexes":[{"name":"users_org_idx","columns":["org_id"]}],"fks":[{"columns":["org_id"],"ref_table":"orgs","ref_columns":["id"]}]},{"name":"v_active","kind":"view","columns":[{"name":"id","type":"bigint","nullable":true}]}]},"meta":{"table_count":2,"duration_ms":12,"connection":"prod"}}"#
        );
    }

    #[test]
    fn schema_names_only_envelope_carries_the_truncation_warning() {
        let schema = Schema {
            tables: vec![
                SchemaTable {
                    name: "users".into(),
                    kind: "table",
                    ..SchemaTable::default()
                },
                SchemaTable {
                    name: "v_active".into(),
                    kind: "view",
                    ..SchemaTable::default()
                },
            ],
        };
        let warnings = [Warning {
            code: "SCHEMA_TRUNCATED",
            message: "listed 2 objects by name only".into(),
        }];
        assert_eq!(
            schema_json(&schema, &schema_meta(2), &warnings),
            r#"{"v":1,"ok":true,"schema":{"tables":[{"name":"users","kind":"table"},{"name":"v_active","kind":"view"}]},"meta":{"table_count":2,"duration_ms":12,"connection":"prod"},"warnings":[{"code":"SCHEMA_TRUNCATED","message":"listed 2 objects by name only"}]}"#
        );
        // table format: the stderr envelope keeps meta/warnings, drops the payload.
        assert_eq!(
            schema_meta_json(&schema_meta(2), &warnings),
            r#"{"v":1,"ok":true,"meta":{"table_count":2,"duration_ms":12,"connection":"prod"},"warnings":[{"code":"SCHEMA_TRUNCATED","message":"listed 2 objects by name only"}]}"#
        );
    }

    #[test]
    fn build_table_marks_composite_pk_and_keeps_multi_column_unique() {
        let t = build_table(
            "memberships".into(),
            "table",
            vec![
                column("org_id", "bigint", false),
                column("user_id", "bigint", false),
                column("a", "text", true),
                column("b", "text", true),
            ],
            &["org_id".to_string(), "user_id".to_string()],
            vec![SchemaIndex {
                name: "memberships_ab_key".into(),
                columns: named(&["a", "b"]),
                unique: true,
            }],
            vec![],
            true,
        );
        let columns = t.columns.as_ref().unwrap();
        assert!(columns[0].pk && columns[1].pk, "composite pk marks both");
        assert!(!columns[2].pk);
        // A multi-column unique stays an index entry (no column flag can hold it).
        assert_eq!(t.indexes.len(), 1);
        assert!(t.indexes[0].unique);
        assert!(!columns[2].unique && !columns[3].unique);
    }

    #[test]
    fn only_a_named_key_part_folds_whatever_its_text_looks_like() {
        // Key parts are typed, so text can never decide this. A real column
        // named "(expression)" is Named -> it folds like any other column...
        let t = build_table(
            "t".into(),
            "table",
            vec![
                column(EXPRESSION_KEY, "text", true),
                column("b", "text", true),
            ],
            &[],
            vec![SchemaIndex {
                name: "t_sentinel_idx".into(),
                columns: named(&[EXPRESSION_KEY]),
                unique: true,
            }],
            vec![],
            true,
        );
        assert!(t.columns.as_ref().unwrap()[0].unique);
        assert!(t.indexes.is_empty(), "the folded index is not repeated");

        // ...while an expression never folds, even when its text is exactly a
        // column name (an index on a quoted column named `lower(b)` vs an
        // index on the expression `lower(b)`).
        let t = build_table(
            "t".into(),
            "table",
            vec![column("lower(b)", "text", true), column("b", "text", true)],
            &[],
            vec![
                SchemaIndex {
                    name: "t_expr_idx".into(),
                    columns: vec![KeyPart::Expression(Some("lower(b)".into()))],
                    unique: true,
                },
                SchemaIndex {
                    name: "t_opaque_idx".into(),
                    columns: vec![KeyPart::Expression(None)],
                    unique: true,
                },
            ],
            vec![],
            true,
        );
        assert!(
            t.columns.as_ref().unwrap().iter().all(|c| !c.unique),
            "no expression may invent a unique column"
        );
        assert_eq!(t.indexes.len(), 2, "both stay as index entries");
    }

    #[test]
    fn a_partial_column_set_drops_whole_keys_never_shortens_them() {
        // A column-level GRANT hides `api_key`; the catalog still reports the
        // composite pk, an index over it and an fk on it. Shortening any of
        // them would BOTH leak the name and describe a key that does not exist
        // (a two-column pk reading as one column).
        let visible = || vec![column("id", "integer", true), column("note", "text", true)];
        let pk = ["id".to_string(), "api_key".to_string()];
        let indexes = || {
            vec![
                SchemaIndex {
                    name: "partly_mixed_idx".into(),
                    columns: named(&["note", "api_key"]),
                    unique: false,
                },
                SchemaIndex {
                    name: "partly_note_idx".into(),
                    columns: named(&["note"]),
                    unique: false,
                },
                // PostgreSQL puts the real expression text here, which can
                // carry a hidden identifier — dropped with a partial set.
                SchemaIndex {
                    name: "partly_expr_idx".into(),
                    columns: vec![KeyPart::Expression(Some("lower(api_key)".into()))],
                    unique: false,
                },
                // A hidden column that is literally named like the placeholder
                // is still a Named part — dropped, not mistaken for one.
                SchemaIndex {
                    name: "partly_sentinel_idx".into(),
                    columns: named(&[EXPRESSION_KEY]),
                    unique: false,
                },
                // An expression WITHOUT text names nothing, so it may stay.
                SchemaIndex {
                    name: "partly_opaque_idx".into(),
                    columns: vec![KeyPart::Expression(None), KeyPart::Named("note".into())],
                    unique: false,
                },
            ]
        };
        let fks = || {
            vec![
                SchemaFk {
                    columns: vec!["api_key".into()],
                    ref_table: "vault".into(),
                    ref_columns: vec!["key".into()],
                },
                SchemaFk {
                    columns: vec!["note".into()],
                    ref_table: "notes".into(),
                    ref_columns: vec!["id".into()],
                },
            ]
        };

        let partial = build_table(
            "partly".into(),
            "table",
            visible(),
            &pk,
            indexes(),
            fks(),
            false,
        );
        assert!(
            partial.columns.as_ref().unwrap().iter().all(|c| !c.pk),
            "a composite pk with a hidden member must vanish, not shrink"
        );
        let names: Vec<&str> = partial.indexes.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["partly_note_idx", "partly_opaque_idx"]);
        assert_eq!(partial.fks.len(), 1);
        assert_eq!(partial.fks[0].ref_table, "notes");
        // Nothing hidden anywhere in the payload.
        let json = serde_json::to_string(&partial).unwrap();
        assert!(
            !json.contains("api_key") && !json.contains("vault"),
            "{json}"
        );

        // With the full column set nothing is filtered (zero regression).
        let full = build_table(
            "partly".into(),
            "table",
            vec![
                column("id", "integer", true),
                column("note", "text", true),
                column("api_key", "text", true),
            ],
            &pk,
            indexes(),
            fks(),
            true,
        );
        assert!(full.columns.as_ref().unwrap()[2].pk);
        assert_eq!(full.indexes.len(), 5);
        assert_eq!(full.fks.len(), 2);
    }

    #[test]
    fn schema_text_renders_blocks() {
        assert_eq!(
            schema_text(&sample_schema()),
            "users table\n  \
             id      bigint  not null  pk\n  \
             email   text    not null  unique\n  \
             org_id  bigint  null\n  \
             index users_org_idx (org_id)\n  \
             fk (org_id) -> orgs (id)\n\
             v_active view\n  \
             id  bigint  null\n"
        );
        // Names-only listing: one line per object, no detail block.
        let listing = Schema {
            tables: vec![SchemaTable {
                name: "users".into(),
                kind: "table",
                ..SchemaTable::default()
            }],
        };
        assert_eq!(schema_text(&listing), "users table\n");
        assert!(listing.is_listing() && !sample_schema().is_listing());
    }

    #[test]
    fn bare_envelope() {
        assert_eq!(bare_success(), r#"{"v":1,"ok":true}"#);
    }

    // ---- doctor ----

    fn by<'a>(checks: &'a [DoctorCheck], name: &str) -> &'a DoctorCheck {
        checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check {name}"))
    }

    /// A worst-case Postgres setup: the role can write and is a superuser, the
    /// transport is insecure and the config file is loose. Every warn/fail
    /// carries an actionable hint (Д10); every ok/na does not.
    #[test]
    fn doctor_checks_cover_all_statuses_with_hints() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Postgres,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: None,
                    superuser: SuperuserFact::Yes("current_setting('is_superuser') = on".into()),
                    read_only_note: None,
                    probe: ProbeFact::Wrote { orphan: None },
                }),
            },
            forward: None,
            transport: Transport::InsecureDirect,
            permissions: Permissions::Loose("mode 644".into()),
        };
        let checks = doctor_checks(&input);
        assert_eq!(by(&checks, "connectivity").status, CheckStatus::Ok);
        assert_eq!(by(&checks, "transport_encrypted").status, CheckStatus::Warn);
        assert_eq!(by(&checks, "read_only_role").status, CheckStatus::Fail);
        assert_eq!(by(&checks, "not_superuser").status, CheckStatus::Fail);
        assert_eq!(by(&checks, "config_permissions").status, CheckStatus::Warn);
        for c in &checks {
            match c.status {
                CheckStatus::Warn | CheckStatus::Fail => {
                    assert!(
                        c.hint.as_deref().is_some_and(|h| !h.is_empty()),
                        "{} must carry a hint",
                        c.name
                    );
                }
                CheckStatus::Ok | CheckStatus::Na => assert!(c.hint.is_none(), "{}", c.name),
            }
        }
        // The read-only-role fail hint carries the actual SQL to fix it.
        assert!(by(&checks, "read_only_role")
            .hint
            .as_deref()
            .unwrap()
            .contains("CREATE ROLE nyet_ro"));
    }

    /// A forward that outlives the process is only acceptable if the human can
    /// see it and kill it: the check must name the port, say whether it was
    /// reused and how old it is, and carry the literal removal command. Without
    /// an `[ssh]` section there is no check at all (UX-4: no `na` noise).
    #[test]
    fn doctor_ssh_forward_is_visible_and_killable() {
        let input = |forward| DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Postgres,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: true },
                server: None,
            },
            transport: Transport::Tunnel,
            forward,
            permissions: Permissions::Na,
        };
        assert!(!doctor_checks(&input(None))
            .iter()
            .any(|c| c.name == "ssh_forward"));

        let kept = doctor_checks(&input(Some(ForwardFact {
            local_port: 54321,
            reused: true,
            age_secs: Some(600),
            kill_command: Some("ssh -O cancel -L 127.0.0.1:54321:db:5432 bastion".to_string()),
        })));
        let check = by(&kept, "ssh_forward");
        assert_eq!(check.status, CheckStatus::Ok);
        for part in [
            "127.0.0.1:54321",
            "reused, opened 10m ago",
            "ssh -O cancel -L 127.0.0.1:54321:db:5432 bastion",
        ] {
            assert!(
                check.message.contains(part),
                "missing {part}: {}",
                check.message
            );
        }

        // Nothing left behind: say so, and do not offer a command that would
        // then be a lie.
        let ephemeral = doctor_checks(&input(Some(ForwardFact {
            local_port: 40000,
            reused: false,
            age_secs: None,
            kill_command: None,
        })));
        let check = by(&ephemeral, "ssh_forward");
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(check.message.contains("removed when this command exits"));
        assert!(!check.message.contains("ssh -O cancel"));
    }

    /// The `pii_columns` check is honest in all four directions (UX-7): no
    /// policy and SQLite are `na`, an unreadable set is `ok`, and a column the
    /// role CAN read is a `warn` that names it and hands over the server-side
    /// fix — because there nyet is the only boundary.
    #[test]
    fn doctor_pii_columns_is_honest_about_the_real_boundary() {
        let access = |pairs: &[(&str, Option<bool>)]| {
            pairs
                .iter()
                .map(|(c, readable)| PiiAccess {
                    column: (*c).to_string(),
                    readable: *readable,
                })
                .collect::<Vec<_>>()
        };
        let input = |engine, pii_mode, pii| DoctorInput {
            secret: None,
            pii_mode,
            engine,
            diagnosis: Diagnosis {
                pii_views: None,
                pii,
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: None,
                    superuser: SuperuserFact::No("off".into()),
                    read_only_note: None,
                    probe: ProbeFact::Blocked {
                        detail: "permission denied".into(),
                        ddl_only: true,
                    },
                }),
            },
            forward: None,
            transport: Transport::TlsDirect,
            permissions: Permissions::Secure,
        };
        let check = |i: DoctorInput| {
            let checks = doctor_checks(&i);
            let c = by(&checks, "pii_columns");
            (c.status, c.message.clone(), c.hint.clone())
        };

        // No policy at all -> the check is not emitted (noise on every
        // connection that does not use the feature).
        let checks = doctor_checks(&input(EngineKind::Postgres, None, Vec::new()));
        assert!(
            !checks.iter().any(|c| c.name == "pii_columns"),
            "pii_columns must be absent without a policy"
        );

        // SQLite -> na, and the message says plainly that nyet is alone here.
        let (status, message, _) = check(input(
            EngineKind::Sqlite,
            Some("mask"),
            access(&[("users.email", None)]),
        ));
        assert_eq!(status, CheckStatus::Na);
        assert!(message.contains("only thing"), "{message}");

        // Unreadable for this role -> ok.
        let (status, message, _) = check(input(
            EngineKind::Postgres,
            Some("deny"),
            access(&[("users.email", Some(false)), ("users.phone", Some(false))]),
        ));
        assert_eq!(status, CheckStatus::Ok);
        assert!(message.contains("cannot read"), "{message}");

        // Readable -> warn, naming the columns and the GRANT recipe.
        let (status, message, hint) = check(input(
            EngineKind::Mysql,
            Some("mask"),
            access(&[("users.email", Some(true)), ("users.phone", Some(false))]),
        ));
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("users.email"), "{message}");
        assert!(message.contains("outside nyet"), "{message}");
        assert!(hint.unwrap().contains("REVOKE SELECT"));

        // Could not verify -> warn, never a pass.
        let (status, message, hint) = check(input(
            EngineKind::Postgres,
            Some("deny"),
            access(&[("typo.email", None)]),
        ));
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("could not verify"), "{message}");
        assert!(hint.is_some());
    }

    /// A read-only-transaction / replica refusal is the strong layer-3 pass: the
    /// message claims every direct write is rejected, and the replica note is
    /// folded in. A non-superuser role over TLS with a 0600 config is all green.
    #[test]
    fn doctor_read_only_role_ok_when_the_probe_is_blocked() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Postgres,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: None,
                    superuser: SuperuserFact::No("current_setting('is_superuser') = off".into()),
                    read_only_note: Some("the server is a read-only replica (hot standby)".into()),
                    probe: ProbeFact::Blocked {
                        detail: "cannot execute CREATE TABLE in a read-only transaction".into(),
                        ddl_only: false,
                    },
                }),
            },
            forward: None,
            transport: Transport::TlsDirect,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        let ro = by(&checks, "read_only_role");
        assert_eq!(ro.status, CheckStatus::Ok);
        assert!(
            ro.message.contains("would still be read-only"),
            "{}",
            ro.message
        );
        assert!(ro.message.contains("read-only replica"), "{}", ro.message);
        assert_eq!(by(&checks, "not_superuser").status, CheckStatus::Ok);
        assert_eq!(by(&checks, "transport_encrypted").status, CheckStatus::Ok);
        assert_eq!(by(&checks, "config_permissions").status, CheckStatus::Ok);
    }

    /// UX-7: an access-denied-on-CREATE block stays `ok` (the recommended
    /// SELECT-only role lands here) but the headline must NOT over-promise — it
    /// says only DDL was proven refused, DML was not probed. The two Blocked
    /// sub-cases produce distinct messages.
    #[test]
    fn doctor_blocked_headline_does_not_over_promise_on_ddl_only() {
        let blocked = |ddl_only: bool| {
            let input = DoctorInput {
                secret: None,
                pii_mode: None,
                engine: EngineKind::Postgres,
                diagnosis: Diagnosis {
                    pii_views: None,
                    pii: Vec::new(),
                    connect: ConnectFact::Ok { via_tunnel: false },
                    server: Some(ServerFacts {
                        js: None,
                        superuser: SuperuserFact::No("off".into()),
                        read_only_note: None,
                        probe: ProbeFact::Blocked {
                            detail: "permission denied for schema public".into(),
                            ddl_only,
                        },
                    }),
                },
                forward: None,
                transport: Transport::TlsDirect,
                permissions: Permissions::Secure,
            };
            let checks = doctor_checks(&input);
            // Status is `ok` in BOTH sub-cases (the SELECT-only role lands here).
            assert_eq!(by(&checks, "read_only_role").status, CheckStatus::Ok);
            by(&checks, "read_only_role").message.clone()
        };
        let access = blocked(true);
        assert!(access.contains("cannot run DDL"), "{access}");
        assert!(access.contains("NOT separately probed"), "{access}");
        let readonly = blocked(false);
        assert!(readonly.contains("would still be read-only"), "{readonly}");
        assert_ne!(access, readonly, "the two sub-cases must read differently");
    }

    /// Honesty crux (UX-1): a probe error that does NOT prove read-only, and an
    /// undetermined superuser status, are `warn` ("could not verify") — NEVER a
    /// false `ok`. A false pass is the worst outcome for a security tool.
    #[test]
    fn doctor_unknown_is_warn_never_a_false_ok() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Postgres,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: None,
                    superuser: SuperuserFact::Unknown("could not read is_superuser".into()),
                    read_only_note: None,
                    probe: ProbeFact::Unknown {
                        detail: "server closed the connection".into(),
                    },
                }),
            },
            forward: None,
            transport: Transport::TlsDirect,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        assert_eq!(by(&checks, "read_only_role").status, CheckStatus::Warn);
        assert!(by(&checks, "read_only_role")
            .message
            .contains("could not verify"));
        assert_eq!(by(&checks, "not_superuser").status, CheckStatus::Warn);
        // Both carry an actionable hint.
        assert!(by(&checks, "read_only_role").hint.is_some());
        assert!(by(&checks, "not_superuser").hint.is_some());
    }

    /// A MySQL probe that wrote but could not clean up: the orphan table name is
    /// surfaced (forensics), not swallowed — the check is still `fail` (the role
    /// writes). And unresolved role/proxy grants are `warn`, not a false `ok`.
    #[test]
    fn doctor_reports_orphan_probe_table_and_unresolved_grants() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Mysql,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: None,
                    superuser: SuperuserFact::Unresolved(
                        "the account has role/proxy grants nyet does not resolve".into(),
                    ),
                    read_only_note: None,
                    probe: ProbeFact::Wrote {
                        orphan: Some("nyet_doctor_probe_42_99_0".into()),
                    },
                }),
            },
            forward: None,
            transport: Transport::InsecureDirect,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        let ro = by(&checks, "read_only_role");
        assert_eq!(ro.status, CheckStatus::Fail);
        assert!(
            ro.message.contains("nyet_doctor_probe_42_99_0"),
            "{}",
            ro.message
        );
        assert_eq!(by(&checks, "not_superuser").status, CheckStatus::Warn);
    }

    /// SQLite has no roles/server/network — those checks are honestly `na`, not
    /// a faked pass or a made-up metric (UX-7).
    #[test]
    fn doctor_sqlite_is_honest_about_na() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Sqlite,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Ok { via_tunnel: false },
                server: None,
            },
            forward: None,
            transport: Transport::Na,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        assert_eq!(by(&checks, "connectivity").status, CheckStatus::Ok);
        for name in ["transport_encrypted", "read_only_role", "not_superuser"] {
            assert_eq!(by(&checks, name).status, CheckStatus::Na, "{name}");
            assert!(by(&checks, name).hint.is_none(), "{name}");
        }
        assert_eq!(by(&checks, "config_permissions").status, CheckStatus::Ok);
    }

    /// A failed connect is a `fail` check (exit 0 in the cli), never an error
    /// envelope — diagnosing a broken connection is exactly what doctor is for.
    #[test]
    fn doctor_connect_failure_is_a_fail_check_not_an_error() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Postgres,
            diagnosis: Diagnosis {
                pii_views: None,
                pii: Vec::new(),
                connect: ConnectFact::Failed {
                    message: "cannot connect".into(),
                    hint: "check host/port".into(),
                },
                server: None,
            },
            forward: None,
            transport: Transport::InsecureDirect,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        assert_eq!(by(&checks, "connectivity").status, CheckStatus::Fail);
        // The DB-dependent checks cannot be verified, so they warn (not fail).
        assert_eq!(by(&checks, "read_only_role").status, CheckStatus::Warn);
        assert_eq!(by(&checks, "not_superuser").status, CheckStatus::Warn);
        // ...but the config-only checks still answer.
        assert_eq!(by(&checks, "transport_encrypted").status, CheckStatus::Warn);
        assert_eq!(by(&checks, "config_permissions").status, CheckStatus::Ok);
    }

    #[test]
    fn doctor_config_checks_list_aliases_or_warn_when_none() {
        let some = doctor_config_checks(&Permissions::Secure, &["a".into(), "b".into()]);
        assert_eq!(by(&some, "connections").status, CheckStatus::Ok);
        assert!(by(&some, "connections").message.contains("a, b"));
        let none = doctor_config_checks(&Permissions::Loose("mode 644".into()), &[]);
        assert_eq!(by(&none, "connections").status, CheckStatus::Warn);
        assert_eq!(by(&none, "config_permissions").status, CheckStatus::Warn);
    }

    /// Contract shape (Д7): keys and order are pinned, `hint` omitted when
    /// absent, `connection` omitted in the config-level (meta-only) envelope.
    #[test]
    fn doctor_envelope_is_compact_and_stable() {
        let checks = vec![
            DoctorCheck {
                name: "connectivity",
                status: CheckStatus::Ok,
                message: "ok".into(),
                hint: None,
            },
            DoctorCheck {
                name: "read_only_role",
                status: CheckStatus::Fail,
                message: "no".into(),
                hint: Some("do x".into()),
            },
        ];
        let meta = DoctorMeta {
            connection: Some("prod".into()),
            duration_ms: 5,
        };
        assert_eq!(
            doctor_json(&checks, &meta),
            r#"{"v":1,"ok":true,"checks":[{"name":"connectivity","status":"ok","message":"ok"},{"name":"read_only_role","status":"fail","message":"no","hint":"do x"}],"meta":{"connection":"prod","duration_ms":5}}"#
        );
        // table format: the checks render on stdout, this data-less envelope on
        // stderr — and the config-level run omits `connection`.
        let meta = DoctorMeta {
            connection: None,
            duration_ms: 0,
        };
        assert_eq!(
            doctor_meta_json(&meta),
            r#"{"v":1,"ok":true,"meta":{"duration_ms":0}}"#
        );
    }

    #[test]
    fn doctor_text_renders_status_name_message_and_indented_hint() {
        let checks = vec![
            DoctorCheck {
                name: "connectivity",
                status: CheckStatus::Ok,
                message: "connected".into(),
                hint: None,
            },
            DoctorCheck {
                name: "read_only_role",
                status: CheckStatus::Fail,
                message: "can write".into(),
                hint: Some("line1\nline2".into()),
            },
        ];
        let text = doctor_text(&checks);
        assert!(text.contains("ok"), "{text}");
        assert!(text.contains("connectivity"), "{text}");
        assert!(text.contains("fail"), "{text}");
        assert!(text.contains("can write"), "{text}");
        assert!(
            text.contains("→ line1") && text.contains("→ line2"),
            "{text}"
        );
    }

    /// MongoDB's `read_only_role` is decided from the PRIVILEGE LIST, with no
    /// probe write anywhere — and the fail-closed wording rule applies to every
    /// branch of it: only "the server listed nothing but reads" is an `ok`.
    #[test]
    fn doctor_mongo_reads_layer_3_from_the_grants_and_never_guesses() {
        let grants = |g: Grants| DoctorInput {
            secret: None,
            // MongoDB rejects a `[pii]` section at config parse.
            pii_mode: None,
            engine: EngineKind::Mongo,
            diagnosis: Diagnosis {
                pii_views: None,
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js: Some(JsFact::Disabled),
                    superuser: SuperuserFact::No("roles: read@app".into()),
                    read_only_note: None,
                    probe: ProbeFact::Grants(Box::new(g)),
                }),
                pii: Vec::new(),
            },
            forward: None,
            transport: Transport::TlsDirect,
            permissions: Permissions::Secure,
        };
        let clean = || Grants {
            writes: Vec::new(),
            write_count: 0,
            unknown: Vec::new(),
            unknown_count: 0,
            this_database: false,
            resources: 2,
            unauthenticated: false,
        };
        let check = |g: Grants| {
            let checks = doctor_checks(&grants(g));
            let c = by(&checks, "read_only_role");
            (c.status, c.message.clone())
        };

        // Only read actions anywhere: an `ok` that says how it knows.
        let (status, message) = check(clean());
        assert_eq!(status, CheckStatus::Ok);
        assert!(message.contains("connectionStatus"), "{message}");
        assert!(message.contains("writes nothing"), "{message}");

        // Write actions in ANOTHER database of the same cluster: a warn that
        // names where, because $out from here into there is a way out.
        let (status, message) = check(Grants {
            writes: vec!["scratch.* (insert, update)".into()],
            write_count: 1,
            ..clean()
        });
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("scratch.*"), "{message}");

        // ...and on this database: a fail.
        let (status, _) = check(Grants {
            writes: vec!["app.* (insert)".into()],
            write_count: 1,
            this_database: true,
            ..clean()
        });
        assert_eq!(status, CheckStatus::Fail);

        // An action nyet cannot classify is NOT assumed harmless.
        let (status, message) = check(Grants {
            unknown: vec!["teleportDocuments on app.*".into()],
            unknown_count: 1,
            ..clean()
        });
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("teleportDocuments"), "{message}");

        // No authenticated user at all: there is provably no read-only role.
        let (status, _) = check(Grants {
            unauthenticated: true,
            resources: 0,
            ..clean()
        });
        assert_eq!(status, CheckStatus::Fail);
    }

    /// The MongoDB-only check, in all three states — and the one that matters
    /// is `Unknown`: nyet refuses to probe by RUNNING JavaScript, so it says it
    /// could not check instead of passing (UX-1/UX-7).
    #[test]
    fn doctor_server_side_js_is_mongodb_only_and_admits_it_cannot_check() {
        let with = |engine, js| DoctorInput {
            secret: None,
            pii_mode: None,
            engine,
            diagnosis: Diagnosis {
                pii_views: None,
                connect: ConnectFact::Ok { via_tunnel: false },
                server: Some(ServerFacts {
                    js,
                    superuser: SuperuserFact::No("roles: read@app".into()),
                    read_only_note: None,
                    probe: ProbeFact::Grants(Box::new(Grants {
                        writes: Vec::new(),
                        write_count: 0,
                        unknown: Vec::new(),
                        unknown_count: 0,
                        this_database: false,
                        resources: 1,
                        unauthenticated: false,
                    })),
                }),
                pii: Vec::new(),
            },
            forward: None,
            transport: Transport::TlsDirect,
            permissions: Permissions::Secure,
        };
        let js = |fact| {
            let checks = doctor_checks(&with(EngineKind::Mongo, Some(fact)));
            let c = by(&checks, "server_side_js");
            (c.status, c.message.clone())
        };
        assert_eq!(js(JsFact::Disabled).0, CheckStatus::Ok);
        let (status, message) = js(JsFact::Enabled);
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("ENABLED"), "{message}");
        let (status, message) = js(JsFact::Unknown("not authorized".into()));
        assert_eq!(status, CheckStatus::Warn);
        assert!(message.contains("could not check"), "{message}");
        assert!(message.contains("not authorized"), "{message}");
        // Emitted for MongoDB and for nothing else.
        for engine in [EngineKind::Postgres, EngineKind::Mysql, EngineKind::Sqlite] {
            let checks = doctor_checks(&with(engine, None));
            assert!(!checks.iter().any(|c| c.name == "server_side_js"));
        }
    }

    /// Without a connection there are no facts, and a check with no fact is a
    /// `warn` — including the MongoDB-only one. "Could not verify" is never an
    /// `ok`: that is the failure mode doctor exists to avoid (UX-1).
    #[test]
    fn doctor_mongo_without_a_connection_never_reads_as_ok() {
        let input = DoctorInput {
            secret: None,
            pii_mode: None,
            engine: EngineKind::Mongo,
            diagnosis: Diagnosis {
                pii_views: None,
                connect: ConnectFact::Failed {
                    message: "no server could be selected".into(),
                    hint: "check the host/port".into(),
                },
                server: None,
                pii: Vec::new(),
            },
            forward: None,
            transport: Transport::InsecureDirect,
            permissions: Permissions::Secure,
        };
        let checks = doctor_checks(&input);
        assert_eq!(by(&checks, "connectivity").status, CheckStatus::Fail);
        for name in ["read_only_role", "not_superuser", "server_side_js"] {
            let check = by(&checks, name);
            assert_eq!(check.status, CheckStatus::Warn, "{name}");
            assert!(check.message.contains("could not"), "{name}");
            assert!(check.hint.is_some(), "{name}");
        }
    }

    #[test]
    fn table_aligns_columns() {
        let items = [
            ConnectionInfo {
                alias: "localdev".into(),
                engine: "sqlite".into(),
            },
            ConnectionInfo {
                alias: "p".into(),
                engine: "postgres".into(),
            },
        ];
        assert_eq!(
            list_table(&items),
            "ALIAS     ENGINE\nlocaldev  sqlite\np         postgres\n"
        );
    }
}
