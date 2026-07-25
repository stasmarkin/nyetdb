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

#[derive(Serialize)]
pub struct SchemaTable {
    pub name: String,
    /// `"table"` or `"view"`.
    pub kind: &'static str,
    /// `None` in the names-only listing; views carry columns but never
    /// indexes/fks (the engines do not collect either for a view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<SchemaColumn>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub indexes: Vec<SchemaIndex>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fks: Vec<SchemaFk>,
}

/// `nullable` is always explicit (an agent writing a query needs it); the flags
/// are serialized only when true and `default` only when the engine reports one
/// — every omitted byte is the user's money (UX-4).
#[derive(Serialize)]
pub struct SchemaColumn {
    pub name: String,
    /// The type as the engine reports it (pg `format_type`, MySQL
    /// `COLUMN_TYPE`, SQLite's declared type).
    #[serde(rename = "type")]
    pub ty: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub pk: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub unique: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
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
        out.push_str(&format!("{} {}\n", table.name, table.kind));
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

pub fn error_json(code: &str, reason: Option<&str>, message: &str, hint: &str) -> String {
    to_json(&ErrorEnvelope {
        v: ENVELOPE_V,
        ok: false,
        error: ErrorBody {
            code,
            reason,
            message,
            hint,
        },
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
            error_json("CONFIG_INVALID", None, "boom", "fix it"),
            r#"{"v":1,"ok":false,"error":{"code":"CONFIG_INVALID","message":"boom","hint":"fix it"}}"#
        );
    }

    #[test]
    fn nyet_refusal_envelope_carries_reason() {
        assert_eq!(
            error_json("NYET", Some("WRITE_OPERATION"), "no", "rewrite"),
            r#"{"v":1,"ok":false,"error":{"code":"NYET","reason":"WRITE_OPERATION","message":"no","hint":"rewrite"}}"#
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
                    columns: None,
                    indexes: Vec::new(),
                    fks: Vec::new(),
                },
                SchemaTable {
                    name: "v_active".into(),
                    kind: "view",
                    columns: None,
                    indexes: Vec::new(),
                    fks: Vec::new(),
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
                columns: None,
                indexes: Vec::new(),
                fks: Vec::new(),
            }],
        };
        assert_eq!(schema_text(&listing), "users table\n");
        assert!(listing.is_listing() && !sample_schema().is_listing());
    }

    #[test]
    fn bare_envelope() {
        assert_eq!(bare_success(), r#"{"v":1,"ok":true}"#);
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
