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
