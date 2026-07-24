//! JSON envelope v1 and table rendering. Pure: values in, strings out.
//! Compact serialization only — agent tokens are the user's money.

use serde::Serialize;

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
    message: &'a str,
    // Mandatory: an error without an actionable hint does not ship (Д10).
    hint: &'a str,
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

pub fn error_json(code: &str, message: &str, hint: &str) -> String {
    to_json(&ErrorEnvelope {
        v: ENVELOPE_V,
        ok: false,
        error: ErrorBody {
            code,
            message,
            hint,
        },
    })
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
            error_json("CONFIG_INVALID", "boom", "fix it"),
            r#"{"v":1,"ok":false,"error":{"code":"CONFIG_INVALID","message":"boom","hint":"fix it"}}"#
        );
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
