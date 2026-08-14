//! Pure statement builders for `nyet sample <alias> <table>`: the text nyet
//! writes on the agent's behalf.
//!
//! `sample` is sugar over `query`, and this module is the whole of the sugar.
//! What it returns travels the ORDINARY query path — layer 1
//! (`validator`/`mongo`), the guardrail, both PII nets, the row limit, the
//! formatters — so nyet's own text is judged by exactly the rules that judge an
//! agent's SQL. Nothing here is trusted and nothing here bypasses anything: the
//! table name is agent input, so it is QUOTED into a single identifier (never
//! spliced into syntax) and then handed to the same validator it would have met
//! coming from the command line.
//!
//! The engines whose guardrail can refuse the sort (PostgreSQL, MySQL/MariaDB)
//! get two spellings: the random draw nyet tries first, and the plain `LIMIT`
//! the cli falls back to (warning `SAMPLE_FALLBACK`, see main.rs). SQLite and
//! MongoDB get one — their guardrail is `off` by construction, so their draw
//! can never be refused for cost.
//!
//! Being the pure, std-only owner of "an agent-supplied name -> one identifier",
//! this module also holds the two rules `engine`'s introspection needs for the
//! same argument (`split_qualified`, `backquote`): quoting is
//! injection-prevention code, so it exists once and both commands read one name
//! the same way.

/// Rows a `sample` returns when `--limit` is absent. Small on purpose: the
/// command answers "what does this data look like", and every row is tokens the
/// agent pays for (UX-4).
pub const DEFAULT_ROWS: u64 = 10;

/// The SQL-standard identifier quote (SQLite, PostgreSQL): a `"` inside the
/// name is doubled, so the whole argument stays ONE identifier whatever it
/// contains.
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// MySQL/MariaDB do the same with backticks. Shared with
/// `engine::mysql_probe_column`, which builds SQL from the same agent-supplied
/// names.
pub fn backquote(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// Split the `[table]` argument into `(schema, name)` on the FIRST dot. Shared
/// with `engine`'s PostgreSQL introspection, so `nyet schema pg sales.orders`
/// and `nyet sample pg sales.orders` cannot drift into reading one argument two
/// ways.
pub fn split_qualified(table: &str) -> (Option<&str>, &str) {
    match table.split_once('.') {
        Some((schema, name)) => (Some(schema), name),
        None => (None, table),
    }
}

/// SQLite: the whole argument is one table name (SQLite has no schemas to
/// qualify with), and `RANDOM()` is its spelling of the draw. No cheap variant:
/// SQLite's guardrail mode is `off` and nothing else is accepted
/// (`guardrail::engine_modes`), so the draw is never refused for cost.
pub fn sqlite(table: &str, rows: u64) -> String {
    format!(
        "SELECT * FROM {} ORDER BY RANDOM() LIMIT {rows}",
        quote(table)
    )
}

/// PostgreSQL: `sales.orders` is a QUALIFIED name, split on the FIRST dot (see
/// `split_qualified`). A bare name resolves through the connection's
/// `search_path`, like any hand-written query.
pub fn postgres(table: &str, rows: u64, random: bool) -> String {
    let name = match split_qualified(table) {
        (Some(schema), name) => format!("{}.{}", quote(schema), quote(name)),
        (None, name) => quote(name),
    };
    let order = if random { " ORDER BY random()" } else { "" };
    format!("SELECT * FROM {name}{order} LIMIT {rows}")
}

/// MySQL/MariaDB: one identifier again (a database qualifier would have to be
/// two, and `nyet schema` does not take one either), `RAND()` for the draw.
pub fn mysql(table: &str, rows: u64, random: bool) -> String {
    let order = if random { " ORDER BY RAND()" } else { "" };
    format!("SELECT * FROM {}{order} LIMIT {rows}", backquote(table))
}

/// ClickHouse: backtick-quoted like MySQL, `rand()` for the draw. It has a
/// native `SAMPLE` clause too, and it is deliberately NOT used here — `SAMPLE`
/// needs the table to have been created with a sampling expression, so on a
/// table without one it is a syntax error rather than a slower answer, and
/// `nyet sample` must work on any table the agent names.
pub fn clickhouse(table: &str, rows: u64, random: bool) -> String {
    let order = if random { " ORDER BY rand()" } else { "" };
    format!("SELECT * FROM {}{order} LIMIT {rows}", backquote(table))
}

/// MongoDB: `$sample` is on the pipeline allowlist and draws without reading
/// the whole collection, so there is no cheap variant to fall back to. The
/// collection name is not quoted because mongosh has no quoting for it — a name
/// that is not a plain identifier simply fails to parse and is refused (exit 5),
/// which is the fail-closed answer.
pub fn mongo(collection: &str, rows: u64) -> String {
    format!("db.{collection}.aggregate([{{$sample: {{size: {rows}}}}}])")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mongo;
    use crate::validator::{self, DenyReason, Policy, Verdict};

    /// The text must reach the database as ONE read statement — that is the
    /// whole security claim of building SQL from an agent-supplied name.
    fn assert_one_read(sql: &str, policy: &Policy) {
        match validator::validate(sql, policy) {
            Verdict::Allow { is_query, .. } => assert!(is_query, "not a plain query: {sql}"),
            Verdict::Deny { reason, .. } => panic!("{sql}: refused as {}", reason.as_str()),
        }
    }

    #[test]
    fn every_dialect_quotes_the_name_into_one_identifier() {
        assert_eq!(
            sqlite("users", 11),
            r#"SELECT * FROM "users" ORDER BY RANDOM() LIMIT 11"#
        );
        // A dot is part of the name on SQLite/MySQL (they take one identifier).
        assert_eq!(
            sqlite("a.b", 3),
            r#"SELECT * FROM "a.b" ORDER BY RANDOM() LIMIT 3"#
        );
        assert_eq!(mysql("a.b", 3, false), "SELECT * FROM `a.b` LIMIT 3");
        // The quote character itself is doubled, never escaped into syntax.
        assert_eq!(
            sqlite(r#"we"ird"#, 1),
            r#"SELECT * FROM "we""ird" ORDER BY RANDOM() LIMIT 1"#
        );
        assert_eq!(mysql("we`ird", 1, false), "SELECT * FROM `we``ird` LIMIT 1");
        assert_eq!(
            mysql("users", 11, true),
            "SELECT * FROM `users` ORDER BY RAND() LIMIT 11"
        );
        // Unicode is a name like any other — quoted, not stripped.
        assert_eq!(
            postgres("пользователи", 5, false),
            r#"SELECT * FROM "пользователи" LIMIT 5"#
        );
    }

    /// PostgreSQL splits on the FIRST dot, through the very `split_qualified`
    /// `engine`'s introspection calls for `nyet schema` — the two commands must
    /// read one argument one way.
    #[test]
    fn postgres_qualifies_on_the_first_dot_like_schema_does() {
        assert_eq!(
            postgres("users", 11, true),
            r#"SELECT * FROM "users" ORDER BY random() LIMIT 11"#
        );
        assert_eq!(
            postgres("sales.orders", 11, false),
            r#"SELECT * FROM "sales"."orders" LIMIT 11"#
        );
        // Second and later dots belong to the object name.
        assert_eq!(
            postgres("a.b.c", 1, false),
            r#"SELECT * FROM "a"."b.c" LIMIT 1"#
        );
        assert_eq!(split_qualified("a.b.c"), (Some("a"), "b.c"));
        assert_eq!(split_qualified("orders"), (None, "orders"));
    }

    #[test]
    fn the_built_text_passes_the_validator_of_its_own_dialect() {
        assert_one_read(&sqlite("users", 11), &Policy::sqlite(&[], &[]));
        for random in [true, false] {
            assert_one_read(&postgres("users", 11, random), &Policy::postgres(&[], &[]));
            assert_one_read(
                &postgres("sales.orders", 11, random),
                &Policy::postgres(&[], &[]),
            );
            assert_one_read(&mysql("users", 11, random), &Policy::mysql(&[], &[]));
        }
    }

    /// An injection attempt in the name is not one: quoting makes it a table
    /// that does not exist. Whatever the validator then says, it must never be
    /// "this is a write" or "this is several statements" — those verdicts would
    /// mean the name escaped its quotes.
    #[test]
    fn an_injecting_name_never_becomes_a_second_statement() {
        let names = [
            r#"users"; DROP TABLE x --"#,
            "users'; DROP TABLE x --",
            "users`; DROP TABLE x --",
            "users\"); DELETE FROM users; --",
            "users\n; SELECT 1",
            "*",
            "",
        ];
        for name in names {
            for (sql, policy) in [
                (sqlite(name, 11), Policy::sqlite(&[], &[])),
                (postgres(name, 11, true), Policy::postgres(&[], &[])),
                (mysql(name, 11, true), Policy::mysql(&[], &[])),
            ] {
                match validator::validate(&sql, &policy) {
                    Verdict::Allow { is_query, .. } => assert!(is_query, "{sql}"),
                    // A name the parser cannot read at all is fine — it is
                    // refused before anything runs. Nothing else is.
                    Verdict::Deny { reason, .. } => assert_eq!(
                        reason,
                        DenyReason::ParseFailed,
                        "{sql}: refused as {}",
                        reason.as_str()
                    ),
                }
            }
        }
    }

    #[test]
    fn the_mongo_text_is_an_allowlisted_sample_aggregation() {
        let request = mongo::check(&mongo("events", 11)).expect("must pass the mongo allowlist");
        assert_eq!(request.collection, "events");
        match request.op {
            mongo::Op::Aggregate { pipeline } => {
                assert_eq!(pipeline.len(), 1);
                let stage = pipeline[0].as_document().expect("a stage document");
                assert_eq!(
                    stage.get_document("$sample").unwrap().get_i32("size"),
                    Ok(11)
                );
            }
            other => panic!("not an aggregate: {other:?}"),
        }
    }

    /// A collection name mongosh cannot read is refused by layer 1, not
    /// smuggled into the pipeline.
    #[test]
    fn an_injecting_collection_name_is_refused_by_layer_1() {
        for name in ["events); db.x.drop(", "events\"", "", "$where"] {
            assert!(
                mongo::check(&mongo(name, 11)).is_err(),
                "{name}: parsed into something"
            );
        }
    }
}
