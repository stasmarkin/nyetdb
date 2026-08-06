//! Pure generator for `nyet agent-setup`: a Claude Code skill (SKILL.md —
//! YAML frontmatter + Markdown body) that teaches an AI agent to use nyet.
//!
//! Д1/Д2: a stable instruction template plus the user's already-read
//! connections -> one String, no IO. The cli reads the config and writes the
//! output. Token-economical on purpose (UX-4) — it is a document the agent
//! reads and pays for — while still self-sufficient (UX-3): an agent seeing
//! nyet for the first time can reach a successful query from it alone.

/// One connection advertised in the dynamic "Your connections" section.
pub struct Conn {
    pub alias: String,
    pub engine: String,
}

/// What the dynamic section is built from.
pub enum Connections {
    /// The config could not be located, read or parsed (or cwd was
    /// unresolvable): degrade to the "set up a config" hint rather than fail —
    /// agent-setup's value is teaching the agent even before any setup.
    Unavailable,
    /// The config loaded; these connections are reachable from the current
    /// directory (consistent with `nyet list`; possibly empty).
    Available(Vec<Conn>),
}

/// The stable instruction: frontmatter + body, up to the dynamic section.
/// A raw string so the JSON examples need no escaping; ends right where the
/// per-user "Your connections" section begins.
const HEAD: &str = r#"---
name: nyet
description: Read-only database access for AI agents. Use nyet to inspect database schemas, sample a table's rows and run safe read-only SQL (SELECT, SHOW, DESCRIBE, EXPLAIN) against the user's configured databases (PostgreSQL, MySQL/MariaDB, SQLite) or read-only mongosh queries against MongoDB. It enforces read-only, keeps credentials behind aliases, and returns compact JSON. Reach for it whenever a task needs to read from a database.
---

# nyet — read-only database access

`nyet` is a read-only CLI for databases. By default a write is refused with a
`NYET` reason+hint — blocked across layers (SQL validation, a server-side
read-only session, and a recommended read-only role) — so send only read
queries. It is read-only by default, not an access-control boundary: the config
owner can selectively permit specific functions via `allow_functions` (a
durable-write function such as `nextval` could be re-enabled that way), so do
not rely on it as a hard guarantee. You name a database by its **alias** — never
a URL, host, or password. The user owns the config; credentials never reach you
and you do not go looking for them (see "Never route around nyet" below).

## Commands

    nyet list --format json                     # connections reachable from here
    nyet schema <alias> [table] --format json   # tables, columns, keys, indexes
    nyet sample <alias> <table> --format json   # a few rows, to see what the data looks like
    nyet explain <alias> "<SQL>" --format json  # query plan + cost/rows (none on SQLite), without running it
    nyet query <alias> "<SQL>" --format json    # run one read-only query
    nyet doctor [alias]                         # (for the human) diagnose the setup

Usual flow: `nyet list` to see aliases, `nyet schema <alias>` to learn the
tables, `nyet sample <alias> <table>` to see what is actually in one, then
`nyet query <alias> "SELECT ..."`. Run `nyet <command> --help` for more.

`sample` is sugar over `query`: nyet writes the statement itself — 10 rows
(`--limit N` for more) drawn at RANDOM — and runs it through the very same
rules, so a refusal reads exactly like a `query` refusal. If the connection's
guardrail refuses the random draw as too expensive, nyet retries with the first
N rows and adds a `SAMPLE_FALLBACK` warning: those rows are then in the
database's own storage order, not a random draw, so do not read them as
representative. `sample` is a `SELECT *`, so on a table with a protected column
it is refused in both PII modes (see below) — name the columns you need with
`nyet query` instead.

**Always pass `--format json` when you parse the output.** `query`/`list`/
`schema`/`explain` otherwise follow the user's `[defaults].format`, and `doctor`
defaults to a human table — so never rely on the default. With `--format json`
the whole answer is one JSON envelope on stdout. Query options: `--limit N`
(max rows), `--timeout SECS`. (The other formats — `jsonl`/`csv`/`table` on
`query` — stream rows on stdout and put the envelope on stderr; use them only
when you deliberately want that, not for parsing.)

If an alias contains a space or shell metacharacter, quote it:
`nyet query "prod db" "SELECT 1" --format json`.

    nyet query <alias> "SELECT id, email FROM users ORDER BY id LIMIT 20" --format json
    {"v":1,"ok":true,"rows":[{"id":1,"email":"a@b.c"}],"meta":{"row_count":1,"truncated":false,"duration_ms":3,"connection":"..."}}

## Reading the result (JSON envelope)

Success is `{"v":1,"ok":true, ...}`:
- `rows` — array of row objects, keys in column order (`query` only).
- `schema` — the schema payload (`schema` only).
- `meta` — fields depend on the command: `query` → `row_count`, `truncated`
  (true = the row limit cut the result; add a WHERE/LIMIT or raise `--limit`),
  `duration_ms`, `connection`; `schema` → `table_count`, `duration_ms`,
  `connection`; `explain` → `duration_ms`, `connection`.
- `warnings` — array of `{code, message}`, omitted when empty. These are NOT
  errors; the answer is valid. Codes include `TRUNCATED`, `SCHEMA_TRUNCATED`,
  `SCHEMA_SAMPLED` (MongoDB: part of that schema answer is a guess drawn from a
  sample — see below), `GUARDRAIL_SKIPPED`, `DUPLICATE_COLUMNS`,
  `UNICODE_STRIPPED`, `INSECURE_TRANSPORT`, `SAMPLE_FALLBACK` (`nyet sample`
  could not draw at random — the rows are the first ones, not a sample),
  `PII_MASKED` (see below).

Failure is `{"v":1,"ok":false,"error":{"code":...,"message":...,"hint":...}}`.
Always read `hint` — it tells you how to fix it. A refusal (`"code":"NYET"`)
also carries a `reason`.

## Exit codes (branch on these; do not parse the text)

    0  success (possibly with warnings)
    1  internal error, or an engine this build does not support yet
    2  CLI usage error
    3  config error (missing/invalid config, or unknown alias)
    4  connection not allowed from the current directory
    5  query refused by nyet — the validator or the guardrail ("code":"NYET")
    6  connection or auth failed
    7  the database returned an execution error
    8  timeout

## MongoDB connections (engine `mongodb`)

A MongoDB alias takes a subset of the **mongosh** syntax instead of SQL:

    nyet query <alias> 'db.users.find({active: true}, {name: 1, _id: 0}).sort({name: 1}).limit(20)'
    nyet query <alias> 'db.orders.aggregate([{$match: {status: "paid"}}, {$group: {_id: "$user_id", total: {$sum: "$amount"}}}])'
    nyet query <alias> 'db.users.countDocuments({active: true})'
    nyet query <alias> 'db.users.distinct("status")'

Accepted: `find` / `findOne` / `aggregate` / `countDocuments` / `distinct`, with
`.sort()`, `.skip()`, `.limit()`, `.toArray()` after `find` (each once). Values
are JSON plus `ObjectId("..")`, `ISODate("..")`, `NumberLong(..)`,
`NumberDecimal("..")`, `UUID("..")`, `/regex/i` and extended JSON
(`{"$oid": ".."}`). Results are documents: the columns are the union of the
top-level field names, and an ObjectId reads back as `{"$oid": ".."}`.

Refused, by an allowlist that is closed by design: every write (including the
`$out`/`$merge` stages anywhere in a pipeline), server-side JavaScript
(`$where`, `$function`, `$accumulator`, `mapReduce`), any `$`-key nyet does not
know, command options (`allowDiskUse`, `let`, `readConcern`, ...) and
`db.runCommand`/`db.adminCommand`. `nyet explain <alias> '<query>'` runs the
same allowlist, so it is not a way around any of this.

`nyet sample <alias> <collection>` works here too (one `$sample` aggregation).
Careful with an empty answer: MongoDB has no catalog to miss, so **0 documents
means the collection is empty OR does not exist** — it is never an error. Check
the name with `nyet schema <alias>` before concluding the data is not there.

`nyet schema <alias>` lists collections and views by name; `nyet schema <alias>
<collection>` describes ONE of them. **MongoDB has no schema, so read the
`source` of every field**: `"validator"` means the collection's declared
`$jsonSchema` — a rule the server enforces — while `"sample"` means nyet
inferred the field from `sampled` random documents and `seen` says in how many
of them it appeared. A field seen in 3 of 100 is not a column; a field absent
from the sample is missing from the answer entirely. `count` is the
collection's document count, nested paths are dotted (`profile.city`, the
spelling a filter takes) and `type` is the BSON type name `{$type: "..."}`
takes.

`nyet explain <alias> '<query>'` returns the query plan without running the
query: `stages` (`COLLSCAN` means no index was usable, `IXSCAN` means one was),
`indexes`, the `rejected` plans and `collection_documents` — the size of the
COLLECTION, not an estimate of the query. MongoDB publishes no cost or row
estimate before execution, so there is none in the answer and no guardrail on
this engine.

## When nyet refuses (exit 5, "code":"NYET")

nyet runs a single read statement only (SELECT, plus SHOW/DESCRIBE/EXPLAIN).
`reason` says why it refused; `hint` says what to do. Fix the query per the
hint and retry — do not resend the same statement, and there is no override
flag. Common reasons:
- `WRITE_OPERATION` — the statement is not a plain read: a write
  (INSERT/UPDATE/DELETE/DDL) anywhere including CTEs and subqueries, a
  `SELECT ... INTO`, or a non-read construct such as any `PRAGMA` (even a
  read-only one — fail closed). Rewrite as a SELECT; for SQLite schema info,
  query `sqlite_master` instead of `PRAGMA`.
- `MULTI_STATEMENT` — send one statement, not several.
- `EXPENSIVE_QUERY` — the plan is over the guardrail limit. The plan is usually
  in the envelope's `estimate`; if planning itself outran its budget there may be
  no `estimate`, so go by `message`/`hint`. Narrow it (add a WHERE filter or a
  LIMIT, join on an indexed column).
- `PII_COLUMN` / `PII_UNPROVABLE` — the query touches a column the config owner
  marked as personal data (see below).
- `DENIED_COMMAND` / `DENIED_OPERATOR` (MongoDB) — the method or the `$`-key is
  not on nyet's read allowlist. The allowlist is closed: anything nyet has not
  reviewed is refused, so check `hint` for what IS allowed rather than retrying
  a variation.
- `DENIED_FUNCTION`, `LOCKING_CLAUSE` (`FOR UPDATE`/`FOR SHARE`),
  `EXPLAIN_ANALYZE`, `TXN_CONTROL`, `EXECUTABLE_COMMENT`, `PARSE_FAILED` — read
  the message and rewrite accordingly.
- `INTERNAL_ERROR` — a bug in nyet itself, not in your query; nothing was
  returned. This is the one reason NOT to rewrite and retry: stop and tell the
  human, quoting the statement and the message.

## Never route around nyet

nyet is the only sanctioned path to these databases. Do not go looking for its
config file, a connection URL, or credentials in the environment, a `.env` or a
secret store; do not connect with `psql`, `mysql`, `mongosh`, `sqlite3`, a
driver or any other client. That holds even when a refusal blocks a task you
were asked to finish: reaching the data another way is a policy violation, not
a workaround, and the human will treat it as one. When the hint does not get
you to an allowed query, stop and tell the human what you needed and why —
they own the config and only they can widen it.

## Protected columns (personal data)

The config owner can mark columns as personal data. `nyet schema` marks them for
you: a column then carries `"pii":"deny"` or `"pii":"mask"` — plan around them
instead of discovering them by refusal.

- `"deny"` — every query that could expose the column is refused
  (`PII_COLUMN`; `PII_UNPROVABLE` when nyet cannot prove where a result column
  came from). Select the other columns instead.
- `"mask"` — you may SELECT the column plainly (`SELECT id, email FROM users`)
  and every value comes back as the literal string `[REDACTED]`, with a
  `PII_MASKED` warning naming the columns. That string is NOT the data: the real
  value, its type and its length are not in the answer, and a masked NULL looks
  like every other masked cell. Never treat it as a value, compare it, or report
  it to the user as one.

In both modes any OTHER use of the column is refused — a `WHERE`/`JOIN ON`/
`USING`, `HAVING`, an alias (`AS e`), an expression around it
(`substr(email,1,3)`), a `SELECT *` of its table, a subquery or CTE that projects
it, and `DISTINCT` over it — because comparing, sorting or grouping by the real
value reads it back out of the row count or the row order. While a masked column
is in the SELECT list, `ORDER BY`/`GROUP BY` accept plain column NAMES only:
`SELECT id, email FROM users ORDER BY id` works, `ORDER BY 1` (or any expression)
is refused.
A masked column also cannot share a SELECT list with `*` or `t.*` (nyet then
cannot tell which result column is which) — list the columns instead.
On a MongoDB connection the same policy protects the field NAME at every depth
of every document: naming it anywhere in the query — a filter, a sort, a
`"$field"` reference, `distinct`, a `$lookup` key — is refused, and a result
of THAT collection that carries the field (even nested, even when the query
never named it) is refused under `"deny"` or comes back as `[REDACTED]` under
`"mask"`. The one `"mask"` relaxation is a plain projection: `{email: 1}` (it
arrives redacted) or `{email: 0}`/`$unset` (it is excluded). Under `"deny"`,
project the fields you need explicitly (`{name: 1, city: 1}`) so the protected
field never enters the result. The policy is keyed on the collection NAME, so a
rule on `users` does not follow the same data into a view or a copy collection
under a different name — the config owner has to name each one; do not assume a
field is safe just because a related collection protects it.

There is no flag, header or retry shape that lifts this: the policy belongs to
whoever owns the config file. If a task genuinely needs the protected data, say
so to the human and ask them.

## Your connections

"#;

/// Instruction template + the user's connections -> the SKILL.md string.
pub fn skill(connections: &Connections) -> String {
    let mut out = String::from(HEAD);
    out.push_str(&connections_section(connections));
    out.push('\n');
    out
}

/// Shell-safe rendering of one argument of a copy-pasteable example: bare when
/// it is a plain identifier, otherwise POSIX single-quoted (only `'` is special
/// inside single quotes, and `'\''` is how it closes, escapes and reopens).
/// `nyet` itself takes the alias as one positional arg, so `nyet query 'prod db'
/// ...` resolves the alias `prod db`.
///
/// Public because the cli prints runnable invocations too — a `sample` fallback
/// suggests the `nyet query` that would draw at random, and THAT argument is
/// SQL: unquoted it carries `"`, `` ` `` and `$(...)` straight into the user's
/// shell. Every example nyet writes goes through here.
pub fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn connections_section(connections: &Connections) -> String {
    match connections {
        Connections::Unavailable => {
            "No nyet config was found (or it could not be read). The user owns the config \
             — once it exists, `nyet list` shows the connections reachable from a given \
             directory. Until then, use the command shapes above with the real alias."
                .to_string()
        }
        // Sorted by alias for a deterministic document; the cli already passes
        // them sorted (BTreeMap), sorted here too so the pure function does not
        // depend on the caller for that.
        Connections::Available(conns) => {
            let mut sorted: Vec<&Conn> = conns.iter().collect();
            sorted.sort_by(|a, b| a.alias.cmp(&b.alias));
            let Some(first) = sorted.first() else {
                return "No connections are reachable from this directory. Run `nyet list` to \
                     confirm, or add this directory to a connection's `allowed_dirs` in \
                     the config."
                    .to_string();
            };
            let mut out = String::from(
                "Reachable from this directory at setup time (run `nyet list` for the \
                 current list):\n\n",
            );
            for conn in &sorted {
                out.push_str(&format!("    {}  {}\n", conn.alias, conn.engine));
            }
            // The runnable example needs an alias clap will read as a positional.
            // A leading `-` alias (`--help`, `-x`) is parsed as an OPTION, and
            // shell quotes do not help (the shell strips them before clap sees
            // the arg), so pick the first alias that is not `-`-led; shell_quote
            // then covers spaces / metacharacters in an arbitrary TOML key.
            match sorted.iter().find(|c| !c.alias.starts_with('-')) {
                Some(c) => {
                    let a = shell_quote(&c.alias);
                    out.push_str(&format!(
                        "\nStart with:\n\n    nyet schema {a} --format json\n    \
                         nyet query {a} \"SELECT 1\" --format json"
                    ));
                }
                // Every alias begins with `-`: pass it after a `--`
                // end-of-options marker so clap reads it as the positional.
                None => {
                    let a = shell_quote(&first.alias);
                    out.push_str(&format!(
                        "\nEvery alias here begins with `-`, so pass it after a `--` \
                         end-of-options marker:\n\n    nyet query --format json -- {a} \"SELECT 1\""
                    ));
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(alias: &str, engine: &str) -> Conn {
        Conn {
            alias: alias.into(),
            engine: engine.into(),
        }
    }

    /// The YAML frontmatter is the first `---`-delimited block; return its
    /// inner lines. Manual parse (no yaml dependency): the generator writes it,
    /// so this checks the shape it must keep.
    fn frontmatter(text: &str) -> Vec<&str> {
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("---"),
            "must open with a frontmatter fence"
        );
        lines.take_while(|l| *l != "---").collect()
    }

    #[test]
    fn frontmatter_is_valid_and_names_the_skill() {
        let text = skill(&Connections::Unavailable);
        let fm = frontmatter(&text);
        // Both required keys present with non-empty values.
        for key in ["name:", "description:"] {
            let line = fm
                .iter()
                .find(|l| l.starts_with(key))
                .unwrap_or_else(|| panic!("frontmatter missing {key}: {fm:?}"));
            let value = line[key.len()..].trim();
            assert!(!value.is_empty(), "{key} value is empty");
        }
        // name is a kebab-safe single token; description says WHEN to use nyet.
        assert!(fm.iter().any(|l| l.trim() == "name: nyet"));
        assert!(fm
            .iter()
            .any(|l| l.starts_with("description:") && l.contains("read-only")));
        // Exactly two lines are a bare `---` fence (open + close); a stray one
        // in the body would corrupt the frontmatter parse.
        assert_eq!(text.lines().filter(|l| *l == "---").count(), 2);
    }

    #[test]
    fn body_teaches_the_core_mechanics() {
        let text = skill(&Connections::Unavailable);
        // Commands.
        for cmd in [
            "nyet list",
            "nyet schema",
            "nyet sample",
            "nyet explain",
            "nyet query",
            "nyet doctor",
        ] {
            assert!(text.contains(cmd), "missing command: {cmd}");
        }
        // Envelope + refusal mechanics (reason + hint) and a sample reason.
        for marker in [
            "\"ok\":true",
            "\"ok\":false",
            "reason",
            "hint",
            "WRITE_OPERATION",
            "EXPENSIVE_QUERY",
            "alias",
            // The PII contract: the agent must know a mask when it sees one.
            "PII_COLUMN",
            "PII_MASKED",
            "[REDACTED]",
            // `sample` draws at random, and says so when it could not.
            "SAMPLE_FALLBACK",
        ] {
            assert!(text.contains(marker), "missing marker: {marker}");
        }
        // Exit codes 0..8 each documented.
        for code in ["0  success", "5  query refused", "8  timeout"] {
            assert!(text.contains(code), "missing exit code line: {code}");
        }
        // Aliases-not-credentials principle — and the rule that makes it hold
        // for a cooperative agent: nyet no longer says where its config is, so
        // the instruction has to say that hunting for it is out of bounds.
        assert!(text.contains("credentials never reach you"));
        assert!(text.contains("Never route around nyet"));
        assert!(text.contains("psql"));
        // Parse examples pass --format json explicitly (the default depends on
        // the user's [defaults].format, so the agent must not rely on it).
        assert!(text.contains("--format json"));
        assert!(text.contains("[defaults].format"));
        // Honest read-only framing (UX-7): "by default" a write is refused, and
        // the config owner can allow specific functions — no absolute guarantee.
        assert!(text.contains("By default a write is refused"));
        assert!(text.contains("allow_functions"));
        assert!(!text.to_lowercase().contains("impossible"));
        // meta fields are per-command (schema has table_count, not row_count).
        assert!(text.contains("table_count"));
        // explain's cost/rows are not universal — SQLite gives no numeric
        // estimate; and the format default is per-command (doctor -> table).
        assert!(text.contains("none on SQLite"));
        assert!(text.contains("defaults to a human table"));
        // WRITE_OPERATION is the catch-all for any non-read statement, PRAGMA
        // included (validator.rs pragma_deny) — the agent must not be surprised.
        assert!(text.contains("PRAGMA"));
        // EXPENSIVE_QUERY does not always carry an estimate (budget-exhausted
        // planning) — say so rather than promising a plan.
        assert!(text.contains("no `estimate`"));
    }

    #[test]
    fn example_aliases_are_shell_quoted_when_unsafe() {
        assert_eq!(shell_quote("prod"), "prod");
        assert_eq!(shell_quote("prod_db-1.x"), "prod_db-1.x");
        assert_eq!(shell_quote("prod db"), "'prod db'");
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        // A space alias reaches the generated example already quoted.
        let text = skill(&Connections::Available(vec![conn("prod db", "postgres")]));
        assert!(
            text.contains("nyet query 'prod db' \"SELECT 1\" --format json"),
            "{text}"
        );
    }

    #[test]
    fn leading_hyphen_alias_never_lands_in_a_broken_runnable_example() {
        // A `-`-led alias is parsed by clap as an option, and shell quotes do
        // not help — so it must not appear as a bare positional in the example.
        // With a normal alias present, the example uses the normal one.
        let text = skill(&Connections::Available(vec![
            conn("--weird", "postgres"),
            conn("prod", "postgres"),
        ]));
        assert!(text.contains("nyet query prod \"SELECT 1\" --format json"));
        assert!(!text.contains("nyet query --weird"));
        // Both are still listed (informational).
        assert!(text.contains("--weird  postgres"));

        // When EVERY alias is `-`-led, the example uses a `--` end-of-options
        // marker so clap reads the alias as the positional.
        let text = skill(&Connections::Available(vec![conn("--weird", "postgres")]));
        assert!(
            text.contains("nyet query --format json -- --weird \"SELECT 1\""),
            "{text}"
        );
    }

    #[test]
    fn dynamic_section_lists_real_connections_sorted_with_an_example() {
        // Deliberately unsorted input: the generator sorts by alias.
        let conns =
            Connections::Available(vec![conn("prod", "postgres"), conn("analytics", "mariadb")]);
        let text = skill(&conns);
        let section = text.split("## Your connections").nth(1).unwrap();
        // Both connections, alias + engine.
        assert!(section.contains("analytics  mariadb"));
        assert!(section.contains("prod  postgres"));
        // Sorted: analytics before prod.
        assert!(
            section.find("analytics").unwrap() < section.find("prod").unwrap(),
            "connections must be sorted by alias"
        );
        // A concrete example uses the first (sorted) real alias, with json.
        assert!(section.contains("nyet query analytics \"SELECT 1\" --format json"));
        assert!(section.contains("nyet schema analytics --format json"));
    }

    #[test]
    fn empty_available_degrades_to_a_hint_not_an_example() {
        let text = skill(&Connections::Available(Vec::new()));
        let section = text.split("## Your connections").nth(1).unwrap();
        assert!(section.contains("No connections are reachable from this directory"));
        assert!(section.contains("allowed_dirs"));
        // No bogus concrete example when there is no real alias.
        assert!(!section.contains("nyet query prod"));
    }

    #[test]
    fn unavailable_config_still_yields_a_full_instruction_with_a_setup_hint() {
        let text = skill(&Connections::Unavailable);
        // The instruction is complete (the agent learns nyet before any setup)...
        assert!(text.contains("## Commands"));
        assert!(text.contains("## Exit codes (branch on these; do not parse the text)"));
        // ...and the dynamic section points at how to configure.
        let section = text.split("## Your connections").nth(1).unwrap();
        assert!(section.contains("No nyet config was found"));
    }
}
