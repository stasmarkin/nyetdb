# Security model

nyet assumes a **cooperative but fallible agent** — one that will write a
`DELETE` by accident, not one actively fighting you. It enforces read-only in
three layers.

| Layer | What it is | Where it holds |
|---|---|---|
| 1 | **The validator** — AST classification before anything touches the database | inside nyet; fail closed, anything not understood is denied |
| 2 | **The session** — `BEGIN READ ONLY`, `mode=ro`, `readonly = 1` | the server refuses a write that slipped past layer 1 |
| 3 | **A read-only database role** | for *every* client, including one that walks around nyet entirely |

Layer 3 is the only one that survives an agent with shell access, which is why
`nyet doctor` reports its absence as a `fail` and every engine page carries a
recipe. MongoDB and Redis have **no layer 2 at all** — see
[ENGINES.md](ENGINES.md).

## The validator

Pipeline: strip invisible Unicode → (MySQL only) reject executable comments →
parse in the engine's own dialect → require exactly one statement → walk the AST
recursively.

The walk denies write and DDL statements **anywhere** in the tree — CTE bodies
including `WITH x AS (DELETE … RETURNING)`, derived tables, subqueries — plus
locking clauses (`FOR UPDATE`/`FOR SHARE`), `COPY`, `SET`, `EXPLAIN ANALYZE`
(which executes what it claims to explain) and denylisted functions. Anything
that fails to parse is denied, not attempted.

**Invisible Unicode** (categories Cf and Cc, except tab/newline/CR) is stripped
before validation and execution, because it can smuggle keywords past a human
reviewer (`SEL<zero-width joiner>ECT`). The verdict applies to the cleaned text;
an accepted query that lost characters carries a `UNICODE_STRIPPED` warning.

## How to read a refusal

A refusal has `code = "NYET"`, exits **5**, and always says why and what to do:

```json
{"v":1,"ok":false,"error":{"code":"NYET","reason":"WRITE_OPERATION","message":"nyet: 'DELETE FROM' is not a read operation","hint":"nyet is read-only; only SELECT, EXPLAIN, SHOW and DESCRIBE statements are accepted — rewrite the task as a read query"}}
```

`error.reason` is a **closed list** an agent may branch on:

| Reason | Meaning |
|---|---|
| `PARSE_FAILED` | could not be parsed — anything not understood is denied |
| `MULTI_STATEMENT` | more than one statement in a single query |
| `WRITE_OPERATION` | not a read, anywhere in the query. MongoDB: a writing method or `$out`/`$merge` in any position. Redis: the server flags the command `write` — or flags it neither way, or does not know it |
| `TXN_CONTROL` | transaction or session control (`BEGIN`/`COMMIT`/`SET`); on ClickHouse also a per-query `SETTINGS` clause |
| `WIRE_FORMAT` | (ClickHouse) a `FORMAT x` clause — pick the output shape with `--format` |
| `LOCKING_CLAUSE` | `SELECT … FOR UPDATE` / `FOR SHARE` — takes row locks, not a plain read |
| `DENIED_FUNCTION` | a function on this connection's denylist. MongoDB: anything running server-side JavaScript |
| `EXPLAIN_ANALYZE` | it *runs* the statement it claims to explain — use `nyet explain` |
| `EXPENSIVE_QUERY` | the plan's estimate is over the guardrail limit, so nothing ran; or planning itself outran its budget |
| `EXECUTABLE_COMMENT` | a MySQL/MariaDB `/*! … */`, `/*M! … */` or `/*+ … */` — the server runs the body, a parser drops it |
| `PII_COLUMN` | the query could expose a column the `[pii]` policy protects |
| `PII_UNPROVABLE` | the database would not state where a result column came from — an undetermined origin is refused, not guessed |
| `DENIED_COMMAND` | (Redis) nyet's own denylist, or the server flags it `admin`/`blocking`/`@dangerous`. (MongoDB) a method not on the read allowlist |
| `DENIED_OPERATOR` | (MongoDB) a `$`-key not on the read allowlist, at any depth — including operators a newer MongoDB adds |
| `UNCLASSIFIED` | (Redis) nyet could not *ask* the server what the command does; grant `+command|info`. The one refusal a rewrite cannot fix |
| `INTERNAL_ERROR` | nyet's own validator crashed — a bug in nyet. The crash is caught and turned into a refusal, so it can never become an unchecked query |

`PRAGMA` is refused with a pointer rather than a dead end: schema questions have
a `SELECT` answer.

## Function denylist

Some functions are dangerous even inside a read-only query, because they act
*outside* the transaction — the filesystem, the network, the cluster. Layer 2
does not stop those, so the validator is the only guard.

| Engine | Denied |
|---|---|
| SQLite | `load_extension`, `fts3_tokenizer`, `readfile`, `writefile`, `edit` |
| MySQL / MariaDB | `load_file`, `sleep`, `benchmark`, `sys_exec`/`sys_eval`, the `get_lock` family, the replication-wait family. `INTO OUTFILE`/`DUMPFILE` fails to parse |
| PostgreSQL | backend kill/cancel, `pg_reload_conf`, `pg_promote`, the `pg_sleep` family, `nextval`/`setval`/`pg_logical_emit_message`, `lo_import`/`lo_export`, `pg_stat_file`, the `dblink*` / `pg_read_*` / `pg_ls_*` prefix families, the whole `*_to_xml` export family, all 11 advisory-lock names, `txid_current`/`pg_current_xact_id`, WAL and backup state, replication slots and origins, `pg_stat_reset*`, index maintenance (`brin_*`, `gin_clean_pending_list`), `pg_import_system_collations`, `pg_notify`, `set_config` |
| ClickHouse | the shortest list, because `readonly = 1` already refuses table functions: `cluster`/`clusterAllReplicas`, `sqlite`, scalar `file`, the `dictGet*` family, `sleep`/`sleepEachRow`, `catboostEvaluate`, `mergeTreeIndex`, plus the egress family and the introspection functions |
| Redis | none — the same config keys name **commands** instead |

None of the PostgreSQL entries is theoretical — each was measured running
inside `BEGIN READ ONLY` on a live server (`query_to_xml`, for one, **executes a
SQL string** nyet never parsed). The per-name evidence is in
[dev/DEV.md](dev/DEV.md).

Matching is case-insensitive on the **terminal** name component, so
`pg_catalog.pg_sleep` and `SELECT * FROM dblink(...)` are caught while a column
merely *named* like a denied function is not. Tune it per connection:

```toml
[connections.localdev.validator]
allow_functions = ["load_extension"]   # remove a built-in entry
deny_functions  = ["my_scary_fn"]      # add your own
```

`allow_functions` removes, `deny_functions` adds, and deny wins a tie. Entries
are **unqualified** names; the prefix families are built in and not tunable.
**Every `allow_functions` entry is a risk you consciously accept** — the
function runs with the database user's privileges even in a read-only session.

## PII columns

Mark the columns that hold personal data and nyet either refuses any query that
could expose them, or returns them redacted.

```toml
[connections.prod.pii]
columns = ["users.email", "users.phone", "customers.ssn"]
mode = "deny"    # deny (default) | mask
```

Entries are `table.column`, one per list entry, written as plain unquoted
identifiers. Matching is **case-insensitive** and the schema qualifier is
ignored — widening the refusal is the only safe direction. A rule nyet cannot
parse *or could never match* is a hard config error (exit 3): a rule that is
accepted but can never fire is worse than a rejected one, because you would
believe the column is protected.

### What gets refused

`PII_COLUMN`, exit 5 — the column named in **any** clause, not just the
projection. A filter is not safer than a `SELECT`: `WHERE email LIKE 'a%'` plus
the row count reads the value one character at a time.

- the column in `SELECT`, `WHERE`, `JOIN ON`, `USING`, `GROUP BY`, `HAVING`,
  `ORDER BY`, a subquery or a CTE — and wrapped in anything (`substr`, `CAST`,
  `md5`, `concat`);
- a `NATURAL JOIN` involving a protected table (the join columns cannot be known
  without the schema);
- a whole-relation read in any spelling — `SELECT *`, `TABLE users`,
  `FROM ONLY users`;
- a whole-row projection of a protected source — `u.*`, the composite
  `SELECT u FROM users u`, a row expansion passed to a function;
- an **unqualified** column name matching a protected column of any table the
  statement reads — without the schema, ownership is unprovable;
- a relation *named* like a protected table, so a CTE called `users` is refused;
  rename the CTE;
- engine catalogs that publish sampled data values — PostgreSQL `pg_stats` and
  friends, MySQL `column_statistics`, SQLite `sqlite_stat3`/`4` — because their
  `most_common_vals` are literal cell values;
- a table source nyet cannot classify, and a result column whose origin the
  database will not state → `PII_UNPROVABLE`.

A wildcard is judged against **its own source**, so `SELECT o.* FROM orders o
JOIN users u …` is fine: `orders` carries no rules.

### `mode = "mask"`

The agent may SELECT the protected column plainly and every value comes back
`[REDACTED]`, with a `PII_MASKED` warning naming the columns.

- **The whole cell goes, in every type — including `NULL`**, so a masked column
  is a JSON string whatever its real type is. A partial mask would leak the
  value piece by piece; a surviving `NULL` would answer "is this on file?".
- **Only the projection is relaxed.** A filter, a join condition, an expression,
  an alias, a wildcard, a `DISTINCT`, an `ORDER BY` position and the same column
  inside a subquery all keep the `deny` behaviour. While a masked column is in
  the SELECT list, `ORDER BY`/`GROUP BY` take plain column **names** only.
- **A cell is redacted only where both nets agree.** If the database reports the
  result column as something other than what the query promised, the answer is
  `PII_UNPROVABLE`, never the value.

Hence the invariant, which holds by construction: **`mask` never returns a value
`deny` would have withheld.**

### How it is enforced

Two independent nets, both fail-closed:

- **Net A — names, before execution.** The validator walks the parsed statement
  and refuses on the rules above, resolving table aliases.
- **Net B — provenance, after execution, before output.** Every result column
  carries the origin the *driver* reported; one that resolves to a protected
  column is refused even if the query never named it. It runs on the single path
  rows can leave the engine, so nothing is formatted, logged or printed until it
  passes.

**Database errors are withheld** on a connection with a PII policy: PostgreSQL
and MySQL quote the offending **cell value** in their messages
(`invalid input syntax for type integer: "alice@example.com"`). The one
exception is a *connect* failure, which happens before any row exists and keeps
its verbatim, actionable message.

Protected columns are marked in `nyet schema` (`"pii": "deny"` / `"mask"`) and
checked by `nyet doctor` (`pii_columns`, `pii_views`).

### Honest limits

- **A mask is not amnesia.** It does nothing about what the agent already read.
- **Views are not followed.** The driver reports a view column's origin as *the
  view*, so a rule on `users.email` does not cover a view over it — list the
  view's own columns too. `nyet doctor`'s `pii_views` check names them for you.
  The same holds for materialized views, set-returning functions and foreign
  tables.
- **Computed columns carry no provenance at all**, on every engine. A rule on
  `users.email` does not cover `email || ''`, nor a `GENERATED` column like
  `email_upper` — that one is a renaming layer *inside* the very table you
  marked, so list it too, or drop it from the role's grants.
- **Counting oracles are not closed.** `row_count`, the guardrail's estimate and
  query timing still respond to filters on *unmarked* columns that correlate
  with protected ones. Refusing every filter would refuse every query.
- **Row order can leak a masked column's sort order.** With a covering index, a
  plain `SELECT id, email FROM users` may come back sorted by `email`; the
  values stay `[REDACTED]`, their relative order does not.
- **The real boundary is the database.** Column-level privileges, curated views
  and RLS are enforced for *every* client:

  ```sql
  REVOKE SELECT ON users FROM nyet_ro;
  GRANT SELECT (id, org_id, created_at) ON users TO nyet_ro;
  ```

  `[pii]` is the fast, local, reviewable layer on top — not a replacement.

### Per engine

- **MongoDB.** A rule is exactly `collection.field` (a deeper path is a config
  error) and protects the field **name at every depth** of every document. Net A
  refuses any query naming it; net B walks the returned documents themselves,
  since they carry their own field names. A handful of operators that move a
  value around without naming it (`$objectToArray`, `$getField`, `$bsonSize`,
  `$$ROOT`, …) is refused up front. The server cannot enforce any of this.
- **ClickHouse.** Net A is the same; net B is **weaker here** — the HTTP
  interface returns no provenance, so nyet compares result column *names*
  instead. That closes a view keeping the column's name, not one that renames
  it; for that, use a column-level `GRANT`. The query log
  (`system.query_log` and friends) is also denied, since it keeps query text.
- **Redis.** A `[pii]` section is a config error — see
  [ENGINES.md](ENGINES.md#redis--valkey).

## Audit log

Letting an agent near a database is only safe if you can see afterwards what it
did, so the log is part of the contract rather than an optional extra. Every
command that reaches a database appends one JSON line to
`~/.local/share/nyet/audit.jsonl` (`$XDG_DATA_HOME/nyet/audit.jsonl`).

```json
{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/me/app","sql":"SELECT id, email FROM users LIMIT 5","verdict":"ok","exit_code":0,"row_count":5,"truncated":false,"duration_ms":12}
{"audit_v":1,"ts":"2026-07-26T12:35:01.114Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/me/app","sql":"DELETE FROM users","verdict":"refused","reason":"WRITE_OPERATION","exit_code":5,"duration_ms":0}
```

- **On by default**, and refusals, database errors and timeouts are logged too —
  the log shows what the agent *tried*.
- `sql` is the **raw** text, so a hidden-character injection stays visible.
- **Never logged: the password, where it lives, or the connection url** — only
  the alias and the engine, so an inline-password url cannot leak into the log.
- `log_responses = true` adds the rows the agent received. Off by default,
  because of volume and the PII in the data itself.
- **Fail-closed.** The record is written *before* the result reaches the agent.
  If the log cannot be written the result is **withheld** — `AUDIT_FAILED`,
  exit 1 — so you never miss an event the agent acted on.
- The file is created `0600`; rotation is external (nyet only appends, and each
  line is written whole under a lock, so it stays valid jsonl across a
  rotation).

```sh
jq -c 'select(.alias=="prod" and .verdict=="refused")' ~/.local/share/nyet/audit.jsonl
```

## What nyet does not protect against

The threat model is a fallible agent, not a hostile one with shell access. An
agent that controls your shell and environment can:

- **rewrite the config** — repointing `url` at a database it controls and having
  nyet hand over the real password;
- **steer the audit log** — the *default* path is resolved from `XDG_DATA_HOME`,
  which the agent's environment controls, so it can send the log elsewhere and
  leave you looking at an empty file. Set an explicit literal `[audit] path` if
  you need a trail that survives that;
- **spoof the working directory**, which is what `allowed_dirs` is compared
  against;
- **connect directly**, without nyet, using the same credentials.

**A read-only role bounds all four; it closes none of them.** It is the thing
that stops any of these from becoming a *write*, which is why `nyet doctor`
treats a missing layer 3 as a failure rather than a suggestion — but a stolen
password is still stolen, a redirected log is still lost, and every one of these
still ends with the agent reading data it was not meant to read.
Confidentiality and the trail need their own answers: column-level grants, a
curated view or RLS for the first; an explicit literal `[audit] path`, on a file
the agent's environment does not steer, for the second.

The full threat model is in [dev/DESIGN.md](dev/DESIGN.md); report a
vulnerability through [SECURITY.md](../SECURITY.md).

The complete allow/deny specification is the public test corpus in
[`tests/corpus/`](../tests/corpus/): every validator rule exists there as at
least one allow and one deny case, and every known bypass is pinned as a corpus
case first, then fixed.
