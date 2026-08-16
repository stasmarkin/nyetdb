# nyetdb — Design (draft)

> **Your AI agent can look. For everything else — nyet.**

The brand and crate are `nyetdb`, the binary is `nyet`. Status: the decisions
are agreed (July 2026), v0.1 can start.

---

## 1. The CLI contract

The stdout/stderr/exit-code contract is a public API for agents. It changes
only through a bump of the `v` field in the response.

### Commands

```
nyet query <alias> <query> [--format json|jsonl|table|csv] [--limit N] [--timeout SECS]
nyet sample <alias> <table> [--format json|jsonl|table|csv] [--limit N] [--timeout SECS]
nyet list [--format json|table]
nyet schema <alias> [table] [--format json|table]
nyet explain <alias> <query> [--format json|table]
nyet doctor [alias] [--format json|table]
nyet agent-setup [--format markdown|json]
```

`sample` is sugar over `query`: nyet writes the query itself (a random sample
of N rows, 10 by default) and runs it through the same pipeline (on Redis it
refuses on the merits: there is no table to take rows from). The envelope,
warnings, error codes and exit codes are exactly those of `query`; there are
no new codes except the `SAMPLE_FALLBACK` warning (the guardrail refused the
random sample — the first N rows were returned instead).

### Streams

- **stdout** — always exactly one JSON envelope (success or error). The agent
  reads one stream and parses one format.
- **stderr** — human-readable diagnostics and logs only (`-v`). The agent does
  not need to parse it.
- The exception is the `table`/`csv`/`jsonl` formats (and the `markdown`
  output of `agent-setup`): the data goes to stdout in its own format, and the
  envelope, without `rows`, goes to stderr as a single JSON line. The
  envelope's destination is decided by the format, not by the outcome: for
  these formats an error envelope also goes to stderr, and stdout stays empty
  on error (stdout carries data only, never the envelope).

### The JSON envelope

Success:

```json
{
  "v": 1,
  "ok": true,
  "rows": [ {"id": 1, "email": "a@b.c"}, ... ],
  "meta": { "row_count": 2, "truncated": false, "duration_ms": 42, "connection": "prod" },
  "warnings": [ {"code": "SLOW_QUERY", "message": "query took 12.3s"} ]
}
```

A refusal by the validator **or by the guardrail** carries the signature code
`NYET`, with the specifics in `reason` (the validator reasons plus
`EXPENSIVE_QUERY`, which belongs to the guardrail; a guardrail refusal
additionally carries a top-level `estimate` field with the plan and the
estimate):

```json
{
  "v": 1,
  "ok": false,
  "error": {
    "code": "NYET",
    "reason": "WRITE_OPERATION",
    "message": "nyet: write operation DELETE found inside WITH clause",
    "hint": "nyet is read-only; rewrite the query without data modification"
  }
}
```

Other errors (config, connection, timeout, database error) use ordinary codes
(`CONFIG_INVALID`, `CONNECTION_FAILED`, `TIMEOUT`, `DB_ERROR`, ...) with no
`reason`. `AUDIT_FAILED` (exit 1, class INTERNAL) means the audit log could
not be written: the result is withheld and the agent gets no data (§4, UX-8).

Stability rules: fields are only ever added; renaming, removing or changing a
type is a breaking change and means a `v` bump. `warnings[].code`,
`error.code` and `error.reason` are part of the contract (closed sets,
documented).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including with warnings) |
| 1 | internal nyet error |
| 2 | CLI usage error (clap default) |
| 3 | config error (missing, invalid, bad permissions) |
| 4 | connection not reachable from the current directory (directory scoping) |
| 5 | query refused by the validator or the guardrail (`error.code = "NYET"`) |
| 6 | connection or auth failure (network, ssh tunnel, credentials) |
| 7 | the database returned an execution error |
| 8 | timeout |

The agent tells classes of failure apart by exit code without parsing text;
the details live in `error.reason` and `error.message`.

---

## 2. Configuration

### Finding the file

`--config <path>` → `$NYET_CONFIG` → `~/.config/nyet/config.toml`. That is all.

**There is deliberately no project config** (`.nyet.toml` in a repository) — a
file in a repository can be created by an agent or arrive through a PR, which
breaks the invariant "only the user creates the config".

### Schema

```toml
# Global defaults (overridable per connection)
[defaults]
row_limit = 1000
timeout_secs = 30
format = "json"
max_row_limit = 10000                  # optional ceilings: the agent's
max_timeout_secs = 60                  # --limit/--timeout cannot exceed them

[audit]                                # global audit policy (UX-8)
enabled = true                         # default true; false for CI/containers
path = "/var/log/nyet/audit.jsonl"     # default $XDG_DATA_HOME/nyet/audit.jsonl; literal-only
log_responses = false                  # default false; true also logs response rows

[connections.prod]
engine = "postgres"                    # postgres | mysql | mariadb | sqlite |
                                       # mongodb | clickhouse | redis (valkey)
url = "postgres://nyet_ro@db.internal:5432/app"
password = { keychain = "prod-db" }    # where the password lives; not in the config
allowed_dirs = ["~/Workspace/app"]     # empty or missing = denied everywhere
row_limit = 500
timeout_secs = 10
max_row_limit = 5000                   # per-connection ceilings override
max_timeout_secs = 30                  # [defaults]

[connections.prod.validator]
allow_functions = ["pg_sleep"]         # drop from the built-in denylist (a deliberate risk)
deny_functions  = ["my_scary_fn"]      # add denials of your own
# on Redis the same pair of keys holds COMMAND names; a command the server
# marked `write` is beyond the reach of allow_functions under any settings

[connections.prod.pii]
columns = ["users.email", "users.phone", "customers.ssn"]  # table.column
                                       # (or schema.table.column); a query
                                       # able to reveal them is refused
mode = "deny"                          # deny (default) | mask: under mask a
                                       # plain projection of the column is
                                       # returned as [REDACTED] + a
                                       # PII_MASKED warning

[connections.prod.guardrail]
mode = "cost"                          # cost | rows | off; the default depends on the engine
max_cost = 1000000.0                   # threshold for mode = "cost" (PostgreSQL only)
max_rows = 10000000                    # threshold for mode = "rows"

[connections.prod.ssh]
host = "deploy@bastion.corp:22"
remote = "db.internal:5432"            # where to forward to from the bastion
control_persist = "15m"                # ControlMaster=auto ControlPersist
reuse_forward = true                   # keep the -L forward between calls (default true)

[connections.localdev]
engine = "sqlite"
path = "./dev.db"                      # sqlite: path instead of url, mode=ro
allowed_dirs = ["~/Workspace/app"]
```

### Rules

- **Secrets**: `password` and `url` are either a literal or a reference to a
  source: `{ keychain = "item" }` (macOS; the ACL checks the calling process's
  signature, so an agent under the same uid does NOT get to read it),
  `{ env = "VAR" }` or `{ command = "..." }` (neither is protected: any
  process of this user reads them). A reference must name exactly one source
  and only as a literal — `${VAR}` inside it is forbidden, as in the policy
  fields, otherwise the agent would swap the source through the environment. A
  source that yielded no value (no such variable, the command failed or stayed
  silent, the item is missing) is a hard error (exit 3), not an empty string.
  `${VAR}` substitution in ordinary string values is unaffected.
- **File permissions**: if the config carries group or other bits — a warning
  on stderr on every run plus an item in `doctor`. Not a refusal, so that
  unusual setups (CI, containers) keep working.
- **`allowed_dirs`**: canonicalized paths (realpath, symlinks resolved, `~`
  expanded) compared by prefix. No globs in v0.1. cwd is taken from the
  process; this is a UX barrier, not a security boundary (see the threat
  model). An empty or missing `allowed_dirs` means denied everywhere (fail
  closed); "reachable from anywhere" is stated explicitly:
  `allowed_dirs = ["~"]`. Entries are static literals only: `${VAR}`
  substitution in `allowed_dirs` is forbidden (the environment is controlled by
  the calling agent — it could widen its own scope), and so are relative paths,
  `..` components and a rooted remainder after `~/` (`~//...`).
- **`validator.allow_functions` / `deny_functions`**: they amend the built-in
  denylist per connection. The policy is configurable; the internal mechanics
  (how the classification is obtained) are not.
- **The `max_row_limit` / `max_timeout_secs` ceilings**: effective = min(the
  usual resolution flag → connection → defaults → built-in, the ceiling). The
  ceiling clamps both the flag and a config value above it (a contradiction
  inside the config resolves towards the stricter side), and the clamp is
  silent. Without the keys the behavior is unchanged. A ceiling of `0` is an
  error (exit 3).
- **`pii.columns`**: the list of protected columns in `table.column` form
  (optionally `schema.table.column`), one column per list entry; a part may be
  double-quoted (`"users"."e-mail"`) when the name cannot be written
  otherwise. A rule that provably cannot match anything (a comma forgotten
  inside a string, a dangling quote) is a hard error: a silently accepted rule
  that does nothing is worse than a rejected one.
  Comparison is case-insensitive and the schema prefix is ignored — erring
  towards a WIDER refusal (Postgres folds unquoted identifiers to lowercase,
  and MySQL's case sensitivity for table names is platform-dependent). A rule
  that fails to parse is a hard error (exit 3), not a quiet "we protect
  nothing". A missing section and `columns = []` are equivalent and mean the
  previous behavior (UX-5). On MongoDB the rule is strictly
  `collection.field` and protects the field NAME at any depth (a deeper path
  is a hard error: it would promise a precision that does not exist); on Redis
  the whole section is a hard error (§3).
- **`pii.mode`**: `deny` (default; a missing key means the previous verdicts
  and the previous rows — the hint texts were rewritten, and `schema` and
  `doctor` gained a marker and a check) | `mask`. `deny` refuses the whole
  query, as before; `mask` allows a plain projection of a protected column but
  replaces EVERY value with `[REDACTED]` (any type, NULL included), and the
  response carries a `PII_MASKED` warning naming the columns. Everything else
  (WHERE, JOIN ON/USING, GROUP BY, HAVING, ORDER BY, DISTINCT, an alias, an
  expression around the column, `SELECT *`/`t.*`/a composite/`TABLE t`, a
  projection in a nested query) is refused under `mask` exactly as under
  `deny` — otherwise the value is read back through row_count or through row
  order. An unknown `mode`, and `mode` without `columns`, are hard errors
  (exit 3).
- **Policy values are literals only**: `${VAR}` substitution is forbidden in
  `allowed_dirs`, `validator.allow_functions`/`deny_functions`,
  `guardrail.mode`, `pii.columns` and `pii.mode`. The environment is
  controlled by the calling agent (threat model), and through these keys it
  would otherwise widen its own scope, lift a function denial or switch the
  guardrail off.
- **`guardrail`**: a mode the engine does not support, an unknown `mode`, a
  threshold `<= 0`, and a threshold the active mode never reads (`max_rows`
  under `mode = "cost"`) are hard errors (exit 3), not a quiet fallback to "no
  guardrail". Who supports what: `cost` — PostgreSQL only (nobody else
  publishes plan cost); `rows` — PostgreSQL, MySQL/MariaDB and ClickHouse, and
  on ClickHouse it is also the default, because `EXPLAIN ESTIMATE` reads part
  metadata without touching a single row; `off` only — SQLite (`EXPLAIN QUERY
  PLAN` carries neither cost nor a row estimate), MongoDB (`queryPlanner`
  gives no estimates, and `executionStats` EXECUTES the query) and Redis (no
  command has a plan or an estimate). There are no global guardrail defaults
  in `[defaults]` (YAGNI): a threshold is a property of one specific database.
- **`[audit]`** (global policy, not per connection): `enabled` (default true —
  auditing is part of the deal, UX-8; `false` for CI and containers), `path`
  (default `$XDG_DATA_HOME/nyet/audit.jsonl` →
  `~/.local/share/nyet/audit.jsonl`), `log_responses` (default false). `path`
  is **literal-only**: `${VAR}` in it is forbidden by the same
  `reject_env_vars_in_policy` rule that covers `allowed_dirs` and
  `guardrail.mode` (the environment is controlled by the agent — otherwise it
  would redirect or silence its own audit trail). A failure to write the log
  gives `AUDIT_FAILED` (exit 1) and the result is NOT handed to the agent
  (fail closed, see §4).
- Unknown keys in the config are a hard error (fail loud, catches typos).

---

## 3. The validator (SQL engines)

Layer 1 of three (layer 2 is the server's read-only for the duration of the
query, layer 3 is the read-only role recommended by `doctor`); not every
engine has layer 2 — see the table below. The principle is **fail closed**:
anything the validator did not understand is refused. Any deny →
`error.code = "NYET"` plus a `reason` from the list below.

### The pipeline

1. **Normalization.** Strip characters in the Unicode Cf/Cc categories (except
   \t \n \r) — protection against zero-width injection into keywords. If any
   were present — the `UNICODE_STRIPPED` warning.
2. **Parsing** with sqlparser-rs using the engine's dialect
   (`PostgreSqlDialect`, `MySqlDialect`, `SQLiteDialect`,
   `ClickHouseDialect`). Fails to parse → deny `PARSE_FAILED`.
3. **Exactly one statement.** Otherwise deny `MULTI_STATEMENT`.
4. **Top-level allowlist:** `Query`, `Explain`, `ExplainTable`, `Show*`,
   `Describe`. Everything else (including `Set*`, `StartTransaction`,
   `Commit`, `Rollback`, any DDL/DML) → deny `WRITE_OPERATION` /
   `TXN_CONTROL`.
5. **Recursive AST walk** (the `visitor` feature): deny if
   Insert/Update/Delete/Merge/Copy/DDL is found inside — this catches writes
   in CTEs (`WITH x AS (DELETE ...) SELECT ...`) and in subqueries.
6. **Locking clauses:** `SELECT ... FOR UPDATE / FOR SHARE` → deny
   `LOCKING_CLAUSE` (layer 2 would reject them too, but the error is clearer
   here).
7. **Function denylist** (extensible, per engine): administrative and
   dangerous functions that work even inside a read-only transaction — for
   PostgreSQL: `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`,
   `pg_promote`, `pg_sleep`, `pg_read_file`, `lo_import`, `dblink*` → deny
   `DENIED_FUNCTION`. The list is a starting point and keeps growing.
   `pg_sleep` is a deny (a silent DoS by occupying the connection pool; an
   agent has no use for it, and the legitimate case is rare and manual).
   Overridable in the config: `validator.allow_functions` / `deny_functions`.

The verdict: `Allow { warnings } | Deny { reason, message, hint }`.

### Layer 2 — session read-only (per engine)

| Engine | Mechanism |
|---|---|
| PostgreSQL | `options=-c default_transaction_read_only=on -c statement_timeout=<ms>`; the query runs in an explicit transaction with `SET TRANSACTION READ ONLY` |
| MySQL/MariaDB | `SET SESSION TRANSACTION READ ONLY`; `max_execution_time` |
| SQLite | the file is opened in `mode=ro` (file-level, stronger than session-level) |
| ClickHouse | `readonly = 1` as a query parameter on EVERY HTTP request — the strongest layer 2 of them all: it cuts writes, any settings change and almost every table function (`url`, `file`, `s3`, `remote`, `executable`, `mysql`, `postgresql`, `mongodb`, `hdfs`, `merge`, `input`, `format`, `loop`, `dictionary` — all `Code: 164 READONLY`, measured on 24.8), because to ClickHouse a table function is simply not a read |
| MongoDB | **none** — session read-only does not exist in MongoDB (`readConcern`/`readPreference` are not permissions; a replica is no barrier: `$out` on a secondary travels to the primary and creates the collection, measured). Layers 1 and 3 remain |
| Redis | **none AT ALL** — no read-only session, no read-only transaction, no switch at connect time: the server offers nothing for the duration of a query. Layer 1 (the classifier) and layer 3 (an ACL account or a replica) remain, and this is the only engine where layer 3 is not advice but the entire server-side boundary; `doctor` does not keep quiet about it, it says so in a dedicated `read_only_session: na` check |

The row limit is client-side: fetch `limit + 1` rows; if more than limit
arrived — `truncated: true` plus a warning.

### ClickHouse — the fourth dialect and the price of failing closed

A ClickHouse connection is an ordinary SQL connection: the same `query`, the
same validator, the same envelope. It differs in a few places, and every one
of them is architectural rather than trivia.

**The dialect.** The main fear about adding a fourth dialect — that some write
would parse as a `Query` and sail past the top-level allowlist — did not
materialize: none of them does.
`INSERT`/`OPTIMIZE`/`TRUNCATE`/`DROP`/`RENAME`/`CREATE`/`GRANT`/`SET`/`USE`
are separate `Statement` variants, while `ALTER … UPDATE/DELETE`, `SYSTEM`,
`KILL`, `DETACH`, `ATTACH`, `BACKUP`, `RESTORE` and `EXCHANGE` do not parse at
all; both outcomes are a refusal. The price lies on the other side and was
paid deliberately: the same dialect fails to parse a handful of LEGITIMATE
reads (`GLOBAL IN`, `GLOBAL ANY LEFT JOIN`, `ASOF JOIN`, `APPLY(...)`,
`EXISTS TABLE`, `view(SELECT …)`, `EXPLAIN indexes = 1`), and those are
refused too — failing closed makes no exceptions for convenient cases. The
list of false refusals is written out in the README as a "how to write it
instead" table, because a hidden false refusal costs more than a named one.

**Two of the refusals come from the AST walk, not from the parser.** A
`SETTINGS k = v` clause inside a query is a `SET` in a query's clothing, so
the verdict is the same `TXN_CONTROL` (layer 2 agrees: under `readonly = 1`
the server would refuse anyway, but exit 5 naming the rule is clearer than
exit 7 with a server error). A `FORMAT x` clause gets the new `WIRE_FORMAT`
reason: the wire format belongs to nyet (it asks for `JSONCompact` and parses
it), and the agent picks the shape of the output through `--format`.

**The layer-1 denylist is short, and every entry is labeled with what it is.**
"Measured past layer 2" means it got through `readonly = 1` on a live server:
`cluster()`/`clusterAllReplicas()` RETURNED rows (they reach other nodes with
the server's own service credentials — the `dblink` class), `sqlite()` and
scalar `file()` made it as far as their own path check, `dictGet*` as far as
resolving the dictionary (and a dictionary can be `SOURCE(HTTP(...))`),
`sleep()` executed, and `mergeTreeIndex()` handed over primary-index granules
— column values without the column ever being named, the `pg_stats` class.
"Denied by class" is the egress family, which layer 2 did stop here: it is on
the list anyway, because layer 2 on this engine is a SETTING nyet asks the
server for, not a property of the server: on an account with a `readonly = 2`
profile the queries run without `readonly = 1` at all, and `2` no longer
counts table functions as writes.

Net B for `[pii]` is weaker here than on the other SQL engines, and this is
the only place where it is weaker: the HTTP interface returns column names and
types and no provenance whatsoever, so there is nobody to ask "which table did
this column come from". Refusing everything as "unprovable" would mean
switching the tool off, so net B compares NAMES: a view that kept the column
name is blocked, a view that renamed it is not (the boundary for that is a
column-level `GRANT`).

### The golden corpus

`tests/corpus/*.yaml`: query + engine + expected verdict (+ reason). Mandatory
coverage: every known bypass (CTE writes, multi-statement, SET, locking,
zero-width unicode, denylisted functions), plus a representative set of
legitimate complex SELECTs (measuring the false-refusal rate is a v0.1
milestone). Non-SQL engines live in subdirectories (`mongo/`, `redis/`) with
their own runners: neither mongosh text nor a Redis command line has any
business inside sqlparser. The Redis corpus has one key found nowhere else —
`flags:`, what `COMMAND INFO` answered on a live 7.4. That is not a smell but
a consequence of WHERE the classification lives: it is server-side, so a
corpus that runs without a server has to bring the server's answer with it.

### Non-SQL engines (implemented)

- Redis (**implemented**, `src/redis.rs`): **the classification comes FROM THE
  SERVER** — `COMMAND INFO` by the exact name, subcommand included
  (`object|encoding`, not `object`, which has no flags at all), and the
  decision is made from the flags.
  This is the exact opposite of the decision taken for MongoDB, and the
  difference is not taste but what the engine publishes: Redis publishes flags
  (`readonly`/`write`/`admin`/`blocking`) and ACL categories, MongoDB
  publishes nothing of the sort — hence a closed allowlist of our own there,
  and no 250-command list of our own here. The server is honest exactly where
  a hand-written list would have been wrong: it marks `GETEX` as `write`
  itself ("because it changes the TTL"), and the same for
  `GETDEL`/`SPOP`/`SORT`/`BITFIELD`/`GEORADIUS`, while their `_RO` twins are
  marked as reads; an unknown name returns nil, so failing closed comes for
  free.
  No cache (see the decision log).

  The rule on top of the flags is short, and its ORDER is the design (each
  step handles what the previous one could not): `write` refuses first, and
  that is a hard boundary `allow_functions` cannot reach — a read-only tool
  that a config can turn into a writing one is not read-only. Then our own
  denylist, and it contains **only the scripting family** (`EVAL`, `EVALSHA`,
  `FCALL`, `SCRIPT`, `FUNCTION`, together with the `_RO` variants the server
  calls reads): Lua is opaque to layer 1 — the same decision as for `$where`
  in MongoDB, since a validator for a second language is a second validator
  that can be wrong — plus a measured DoS: a script occupies the server's
  single thread without preemption, and a loop puts the whole server into BUSY
  until `SCRIPT KILL`. Then "the server does not know this command", `admin`,
  `blocking`, "the server did not call this a read", and the `@dangerous`
  category (whose price is real: it takes `KEYS`, `SORT_RO` and `INFO` with
  it). Everything except `write` is overridable by name by the config's owner
  through `validator.allow_functions`/`deny_functions` — for Redis those are
  command names.

  **The output contract follows the shape of the RESP3 RESPONSE, not the
  command**, and that is the same choice once more: Map → `field`/`value`
  columns, Array/Set → a row per element, scalar/nil → a single row, anything
  nested → JSON in the cell as-is. RESP3 is not a preference here: in RESP2
  the responses of `HGETALL` and `LRANGE` are indistinguishable on the wire,
  and telling them apart would need exactly the command list we managed to
  avoid.

  Reasons: `DENIED_COMMAND` — the same one MongoDB uses (here it is the
  scripting family), and the new `UNCLASSIFIED` — the server did not call the
  command a read. The second one did not come from taste, see the section
  below.

  What Redis does NOT have, stated plainly: layer 2 (see the table above), the
  `[pii]` section (a hard config error: a `table.column` rule cannot match
  anything here — there are no tables, no columns and no names on the wire;
  the ACL key pattern, which the server itself enforces, is offered instead),
  the guardrail (`off` only), a schema (`nyet schema` answers `na` and says
  why, plus what costs nothing: key counters from `INFO keyspace`; nyet does
  not SCAN production on its own initiative) and a plan (`explain` is
  `no_estimate`, but layer 1 still runs, so that `explain` does not become a
  way around the classifier). And `--limit` here is client-side and LATE:
  `LRANGE k 0 -1` pours ten million elements into the process before anything
  counts them.
- MongoDB (**implemented**, `src/mongo.rs`): a parser of our own for a subset
  of mongosh (`db.<collection>.find/findOne/aggregate/countDocuments/distinct`
  and the `.sort/.skip/.limit/.toArray` chains) plus a **closed allowlist**
  over the parsed structure — method names, pipeline stages, operators,
  expressions and accumulators. Any unknown `$` key at any depth is a deny (a
  new writing operator in the next major is refused by default). `$out` and
  `$merge` are denied in ANY position, nested pipelines included (`$lookup`,
  `$unionWith`, `$facet`); server-side JS (`$where`, `$function`,
  `$accumulator`, `mapReduce`, the BSON `$code` value) is always denied.
  New reasons: `DENIED_COMMAND` (a collection method outside the allowlist)
  and `DENIED_OPERATOR` (a `$` key outside the allowlist); `PARSE_FAILED`,
  `WRITE_OPERATION` and `DENIED_FUNCTION` are the same as for SQL.
  Golden corpus: `tests/corpus/mongo/*.yaml`.
  What MongoDB does NOT have, and we say so honestly: layer 2 (see the table
  above) and the guardrail (`explain` in `queryPlanner` mode gives neither
  cost nor a row estimate, and `executionStats` EXECUTES the query — only
  `mode = "off"` is accepted). The `[pii]` section also started out as a hard
  config error, but was implemented later (step PII-M1) — with the nets
  INVERTED: there is no provenance from the server, but the result is
  self-describing, so a strictly `collection.field` rule protects the field
  NAME at any depth, net A refuses on any mention of the name and forbids
  operators that convert names into values (`$objectToArray` and relatives),
  and net B recursively scans the response documents.

  `nyet schema`, `explain` and `doctor` are **implemented**
  (`src/mongo/meta.rs` — pure parsing of the server's answers, `engine::Mongo`
  — IO only):
  - **schema**: MongoDB has no schema, so every field carries a `source` —
    `validator` (a declared `$jsonSchema`, a rule the server applies on every
    write) or `sample` (nyet's inference from `sampled` random documents, plus
    `seen` — in how many of them the field occurred). A guess is never served
    as a schema (UX-7): the whole response carries the new `SCHEMA_SAMPLED`
    warning. Without a collection name — names and kinds only (one round trip;
    describing a collection means sampling it), with `SCHEMA_TRUNCATED`.
  - **explain**: strictly `verbosity: "queryPlanner"` — `executionStats` and
    `allPlansExecution` EXECUTE the query (measured: 1 ms against 4 s on the
    same pipeline). The same layer 1 as for `query` applies here too, so
    explain is not a way around the allowlist. The plan carries neither cost
    nor a row estimate — they are not invented; it carries stages
    (`COLLSCAN`/`IXSCAN`), indexes, rejected plans and
    `collection_documents` (the size of the COLLECTION, not an estimate for
    the query).
  - **doctor**: read-only is proven **without a single write** —
    `connectionStatus {showPrivileges: true}` lists what these credentials may
    do across every resource of the cluster (a write grant in another database
    is a way out through `$out`, measured: `fail`/`warn` naming where). Plus
    the mongo-only `server_side_js` check: there is no runtime parameter for
    server-side JS, so either the server's startup options are read or the
    answer is an honest "could not check" — nyet will not try `$where` or
    `$function` to find out.

### The recommended hardening breaks the tool that recommends it

One pattern surfaced THREE times across two engines, and it deserves its own
place because it will happen again:

1. A ClickHouse account with a `readonly = 1` profile — exactly the one nyet
   advises creating as layer 3 — **cannot change a single setting**, and a
   parameter in the url is precisely a settings change. So nyet's own limits
   (`max_execution_time`, `max_result_rows`, `max_block_size`) return
   `Code: 164` on it, and the first version of the engine did not work at all
   on the recommended account. The cure is a stepwise rollback of the
   parameters; what constrains a query in that case — the account's profile,
   the deadline inside the nyet process, and client-side row truncation — is
   named by `doctor` rather than by silence.
2. An account with a `readonly = 2` profile will not let the setting be
   lowered to `1`, so nyet's queries run under `2`. It looks read-only (writes
   are rejected), but settings can be changed and the server no longer counts
   table functions as writes — meaning only the layer-1 denylist is left
   against them. `doctor` distinguishes this case in the dedicated
   `readonly_setting` check and does not pass `2` off as `1`.
3. A read-only Redis ACL cannot execute `COMMAND INFO`: `COMMAND` is not in
   the `@read` category. And that command IS the classification, so on such an
   account every single query was refused. Three consequences follow: the
   recipe in the README grants `+command|info` (and `+info`, which `nyet
   schema` uses to read key counters), the refusal has its own `UNCLASSIFIED`
   reason — so the agent does not spend turns rewriting a command that is not
   the problem — and `read_only_session` on such an account is `fail`, not
   `na`: that check exists to say what stands in for the missing layer 2, and
   if layer 1 is down, nothing stands.

All three were found not by reading documentation but by running nyet under
the account the README tells you to create. Which is why the integration tests
now do that first.

---

## 4. Threat model

### Assets

The integrity of production data; availability (heavy queries); the
confidentiality of credentials; **the confidentiality of columns the config's
owner marked as PII** (`[connections.X.pii]`).

### In scope (what we protect against)

- **A cooperative but mistaken agent**: an accidental UPDATE/DELETE/DDL, a
  "helpfully cleaned up" table, writes induced by prompt injection from data,
  tickets or PRs.
- **Heavy queries**: a full scan over tens of millions of rows, a missing
  LIMIT — mitigated by the timeout, the row limit and the auto-guardrail via
  EXPLAIN (a plan estimate above the threshold → the query is not executed,
  `NYET`/`EXPENSIVE_QUERY`, exit 5). The guardrail is best effort against
  monsters, not a guarantee: an engine without estimates (SQLite, MongoDB,
  Redis) and an unparsed plan both leave it off (see DEV.md).
- **Credentials reaching the LLM's context**: the agent works with aliases;
  passwords live only in the env or the config, and nyet never prints them to
  stdout, stderr or logs.
- **Disclosure of marked PII columns through a query against a relation nyet
  recognizes by name**: any reference to a protected column (projection,
  WHERE, JOIN ON, `JOIN ... USING` — parenthesized joins included, GROUP BY,
  HAVING, ORDER BY, a subquery, a CTE), a `NATURAL JOIN` with a marked table,
  reading the whole row in any spelling (`SELECT *`, `t.*`, a composite,
  `f(t.*)` in the projection and in source position, `TABLE t`, both forms of
  `FROM ONLY t` / `FROM ONLY (t)`), and a table source nyet could not place in
  any category (→ `PII_UNPROVABLE`; a source recognized as opaque — a
  subquery, a set-returning function, `UNNEST` — is allowed, see "Out of
  scope"), positional renaming through an alias column list
  (`users AS u (a,b,c)`), an unqualified name matching a protected one, and
  THIS engine's catalogs holding data values in statistics (`pg_stats`,
  `information_schema.column_statistics`, `sqlite_stat4`, ...) →
  `NYET`/`PII_COLUMN`, exit 5, BEFORE execution (net A).
  On ClickHouse the query log as a whole falls into the same category
  (`system.query_log` and relatives, `system.processes`): it stores the TEXT
  of queries, so somebody else's `WHERE email = 'a@b.c'` is a protected cell
  quoted verbatim.
  Plus net B: the provenance of the result columns from the driver is checked
  AFTER execution and BEFORE output — a column that turns out to be protected,
  and a column whose origin could not be established, are both refused
  (`PII_COLUMN` / `PII_UNPROVABLE`); on ClickHouse the HTTP interface returns
  no provenance at all, so net B compares column NAMES there (§3), and on
  Redis there is no `[pii]` section whatsoever.
  Net B is a cross-check against the wire: it sees what the server actually
  returned, and so it catches a divergence between nyet's parse and the
  server's parse. It does not judge computed columns at all — they have no
  provenance.
  **The sanction is configurable (`pii.mode`), the boundary of the guarantee
  is not.** Under `mode = "mask"`, instead of a refusal, `[REDACTED]` is
  returned (the whole value, any type, NULL included) plus a `PII_MASKED`
  warning; the relaxation covers ONLY a plain projection of a column that net
  B can prove by provenance — everything else (filters, joins, reading the
  whole row, nested projections, and also sorting, grouping or DISTINCT BY A
  PROTECTED column — by name or by position) is refused as under `deny`. While
  a protected column is in the select list, `ORDER BY` and `GROUP BY` accept
  ONLY bare column names — a position or any expression is refused, because
  nyet does not model which spellings a given planner folds into a column
  reference (measured: `1`, `+1`, `(1)`, `-(-1)`, `0x1`, `0_1`,
  `1 COLLATE NOCASE` are ordinals on some engines, while `1+0` and `abs(1)`
  are ordinals on none). A cell is redacted only if BOTH nets agree: net A
  named the column in the projection, and the driver's provenance confirmed it
  is that column. A divergence in either direction is a refusal: a column
  promised but not redacted → `PII_UNPROVABLE`; a protected column the query
  never named (SQLite resolves a view down to the base table) → a refusal as
  under `deny`, not a mask; a wildcard next to a masked column
  (`SELECT o.*, u.email`) → a refusal, because `*` expands into N columns and
  the positional correspondence cannot be proven. Hence the invariant by
  construction: `mask` never returns a value that `deny` would have held back.
  The mask adds nothing to the list of threats nyet protects against and
  removes nothing from it: it only changes the shape of the answer for the
  very same class of queries. Everything "out of scope" below applies in both
  modes.
- **Exfiltrating a value through the DBMS's error text**: `SELECT email::int`
  returns `invalid input syntax for type integer: "alice@example.com"` — one
  cell per query, past any result filter. On a connection with a PII policy
  the raw database error text is not handed to the agent at all (`DB_ERROR`
  with an honest message). Filtering the text with regexes is not done — that
  would be theater (UX-7).

### Out of scope (what we do NOT protect against — stated honestly)

- **An agent with shell access going around nyet**: it can read the config and
  go to the database directly (psql/nc). The mitigation is not nyet but layer
  3: a read-only database role, which makes direct access read-only too.
  `doctor` checks for it and campaigns for it.
- **Spoofing cwd**: `allowed_dirs` is a UX barrier against accidentally
  hitting the wrong database, not a security boundary.
- **Prompt injection through query results**: complete protection does not
  exist (see the demonstrated attacks of 2026). Mitigations: read-only limits
  the blast radius, the audit log provides forensics; the rest is the
  harness's responsibility. The audit log is implemented (UX-8): every command
  that reaches a database (`query`/`schema`/`explain`/`doctor <alias>`) writes
  one jsonl line into `~/.local/share/nyet/audit.jsonl` — refusals and errors
  included ("what the agent TRIED"). It is on by default and **fails closed**:
  the record is committed before the result is handed over, and a failed write
  gives `AUDIT_FAILED` with no data going to the agent. Credentials are never
  logged (only alias and engine, not the url; the database error text does not
  reach the record either — only `error.code`). The ordering guarantees the
  human cannot miss an event the agent already got to act on. **An explicit
  `[audit] path` is literal-only** (the agent cannot rewrite the pin through
  the env), BUT **the default path resolves from the agent-controlled
  `XDG_DATA_HOME`/`HOME`** — an agent can redirect the default log (the same
  boundary as cwd spoofing: an agent with shell or env access is out of
  scope). An agent-resilient trail needs an explicit literal `path` beyond
  env influence, plus layer 3 (a read-only role).
- **Counting oracles over PII**: `row_count`, the guardrail's `estimate` and
  the execution time still react to filters on UNMARKED columns that correlate
  with protected ones. Closing them would mean forbidding every query. Under
  `mask` it is exactly the same: CELLS are masked, rows are not filtered, so
  the row_count of a masked response is the real one.
- **What the agent already learned**: the mask takes effect when the rule
  appears and does not recall data that already reached the agent's context,
  its logs, or the outside world.
- **Row order**: with an index on a protected column the engine returns rows
  in that column's order for free (measured on SQLite and MySQL 8.4), so under
  the mask what leaks is not the value but the relative ORDER of values.
  Closing that would require forbidding the projection itself, i.e. cancelling
  the mode.
- **GENERATED columns**: a derived column (`upper(email)`) carries its own
  provenance, and a rule on the source column does not cover it — the same
  renaming layer as a view, but inside the "protected" table itself. It is
  listed separately.
- **Views and other server-side renamings**: the rules act on the names nyet
  sees. Postgres and MySQL/MariaDB report the origin of a view's column as THE
  VIEW ITSELF (measured, see DEV.md), so a rule on the base table does not
  cover the view — its columns are listed separately. The same holds for
  materialized views, **set-returning functions** (`RETURNS SETOF users` —
  `SELECT * FROM f()` returns everything, and net B reports the function, not
  the base table) and foreign tables.
  **For COMPUTED columns this is true on every engine, SQLite included**: an
  expression carries no provenance at all, so `contact || ''` and the counting
  oracle `count(*) ... WHERE contact LIKE 'a%'` over an unlisted view are not
  refused even where a bare `contact` is. Closing `Expression` entirely would
  be possible, but it would refuse every aggregate, every expression and every
  set operation on every PII connection — the price was rejected under UX-1,
  not because there is nothing to gain.
- **A relation whose OWN name matches a protected table's name** (a CTE, a
  temp table) is treated as that table — a deliberate false refusal. Telling
  them apart in the AST IS possible (`Query.with` carries the CTE names), but
  doing it correctly needs lexical scoping of names, while `PiiScope` is a
  single flat one for the whole statement; the naive exclusion fails open, see
  the counterexample in DEV.md. The workaround is to rename the CTE.
- **The real confidentiality boundary is the database layer**: column-level
  GRANTs, views and RLS apply to ANY client, including an agent that went
  around nyet. The `[pii]` section is a fast, local, reviewable layer on top,
  not a replacement (recipes are in the README).
- **A hostile human user**: nyet is a user's tool, not an access control
  system between people.

### Process

`SECURITY.md` with a contact for private reports — before the first public
release. Known validator bypasses are recorded in the golden corpus.

---

## Decision log (July 2026)

1. An empty or missing `allowed_dirs` → **denied everywhere** (fail closed);
   "from anywhere" is an explicit `allowed_dirs = ["~"]`.
2. Config permissions with group/other bits → a **warning** on stderr plus an
   item in `doctor`, not a refusal (we do not break CI or containers).
3. `pg_sleep` → **deny** (a silent DoS through the connection pool); the
   denylist is overridable in the config
   (`validator.allow_functions`/`deny_functions`).
4. jsonl → **the envelope as a single JSON line on stderr**, with stdout a
   clean stream of data lines.
5. Redis `COMMAND INFO` → **no cache**: it is asked by the exact command name
   before executing that command (one extra roundtrip, always matching the
   server's version); a cache belongs only as a natural property of the
   connection daemon (v0.5). The mechanics of obtaining the classification are
   not configurable — only the policy is
   (`validator.allow_functions`/`deny_functions`, which for Redis are command
   names).
6. The envelope (both success and error) for non-json formats goes **to
   stderr**; stdout carries data only (and is empty on error). The envelope's
   destination is decided by the format, not by the outcome.

## Decision log (August 2026, ClickHouse and Redis)

7. The `write` flag from the Redis server is a **hard boundary the config
   cannot reach**; everything else (our own denylist, `admin`/`blocking`/
   `@dangerous`, "the server did not call this a read") is overridable by name
   by the config's owner.
8. The Redis output contract follows **the shape of the RESP3 response, not
   the command**; hence also the RESP3 requirement: in RESP2, `HGETALL` and
   `LRANGE` are indistinguishable on the wire, and we would have needed the
   very command list we are avoiding.
9. Redis scripting is denied **entirely**, including the `_RO` variants the
   server calls reads — the same decision as for `$where` in MongoDB, plus a
   measured DoS against the whole server.
10. ClickHouse: `SETTINGS k = v` inside a query → `TXN_CONTROL` (it is a
    `SET`), `FORMAT x` → **the new `WIRE_FORMAT` reason** (the wire format
    belongs to nyet). The dialect's false refusals are not worked around with
    hacks — they are written out in the README together with how to write the
    query instead.
11. ClickHouse: nyet's own query parameters are rolled back **stepwise** if
    the account may not change settings, and `doctor` names the consequences
    (`readonly_setting`) — instead of not working on the recommended account
    or quietly passing `readonly = 2` off as `1`.
