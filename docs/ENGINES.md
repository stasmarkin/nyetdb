# Engines

Six engines, and they are not equally strong. nyet says where an engine is
weaker rather than implying otherwise.

| Engine | `nyet query` takes | Layer 2 — session read-only | Guardrail | `[pii]` |
|---|---|---|---|---|
| [PostgreSQL](#postgresql) | SQL | `BEGIN READ ONLY` + server `statement_timeout` | `cost` / `rows` | full |
| [MySQL / MariaDB](#mysql--mariadb) | SQL | `START TRANSACTION READ ONLY` + `max_execution_time` | `rows` | full |
| [SQLite](#sqlite) | SQL | the file is opened `mode=ro` | — | full |
| [ClickHouse](#clickhouse) | SQL | `readonly = 1` on every request | `rows` | weaker |
| [MongoDB](#mongodb) | a subset of mongosh read syntax | **none** | — | by field name |
| [Redis / Valkey](#redis--valkey) | one command per call | **none** | — | refused |

Cassandra, MSSQL and Elasticsearch resolve the connection and answer
`NOT_IMPLEMENTED`.

**TLS is asked for differently on each engine**, and a direct connection that
does not get it carries an `INSECURE_TRANSPORT` warning:

| Engine | How TLS is asked for | Default |
|---|---|---|
| PostgreSQL | `?sslmode=` in the url | `prefer` — TLS only if the server offers it, silently plaintext if not |
| MySQL / MariaDB | `?ssl-mode=` in the url | `PREFERRED` — same |
| MongoDB | `?tls=true` (a `mongodb+srv://` url turns it on) | off |
| ClickHouse | the scheme: `https://` | off on `http://` |
| Redis / Valkey | the scheme: `rediss://` | off on `redis://` |

On PostgreSQL and MySQL use `verify-full` / `VERIFY_IDENTITY` in production —
`require` encrypts but does not authenticate the server. Over an
[SSH tunnel](GETTING-STARTED.md#ssh-tunnels) the rules differ.

## PostgreSQL

```toml
engine = "postgres"
url = "postgres://nyet_ro@db.internal:5432/app?sslmode=verify-full"
password = { keychain = "nyet-ro" }
```

- **Layer 2:** every query runs in an explicit `BEGIN READ ONLY` transaction on
  a connection opened `default_transaction_read_only=on`, with a server-side
  `statement_timeout` — so a write that slipped past the validator is refused by
  the server, and a runaway query is cancelled server-side (exit 8).
- **TLS:** `sslmode` = `disable` / `prefer` / `require` / `verify-ca` /
  `verify-full`; point `sslrootcert=` at a private CA.
- **Types → JSON:** integers, floats and bool natively; `numeric` → string
  (exact, no rounding); `uuid` / `timestamp` / `date` / `time` → string;
  `json`/`jsonb` → structured; `bytea` → lowercase hex; `NULL` → null. A type
  nyet cannot serialize returns a `DB_ERROR` asking you to `::text`-cast it.
- **Guardrail:** `cost` by default (the planner's own number), or `rows`.

### Read-only role (layer 3)

```sql
CREATE ROLE nyet_ro LOGIN PASSWORD 'set-a-strong-one' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE app TO nyet_ro;
GRANT USAGE ON SCHEMA public TO nyet_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nyet_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO nyet_ro;
```

## MySQL / MariaDB

```toml
engine = "mariadb"   # or "mysql" — same driver and dialect
url = "mysql://nyet_ro@db.internal:3306/shop?ssl-mode=VERIFY_IDENTITY"
```

The label only tells nyet which server-side timeout variable to try first
(MySQL's `max_execution_time` in ms, MariaDB's `max_statement_time` in seconds).
A mislabelled server is still capped — it just costs one extra round trip.

- **Layer 2:** an explicit `START TRANSACTION READ ONLY` plus that server-side
  timeout.
- **TLS:** `ssl-mode` = `DISABLED` / `PREFERRED` / `REQUIRED` / `VERIFY_CA` /
  `VERIFY_IDENTITY`; `ssl-ca=` for a private CA. **MySQL 8's default
  `caching_sha2_password` works with a password over TLS** — `REQUIRED` is
  enough, and it accepts the self-signed certificate MySQL 8 generates itself.
- **Types → JSON:** `DECIMAL` → string (exact); `BIGINT UNSIGNED` as a number
  (may exceed i64); dates and strings → string; `BINARY`/`BLOB` → lowercase hex;
  MySQL `JSON` → structured (on MariaDB it is `LONGTEXT` underneath, so it comes
  back as a JSON string).
- **Guardrail:** `rows` only — neither server reports a comparable plan cost
  through a form that works on both, and nyet does not invent one.
- **Executable comments** (`/*! … */`, `/*M! … */`, `/*+ … */`) are refused: the
  server runs their body, but a SQL parser drops them as ordinary comments.
- If the role reads views, grant it `SHOW VIEW` on them — otherwise the server
  refuses to plan those queries and the guardrail switches off for them (with a
  warning).

### Read-only user (layer 3)

```sql
CREATE USER 'nyet_ro'@'%' IDENTIFIED BY 'set-a-strong-one';
GRANT SELECT ON app.* TO 'nyet_ro'@'%';
FLUSH PRIVILEGES;
```

## SQLite

```toml
engine = "sqlite"
path = "./dev.db"    # required; an absolute path is the predictable choice
```

The file is opened `mode=ro`, so a write that slipped past the validator fails
in the database itself. There is no server, no role and no network, so
`nyet doctor` answers `na` for the role and transport checks rather than
inventing a metric, `[ssh]` is a config error, and the guardrail has nothing to
estimate (`EXPLAIN QUERY PLAN` publishes no cost and no row count) — `off` is
the only accepted mode.

On SQLite a `[pii]` policy is the only thing enforcing itself: there are no
column privileges to hide a column behind.

## ClickHouse

```toml
engine = "clickhouse"
url = "https://nyet_ro@clickhouse.internal:8443/app"   # the HTTP interface
```

The scheme decides TLS — there is no `sslmode`-shaped middle ground to get
subtly wrong — and a plain `http://` url earns an `INSECURE_TRANSPORT` warning.

- **Layer 2 is the strongest here.** nyet sends `readonly = 1` on every request,
  and ClickHouse takes that further than a read-only transaction does: it
  refuses writes, refuses every settings change, and refuses **table functions**
  (`url`, `file`, `s3`, `remote`, `executable`, `mysql`, …). One consequence
  looks like a bug: such an account may not change *any* setting, so nyet's own
  per-request caps are refused — nyet detects that and retries without them,
  leaving the account's profile plus nyet's own deadline as the bounds. Put the
  limits in the profile if you want them enforced server-side.
- **Guardrail:** `rows`, from `EXPLAIN ESTIMATE`, which reads part metadata
  without touching a row — the cheapest true estimate of any engine here. It
  answers for MergeTree tables and comes back empty for system tables and table
  functions, which nyet reports as *no estimate*, never as zero rows.
- **Two clauses are refused by nyet itself:** a per-query `SETTINGS k = v`
  (`SET` in a query's clothes) and `FORMAT x` (the wire format is nyet's — pick
  the output shape with `--format`).
- **Some legitimate reads do not parse**, and fail closed like anything else:

  | Not parsed | Write it as |
  |---|---|
  | `GLOBAL IN`, `GLOBAL ANY LEFT JOIN` | a plain `IN` / `JOIN` |
  | `ASOF JOIN`, `ANY`/`ALL` join modifiers | a join plus a window function |
  | `APPLY(f)` column transformer | name the columns |
  | `EXISTS TABLE t` | `SELECT count() FROM system.tables WHERE name = 't'` |
  | `view(SELECT ...)` table function | a subquery |
  | `EXPLAIN indexes = 1 ...` | plain `EXPLAIN`, or `nyet explain` |

  `FINAL`, `PREWHERE`, `ARRAY JOIN`, `SAMPLE`, `LIMIT … BY`, `WITH FILL`,
  `WITH TOTALS`, `* EXCEPT (…)`, `* REPLACE (…)` and lambdas all work.

### Read-only account (layer 3)

```sql
CREATE USER nyet_ro IDENTIFIED BY 'set-a-strong-one' SETTINGS readonly = 1;
GRANT SELECT ON app.* TO nyet_ro;
```

`readonly = 1`, **not `2`**. `readonly = 2` refuses writes but allows settings
changes, so a client can raise its own limits — and ClickHouse then stops
treating table functions as writes. `nyet doctor` tells the two apart and warns
about the second rather than reporting it as the first.

## MongoDB

```toml
engine = "mongodb"
url = "mongodb://nyet_ro@mongo.internal:27017/events?tls=true"   # db name required
```

nyet never picks a database and offers no way to switch to another one.

**Queries are a subset of the mongosh read syntax** — what you would type in
`mongosh`, not raw BSON command documents:

| Form | Notes |
|---|---|
| `db.<c>.find(<filter>[, <projection>])` | plus `.sort()`, `.skip()`, `.limit()`, `.toArray()`, each at most once |
| `db.<c>.findOne(<filter>[, <projection>])` | a `find` with limit 1 |
| `db.<c>.aggregate([<stages>])` | the pipeline only, no options document |
| `db.<c>.countDocuments([<filter>])` | one row, `{"count": N}` |
| `db.<c>.distinct("<field>"[, <filter>])` | one row per value; a dotted path is refused |

Values are JSON plus the mongosh constructors (`ObjectId`, `ISODate`,
`NumberLong`, `NumberDecimal`, `UUID`), regex literals, and extended JSON in
value position. Comments, trailing commas and either quote style are fine.
Results come back as **relaxed extended JSON** (`{"$oid": …}`, `{"$date": …}`) —
the same spelling you can paste into the next filter. Your own `.limit(n)` can
only lower the connection's limit, never raise it.

**Everything nyet did not explicitly parse is a refusal, never an attempt:**
every writing method and `$out`/`$merge` in *any* position, nested pipelines
included; server-side JavaScript (`$where`, `$function`, `$accumulator`,
`mapReduce`); any unknown `$`-key at any depth — which is what makes a writing
operator from the next MongoDB major refused before anyone has heard of it;
command options (`allowDiskUse`, `readConcern`, …); database-level commands and
the `system.*` catalogs; duplicate field names; nesting past 100 levels or an
input past 64 KiB.

**What MongoDB does not get, said plainly:**

- **No layer 2.** MongoDB has no read-only session, transaction or connection
  flag — `readConcern` and `readPreference` are consistency and routing knobs,
  not permissions, and connecting to a secondary is not a barrier either (a
  write sent there is routed to the primary and executes). The read-only role
  below is therefore the whole story.
- **No guardrail.** `queryPlanner` publishes no cost and no row estimate, and
  `executionStats` mode *runs* the query. `off` is the only accepted mode; the
  row limit and `maxTimeMS` are the backstops.
- **No schema.** `nyet schema <alias>` lists names and kinds; naming a
  collection samples up to 100 documents and marks every inferred field
  `source: "sample"` with `seen` (how many of the sampled documents had it),
  against `source: "validator"` for a declared `$jsonSchema`. Such answers carry
  `SCHEMA_SAMPLED`. For a bigger sample, ask for it as what it is — a query with
  `$sample`.
- **`nyet explain` plans and only plans** (`queryPlanner` verbosity): stages,
  indexes and rejected plans, but no cost and no row estimate.
- **`nyet doctor` proves read-only without writing anything** — it reads the
  whole cluster's privilege list, because a role that is `read` here and
  `readWrite` in a scratch database can copy a collection out.
- **A reply can be cut by the server**, which caps a batch at 16 MiB and can
  reach that before the row limit. nyet reports `truncated: true` rather than
  passing a partial answer off as the whole result; raising `--limit` will not
  help, so narrow the query or project the large fields away.
- **Through an SSH tunnel** nyet forces `directConnection=true` and drops TLS on
  that leg — otherwise the driver would read the replica set's configuration and
  connect to the members' real addresses, straight around your bastion. A
  `mongodb+srv://` url, an explicit `directConnection=false` and an explicit
  `tls=true` are therefore config errors alongside `[ssh]`, rather than
  half-supported.

### Read-only user (layer 3) — not optional here

```js
use events
db.createUser({
  user: "nyet_ro",
  pwd: passwordPrompt(),
  roles: [ { role: "read", db: "events" } ]
})
```

MongoDB has **no field-level privileges**, so a `[pii]` policy has no `REVOKE`
twin. The durable fix is a view that `$unset`s the protected fields plus a role
granted `find` on the view only — which is what `nyet doctor` recommends.

## Redis / Valkey

```toml
engine = "redis"
url = "redis://nyet_ro@cache.internal:6379/0"   # rediss:// for TLS
```

One Redis command per call, with `redis-cli` quoting:

```console
$ nyet query cache 'HGETALL user:42'
{"v":1,"ok":true,"rows":[{"field":"name","value":"Ann"},{"field":"email","value":"a@b.c"}],...}
```

**The classification comes from the server, not from a list nyet keeps.** Before
running anything, nyet asks `COMMAND INFO` about the exact command (subcommand
included) and decides from the flags — one extra round trip, and no list to go
stale. It catches what a hand-written list would miss: `GETEX` is a write
*because it changes the TTL*, `GETDEL`/`SPOP`/`SORT`/`GEORADIUS` are writes
while their `_RO` twins are not, and an unknown name fails closed for free.

The rules on top of those flags, in order:

1. **A command the server flags `write` is refused, and nothing overrules it.**
2. nyet's own denylist: the whole scripting family (`EVAL`, `EVALSHA`, `FCALL`,
   `SCRIPT`, `FUNCTION`, `_RO` variants included) — Lua is opaque to the
   validator, and a script runs uninterrupted on Redis's single thread.
3. `admin`, `blocking` and the `@dangerous` ACL category — which takes `KEYS`,
   `SORT_RO` and `INFO` with it.
4. A command flagged **neither** read nor write (`INFO`, `PING`, `MULTI`,
   `SUBSCRIBE`, `HELLO`) is refused: nyet was not told what it does.

Rules 2–4 are policy, so `validator.allow_functions` overrules them by name —
for Redis those entries are command names (`allow_functions = ["info", "keys"]`).

**Output follows the reply shape** (nyet connects with RESP3 so it can tell them
apart): a map (`HGETALL`, `XINFO STREAM`) gives `field`/`value` rows, an array
or set (`LRANGE`, `SMEMBERS`, `SCAN`) gives one `value` row per element, and a
scalar or nil (`GET`, `TTL`) gives one row. A nested element keeps its structure
as JSON in the cell.

**What is missing, said plainly:** there is no layer 2 at all, so `nyet doctor`
reports `read_only_session: na` rather than leaving the absence unmentioned.
`nyet schema` answers `na` plus the per-database key counts `INFO keyspace`
already publishes — it will not `SCAN` production to invent a schema; run that
yourself when you want it. `nyet explain` has nothing to show, and `nyet sample`
is refused (there is no table to draw from). `--limit` truncation here is
client-side and late: `LRANGE k 0 -1` transfers the whole list first.

A `[pii]` section on a Redis connection is a **hard config error** (exit 3), not
a policy that quietly does nothing — there are no tables, no columns and no
declared fields to match, so it would read as protection and protect nothing.
Use an ACL key pattern instead.

### Read-only account (layer 3) — not optional here either

```
ACL SETUSER nyet_ro on >set-a-strong-one ~* &* -@all +@read +@keyspace -keys +command|info +info
```

Left to right: `-@all` starts from nothing, `+@read` adds the readers,
`+@keyspace` adds `EXISTS`/`TTL`/`TYPE`/`SCAN`, and `-keys` takes `KEYS` back
out. **`+command|info` is not optional** — it is how nyet asks the server what
each command does, and `COMMAND` is not in `@read`; without it *every* query on
the connection is refused as `UNCLASSIFIED`. `+info` is the smaller one: it is
what `nyet schema` reads the key counts with.

Narrow `~*` to a key pattern (`~public:*`) if the agent has no business in the
rest of the key space — **that pattern is the only data boundary Redis offers**.
A replica is the other route to layer 3, and it covers every account at once:
`replica-read-only` makes the server refuse writes outright, and `nyet doctor`
notices.
