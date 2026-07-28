# nyetdb

> **Your AI agent can look. For everything else — nyet.**

`nyet` is a safety-first CLI for read-only database access by AI agents
(Claude Code, Cursor, and other harnesses). One user-owned config file with
credentials, per-directory scoping, layered read-only enforcement (SQL AST
validation + session-level read-only + read-only roles), and JSON output
designed for agents.

Supported: PostgreSQL, MySQL/MariaDB, SQLite, MongoDB.

## Status

**In development.** What works today:

- config: parsing, validation (unknown keys are hard errors), `${VAR}`
  substitution, `password_env`, file permission warnings;
- directory scoping (`allowed_dirs`) and `nyet list`;
- `nyet schema` for all three engines: tables, views, columns, primary keys,
  unique constraints, indexes and foreign keys as structured JSON (see below);
- `nyet query`, `schema`, `explain` and `doctor` for **MongoDB**: a parser for a
  subset of the mongosh read syntax plus a closed allowlist over what it parsed
  (see "MongoDB" below) — reads only, and honestly weaker than the SQL engines
  (no read-only session exists in MongoDB, no guardrail; `[pii]` works, with
  its own mechanics — see "PII columns"). `schema`
  marks every field it INFERRED from a sample as a guess, `explain` shows the
  plan without executing anything and invents no cost, and `doctor` proves
  read-only from the privileges the server publishes — without writing a byte;
- `nyet query` for **SQLite**, **PostgreSQL** and **MySQL/MariaDB**: the full
  SQL validator (read-only allowlist, recursive AST walk, Unicode stripping,
  locking clauses, per-engine function denylist with per-connection policy),
  session read-only enforcement (SQLite `mode=ro`; PostgreSQL
  `default_transaction_read_only` + server `statement_timeout` + an explicit
  `BEGIN READ ONLY`; MySQL/MariaDB an explicit `START TRANSACTION READ ONLY` +
  a server-side `max_execution_time`/`max_statement_time`), row limit, timeout,
  json / jsonl / csv / table output;
- **SSH tunnels** for PostgreSQL and MySQL/MariaDB: reach a database behind a
  bastion by shelling out to the system `ssh` (see the SSH tunnels section below);
- `nyet explain` and the **auto-guardrail**: the query plan, a cost estimate and
  a verdict — and, before `nyet query` runs anything, a refusal for plans whose
  estimate is over the connection's threshold (see below);
- the stable JSON envelope and exit-code contract.

Redis and ClickHouse are wishlist items rather than scheduled work, and each
needs a decision before it is built rather than just a driver — see ROADMAP.
`nyet query` against an engine that is not supported resolves the connection
and returns `NOT_IMPLEMENTED`.
Direct connections **support TLS** (rustls): set `sslmode=require`/`verify-full`
(Postgres) or `ssl-mode=REQUIRED`/`VERIFY_IDENTITY` (MySQL) in the `url` to force
it — otherwise the default (`prefer`/`PREFERRED`) uses TLS only if the server
offers it and may fall back to plaintext (a query over such a connection carries
an `INSECURE_TRANSPORT` warning). MySQL 8's default `caching_sha2_password` works
with a password over TLS (see the connection sections below).

- [Roadmap](ROADMAP.md)
- [Design](docs/DESIGN.md)
- [Development](docs/DEV.md)

## Install

Once a `v*` release is published, install a prebuilt binary with the shell
installer or Homebrew (both produced by the release pipeline — see
[docs/DEV.md](docs/DEV.md)):

```sh
# shell installer (macOS/Linux, x86_64 and aarch64)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/stasmarkin/nyetdb/releases/latest/download/nyetdb-installer.sh | sh

# or Homebrew
brew install stasmarkin/tap/nyetdb
```

Or build from source (any platform with a Rust toolchain):

```sh
cargo install --path .
```

The minimum supported Rust version (MSRV) is stated as `rust-version` in
`Cargo.toml` and checked in CI.

Prebuilt binaries cover macOS and Linux (x86_64 + aarch64). Windows is not
released yet — SSH tunnels and some tests are unix-only; build from source if
you need it.

## Configuration

`nyet` reads exactly one config file, looked up in this order:

1. `--config <path>`
2. `$NYET_CONFIG`
3. `~/.config/nyet/config.toml`

There is deliberately no per-project config file in the repository: a file in
a repo could be created by an agent or arrive via PR, and the config must be
authored by the user only.

Full annotated example:

```toml
# Global defaults, overridable per connection (and by CLI flags).
[defaults]
row_limit = 1000       # max rows returned per query
timeout_secs = 30      # per-query timeout
format = "json"        # default output format: json | jsonl | table | csv
# Optional ceilings: the agent's --limit / --timeout cannot go above these.
max_row_limit = 10000
max_timeout_secs = 60

# Global audit policy (on by default). See the "Audit log" section below.
[audit]
enabled = true                         # false disables logging (CI/containers)
# path = "/var/log/nyet/audit.jsonl"   # default: ~/.local/share/nyet/audit.jsonl
log_responses = false                  # true also logs the result rows

[connections.prod]
engine = "postgres"                    # postgres | mysql | mariadb | sqlite | mongodb
url = "postgres://nyet_ro@db.internal:5432/app"
password_env = "PROD_DB_PASSWORD"      # NAME of an env var; no password in the file
# Directories this connection is reachable from (subdirectories included).
# Empty or absent = denied everywhere (fail closed). "Everywhere" is an
# explicit choice: allowed_dirs = ["~"].
allowed_dirs = ["~/Workspace/app"]
row_limit = 500
timeout_secs = 10
max_row_limit = 5000                   # optional ceilings for this connection,
max_timeout_secs = 30                  # overriding the [defaults] ones

# Validator policy tuning — see the Security section below.
# CAUTION: every allow_functions entry is a conscious risk you take.
[connections.prod.validator]
allow_functions = ["pg_sleep"]         # remove from the built-in denylist
deny_functions = ["my_scary_fn"]       # add your own bans

# Columns that hold personal data. Any query that could expose one is
# refused outright (NYET / PII_COLUMN, exit 5). See "PII columns" below.
[connections.prod.pii]
columns = ["users.email", "users.phone", "customers.ssn"]

# Auto-guardrail: refuse a query whose PLAN is over the limit (see below).
# On by default with a generous limit; which modes exist depends on the engine.
[connections.prod.guardrail]
mode = "cost"                          # cost | rows | off
max_cost = 1000000.0                   # cost mode (PostgreSQL only)
max_rows = 10000000                    # rows mode

# SSH tunnel to reach the database through a bastion (see the section below).
[connections.prod.ssh]
host = "deploy@bastion.corp:22"     # [user@]bastion[:port]
remote = "db.internal:5432"         # host:port to forward to, as seen from the bastion
control_persist = "15m"             # optional; default 15m
reuse_forward = true                # optional; default true — keep the forward between runs

[connections.analytics]
engine = "mariadb"                     # or "mysql" — same driver/dialect
url = "mysql://nyet_ro@db.internal:3306/shop"
password_env = "ANALYTICS_DB_PASSWORD"
allowed_dirs = ["~/Workspace/shop"]

[connections.events]
engine = "mongodb"
# The database name is part of the url and nyet never switches away from it.
url = "mongodb://nyet_ro@mongo.internal:27017/events?tls=true"
password_env = "EVENTS_DB_PASSWORD"
allowed_dirs = ["~/Workspace/app"]
# NOTE: a guardrail mode other than "off" is a hard config error for MongoDB;
# [connections.events.pii] works, with rules of exactly "collection.field" —
# see "MongoDB specifics" and "PII columns" below.

[connections.localdev]
engine = "sqlite"
path = "./dev.db"                      # sqlite uses path instead of url
allowed_dirs = ["~/Workspace/app"]
```

SQLite specifics: `path` points at the database file and is required; a
relative `path` resolves against the directory `nyet` runs from (an absolute
path is the predictable choice). The file is opened read-only (`mode=ro`), so
even a write that somehow slipped past the SQL validator fails in the
database itself.

PostgreSQL specifics: `url` is required (`postgres://user@host:port/dbname`);
put the password in the env var named by `password_env`, never in the file or
the url. If `password_env` is set but the variable is missing, that is a hard
config error (exit 3). With no `password_env`, `nyet` connects without a
password (local trust/peer auth). Every query runs in an explicit
`BEGIN READ ONLY` transaction on a connection opened with
`default_transaction_read_only=on` and a server-side `statement_timeout`, so a
write that slipped past the validator is refused by the server (and a runaway
query is cancelled server-side → exit 8). Result types map to JSON as:
integers/floats/bool natively, `numeric` → string (exact, no rounding),
`uuid`/`timestamp`/`date`/`time` → string, `json`/`jsonb` → structured JSON,
`bytea` → lowercase hex, `NULL` → null; an exotic type nyet cannot serialize
returns a DB_ERROR asking you to `::text`-cast the column. **TLS:** a direct
(non-tunnelled) connection honors the `sslmode` in the `url` —
`disable`/`prefer` (default)/`require`/`verify-ca`/`verify-full`. For production
use `sslmode=verify-full` so the server certificate and hostname are actually
verified (a plain `require` encrypts but does not authenticate the server);
point `sslrootcert=/path/to/ca.pem` in the `url` at a private CA if the cert is
not signed by a public one.

MySQL/MariaDB specifics: use `engine = "mysql"` or `engine = "mariadb"` (they
share the driver and SQL dialect; the only difference is the server-side query
timeout variable — MySQL's `max_execution_time` in milliseconds vs MariaDB's
`max_statement_time` in seconds — which nyet sets for you; the label only tells
nyet which one to try first, so a mislabelled server is still capped, it just
costs one extra round trip per connection). `url` is required
(`mysql://user@host:port/dbname`); the password goes in `password_env`, never in
the file or url. Every query runs inside an explicit `START TRANSACTION READ
ONLY`, so a write that slipped past the validator is refused by the server, and
a runaway query is cancelled server-side → exit 8. Result types map to JSON as:
integers/floats/bool natively, `BIGINT UNSIGNED` as a number (may exceed i64),
`DECIMAL` → string (exact), `DATE`/`DATETIME`/`TIMESTAMP`/`TIME` → string,
`VARCHAR`/`TEXT`/`ENUM` → string, `BINARY`/`BLOB` → lowercase hex, MySQL `JSON`
→ structured JSON, `NULL` → null. (On MariaDB, `JSON` columns are `LONGTEXT`
under the hood, so they come back as a JSON string, not structured.) An exotic
type nyet cannot serialize returns a DB_ERROR asking you to `CAST(col AS CHAR)`.
**TLS:** a direct connection honors the `ssl-mode` in the `url` —
`DISABLED`/`PREFERRED` (default)/`REQUIRED`/`VERIFY_CA`/`VERIFY_IDENTITY`. For
production use `ssl-mode=VERIFY_IDENTITY` (verifies the server certificate and
hostname); point `ssl-ca=/path/to/ca.pem` at a private CA when needed.
**MySQL 8's default `caching_sha2_password` works with a password over TLS** —
use `ssl-mode=REQUIRED` or stricter (`REQUIRED` accepts a self-signed cert; the
auto-generated one MySQL 8 ships is enough to get the password onto an encrypted
channel). MariaDB's default `mysql_native_password` works with or without TLS.

MongoDB specifics: `engine = "mongodb"`, and `url` is required *including the
database name* (`mongodb://user@host:27017/dbname`) — nyet never picks a database
and offers no way to switch to another one. The password goes in
`password_env`. Queries are written in a **subset of the mongosh syntax**
(`db.<collection>.find(...)`, `.aggregate([...])`, `.countDocuments(...)`,
`.distinct(...)`) — see the "MongoDB" usage section below for exactly what is
accepted and why everything else is refused. Result documents map to JSON as
**relaxed extended JSON**: an ObjectId reads `{"$oid": "..."}`, a date
`{"$date": "2026-01-31T00:00:00Z"}`, a `Decimal128` `{"$numberDecimal": "19.99"}`
— the same spelling you can paste back into the next filter. **TLS:** put
`tls=true` in the url (a `mongodb+srv://` url turns it on by default); without
it a query carries the `INSECURE_TRANSPORT` warning. Certificates are verified
against the bundled Mozilla roots; point `tlsCAFile=` at a private CA if needed.
**Handshake:** nyet declares MongoDB's stable API (v1, not strict — the commands
outside it that `doctor` needs still work), which makes the driver open with
`hello` rather than the legacy `isMaster`. Some deployments sit behind a proxy
that answers `hello` and hangs up on the legacy name, and the failure is a bare
`unexpected end of file` that names nothing. A server older than 5.0 does not
understand `apiVersion` at all — nyet recognises it by its wire version and
reconnects once without it, so only those pay the extra round trip.

**Be honest about what MongoDB does NOT get (UX-7).** The SQL engines have three
layers; MongoDB has two, and nyet says so rather than implying otherwise:

- **there is no layer 2** — MongoDB has no read-only session, transaction or
  connection flag. `readConcern` and `readPreference` are consistency and
  routing knobs, not permissions, and **connecting to a secondary is not a
  barrier either**: a write stage sent to a secondary is routed to the primary
  and executes there (measured). So layer 1 (nyet's allowlist) and layer 3 (a
  read-only role) are the whole story — which makes the read-only role below
  much more important here than on the SQL engines.
- **`[pii]` works, but by a different mechanism.** There is no column
  provenance to cross-check, so the rules are `collection.field` exactly (a
  deeper path is a config error) and protect the field NAME at every depth of
  every document: naming it anywhere in a query is refused, and the result
  documents — which carry their own field names — are scanned before anything
  is returned. See "PII columns" for the mechanics and the honest cost. The
  server itself still cannot enforce any of this (no field-level privileges),
  so a view that projects the sensitive fields away plus a role scoped to the
  view remains the boundary that holds for every client — `nyet doctor` says
  exactly that.
- **no auto-guardrail.** MongoDB's `explain` publishes no cost and no row
  estimate in `queryPlanner` mode, and its `executionStats` mode *runs* the
  query — the one thing a guardrail must never do. So `off` is the only
  guardrail mode a MongoDB connection accepts (anything else is a config
  error), and the backstops are the row limit and the timeout. nyet sends
  `maxTimeMS` with every command, so a runaway query is cancelled server-side.
- **there is no schema.** `nyet schema` answers anyway, but it never presents a
  guess as a schema: see "MongoDB schema, explain and doctor" below.
- **server-side JavaScript cannot be checked from the client.** MongoDB exposes
  no runtime parameter for it, so `nyet doctor` reports "could not check"
  unless the account may read the server's startup options — and it will not
  probe by RUNNING JavaScript, which is the one thing nyet promises never to
  send.

### Recommended: a read-only MongoDB user (layer 3)

**On MongoDB this is not optional advice.** There is no read-only session to
fall back on (see above), so the database role is the only thing under nyet's
allowlist:

```js
use events
db.createUser({
  user: "nyet_ro",
  pwd: passwordPrompt(),
  roles: [ { role: "read", db: "events" } ]
})
```

Then `url = "mongodb://nyet_ro@mongo.internal:27017/events?tls=true"` and
`password_env = "NYET_RO_PASSWORD"`. With the `read` role the server refuses
`$out`/`$merge` and every write command outright — nyet's layer 1 simply gets
there first, without a round trip.

### Recommended: a read-only MySQL/MariaDB user (layer 3)

Same idea as the PostgreSQL role: a `SELECT`-only user makes even a direct
connection (bypassing nyet) read-only.

```sql
CREATE USER 'nyet_ro'@'%' IDENTIFIED BY 'set-a-strong-one';
GRANT SELECT ON app.* TO 'nyet_ro'@'%';
FLUSH PRIVILEGES;
```

Then `url = "mysql://nyet_ro@db.internal:3306/app"` and
`password_env = "NYET_RO_PASSWORD"`.

### Recommended: a read-only PostgreSQL role (layer 3)

`nyet` is read-only, but an agent with shell access could bypass it and reach
the database directly (threat model). The durable fix is a read-only role, so
even direct access is read-only. Create one and point `url` at it:

```sql
CREATE ROLE nyet_ro LOGIN PASSWORD 'set-a-strong-one' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE app TO nyet_ro;
GRANT USAGE ON SCHEMA public TO nyet_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nyet_ro;
-- so future tables are readable too:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO nyet_ro;
```

Then `url = "postgres://nyet_ro@db.internal:5432/app"` and
`password_env = "NYET_RO_PASSWORD"`.

### PII columns

A connection can declare which columns hold personal data. `nyet` then either
refuses any query that could expose them, or returns them fully redacted.
The mechanics below are the SQL engines'; MongoDB gets the same policy through
a different pair of nets — see "PII on MongoDB" at the end of this section:

```toml
[connections.prod.pii]
columns = ["users.email", "users.phone", "app.customers.ssn"]
mode = "deny"    # deny (default) | mask
```

Each entry is `table.column`, optionally schema-qualified, written with **plain
unquoted identifiers** — one column per list entry. Matching is
**case-insensitive** and the schema qualifier is **ignored** (only the
`table.column` tail is compared) — quote a part (`"users"."e-mail"`) when the
name cannot be written bare; matching still ignores case. This is because
Postgres folds unquoted identifiers to
lower case, MySQL's table-name case sensitivity depends on the platform, and the
same table can be reached under several qualifications — widening the refusal is
the only safe direction. Anything nyet cannot parse *or could never match* is a
hard config error (exit 3) — for instance a whole list crammed into one string
(`"users.email, users.phone"`, one forgotten comma), or a stray quote.
A rule that is accepted but can never fire is worse than a rejected one: you
would believe the column is protected while every query returns it. An absent
section, or `columns = []`, means no policy at all — an existing config behaves
exactly as before.

`mode` picks the sanction, one per connection: `"deny"` (the default — an absent
key keeps the same verdicts and the same rows as before; refusal `hint` texts
were rewritten and `schema`/`doctor` gained the additions below) refuses the
whole query, `"mask"` additionally
lets a **plain projection** through with every value replaced (see below). An
unknown mode, or a `mode` with no `columns`, is a config error (exit 3): a
sanction that applies to nothing reads as protection that is not there.

Like `allowed_dirs`, `validator.allow_functions` and `guardrail.mode`, this is a
**policy** value: `${VAR}` substitution inside a rule or the mode is rejected
(exit 3). The
environment belongs to the calling agent, and it must not be able to unprotect
its own target. For the same reason **there is no CLI flag to override the
policy** — an agent that can lift its own limit does not have one.

**What gets refused** (`error.reason = "PII_COLUMN"`, exit 5). Everything below
is about relations nyet can identify by name — see the limits section for what
that excludes. Under `mode = "mask"` the list is unchanged except for the first
item's *plain projection* case (`SELECT email FROM users`), which is answered
with `[REDACTED]` instead:

- the column named in any clause — `SELECT`, `WHERE`, `JOIN ON`,
  `JOIN ... USING (col)`, `GROUP BY`, `HAVING`, `ORDER BY`, a subquery or a CTE.
  A filter is not "safer" than a projection: `SELECT count(*) FROM users WHERE
  email LIKE 'a%'` reads the value one character at a time out of the row count,
  and `FROM users JOIN dict USING (email)` does the same through the join —
  parenthesised joins (`FROM (users JOIN dict USING (email))`) included;
- a `NATURAL JOIN` involving a protected table — it joins on every column the
  two relations share, and which ones those are cannot be told without the
  schema;
- a whole-relation read of a protected table in any spelling nyet can see:
  `SELECT * FROM users`, PostgreSQL's `... UNION ALL TABLE users`, and both
  spellings of `FROM ONLY users` / `FROM ONLY (users)`;
- the column wrapped in anything — `substr(email,1,3)`, `CAST(email AS TEXT)`,
  `md5(email)`, `concat(email,'x')`, `json_build_object('e', email)`;
- a whole-row projection of a source that has protected columns —
  `SELECT u.* FROM users u`, PostgreSQL's composite `SELECT u FROM users u`, and
  a row expansion passed to a function, whether the function sits in the
  projection (`json_agg(u.*)`, which really does return every column — verified)
  or in table-source position (`FROM f(u.*)`, `FROM LATERAL f(u.*)`);
- a table source nyet cannot sort into any of its categories — it may be the
  protected table under a spelling nyet reads differently, so it is refused
  (`PII_UNPROVABLE`) rather than assumed harmless. This is a guard against a
  future parser, not a catch-all: a source nyet *does* recognise as opaque (a
  subquery, a set-returning function, `UNNEST`, `JSON_TABLE`) is allowed, and
  what it returns falls under the limits below;
- renaming a protected table's columns positionally with an alias column list
  (`SELECT c FROM users AS u (a, b, c)`) — nyet does not know the real column
  order, so which alias now stands for the protected column is unprovable;
- an **unqualified** column name that matches a protected column of any table
  the statement reads (`SELECT email FROM users u JOIN orders o ON ...`) —
  without the database's schema, ownership is unprovable, so it is refused;
- catalogs of **this engine** that publish sampled data values, on any
  connection with a PII policy: PostgreSQL `pg_stats` / `pg_stats_ext` /
  `pg_statistic` / `pg_statistic_ext_data` (their `most_common_vals` and
  `histogram_bounds` are literal cell values), MySQL/MariaDB
  `information_schema.column_statistics` and `mysql.column_stats`, SQLite
  `sqlite_stat3` / `sqlite_stat4`. The list is per engine, so your own table
  that happens to be called `column_stats` on SQLite is just a table;
- a result column that turns out to come from a protected column even though
  the query never named it (`error.reason` is still `PII_COLUMN`, and
  `PII_UNPROVABLE` when the database will not state a column's origin at all —
  see "How it is enforced" below).

#### `mode = "mask"` — the column comes back redacted

With `mode = "mask"` the agent may **SELECT the protected column plainly**, and
every value in it is replaced before it reaches anything — the answer, the
formatters and the audit log alike:

```
nyet query prod "SELECT id, email FROM users LIMIT 2" --format json
{"v":1,"ok":true,"rows":[{"id":1,"email":"[REDACTED]"},{"id":2,"email":"[REDACTED]"}],
 "meta":{...},"warnings":[{"code":"PII_MASKED","message":"column(s) 'email' are protected ..."}]}
```

Four properties, all deliberate:

- **The whole cell goes, in every type.** `[REDACTED]` is a fixed string, not
  configurable, and it replaces numbers, dates, JSON and **NULL** alike — so the
  masked column is a JSON *string* whatever the column's real type is. A partial
  mask (`j***@gmail.com`) leaks the value piece by piece and a stable token is an
  equality oracle over it; a surviving NULL would answer "is this person's phone
  on file?" for every row.
- **The agent is told.** Every masked answer carries a `PII_MASKED` warning
  naming the columns (never values). Without it an agent reads `[REDACTED]` as
  data and reasons on it.
- **Only the projection is relaxed.** Everything else keeps the `deny` behaviour:
  a `WHERE`/`JOIN ON`/`USING`, `HAVING`, an expression around the column
  (`substr(email,1,3)`), an **alias** (`SELECT email AS e` — SQLite lets `WHERE`
  refer to `e`, which nyet could no longer recognise), a whole-row read
  (`SELECT *`, `t.*`, `TABLE users`, the composite `SELECT u FROM users u`), and
  the same column projected inside a subquery, CTE or UNION arm. Otherwise the
  mask would be theatre: `WHERE email LIKE 'a%'` plus the row count spells the
  value out one character at a time.
- **While a masked column is in the SELECT list, `ORDER BY`/`GROUP BY` take
  plain column NAMES only** — `ORDER BY id`, `ORDER BY u.created_at DESC` and
  `GROUP BY id` work and still return the protected column redacted; a POSITION
  (`ORDER BY 1`) or any expression is refused, and so is `DISTINCT`. Row order
  and row count are the real ones, so ordering by the hidden value ranks every
  other column by it — and nyet does not try to work out which spellings a given
  server folds into a column reference (measured: `1`, `+1`, `(1)`, `-(-1)`,
  `0x1`, `0_1` and `1 COLLATE NOCASE` are all the same ordinal on some engine,
  while `1+0` and `abs(1)` are not on any). Anything it cannot check by name, it
  refuses. Sorting the rows on your side is unaffected.
- **A cell is redacted only where BOTH nets agree.** The query text says which
  column may be masked (that is the relaxation above), and the driver's
  provenance proves the result column really is that one; a value is replaced
  only when the two line up, and anything else is refused exactly as under
  `deny`:
  - the projection was allowed on the promise of a mask and the database then
    reported something else — a computed value, or a base-table column no rule
    names — → `PII_UNPROVABLE` (exit 5), never the value;
  - a protected column reaches the result without the query naming it (SQLite
    resolves a renaming view's column to its base table) → refused, the same as
    under `deny`. nyet does not mask what it was not asked to mask: a column the
    query never named is one nyet could not check the `ORDER BY`/`DISTINCT`
    against, and sorting by a redacted value ranks every other column by it;
  - the SELECT list mixes a wildcard with a column to be masked
    (`SELECT o.*, u.email ...`) → refused: `*` expands into as many columns as
    the source has, so which result column is the protected one cannot be told.
    List the columns instead.

  Hence the invariant, which holds by construction: **`mode = "mask"` never
  returns a value `mode = "deny"` would have withheld.** Every cell it redacts
  belongs to a query `deny` refuses outright, and every query the two modes both
  allow returns byte-identical rows.

Everything the limits section says still applies unchanged: a mask cannot undo
what the agent already learned, and it does not close the counting oracles over
*unmarked* columns.

**What keeps working** — the point is a policy, not a wall:

```
nyet query prod "SELECT count(*) FROM users"          # aggregate, no protected input
nyet query prod "SELECT id, created_at FROM users"    # the unmarked columns
nyet query prod "SELECT * FROM orders"                # a table with no rules
nyet query prod "SELECT * FROM orders WHERE uid IN (SELECT id FROM users)"
nyet query prod "SELECT o.* FROM orders o JOIN users u ON u.id = o.uid"
```

A wildcard is judged against **its own source**: the last two are fine because
`*` and `o.*` expand `orders`, which carries no rules — reading a protected
table elsewhere in the statement does not make them unsafe. The same proof
applies to a qualified column (`SELECT o.email FROM orders o JOIN users u ...`
is fine — `o` provably names `orders`), and to an alias that merely spells a
protected name (`SELECT * FROM orders AS users` is `orders`).

Refusals are deliberately wider than that in two places, both fail-closed:

- an **unqualified** column name is refused wherever it appears in a statement
  that reads a protected table, even if it belongs to another table in the same
  FROM — without the schema, ownership is unprovable;
- a relation that *is* named like a protected table is treated as one, so a CTE
  or a temp table called `users` on a connection with `users.email` rules is
  refused (`WITH users AS (SELECT 1 AS email) SELECT email FROM users`).
  Qualifying does not help — the name is what nyet matches on; **rename the CTE**
  (`WITH signups AS (...) SELECT email FROM signups`).

**Database errors are withheld.** On a connection with a PII policy, `nyet`
never passes the raw text of an error the DATABASE raised while running a
statement — in `query`, `schema`, `explain` and `doctor` alike: PostgreSQL and MySQL
quote the offending **cell value** in their messages (`invalid input syntax for
type integer: "alice@example.com"`), which is an exfiltration channel one cell
per query that no filter on the result can see. The whole message is replaced by
an honest one (`DB_ERROR`, exit 7, "its error text is withheld ... check the
query against the real schema with `nyet schema <alias>`"). Filtering the text
with patterns would be theatre, so nyet does not pretend to. `nyet doctor`
likewise reports its verdicts (connectivity, read-only, superuser) and replaces
the server's wording in its write-probe detail.

**One deliberate exception:** a CONNECT failure keeps its verbatim message
everywhere, `doctor` included (`password authentication failed for user
"nyet_ro"`, `no pg_hba.conf entry for host ...`). A refused handshake happens
before any row exists, so it cannot quote a cell — and hiding it would make
`nyet doctor`, whose entire job is telling you why the connection is broken,
useless exactly when you need it. Connections without a PII policy keep the
verbatim, actionable error everywhere.

#### How it is enforced (and what it does not cover)

Two independent nets, both fail-closed:

- **Net A — names, before execution.** The validator walks the parsed statement
  and refuses on the rules above. Table aliases are resolved, so `FROM users u
  ... u.email` is the same as `users.email`.
- **Net B — provenance, after execution and before output.** Every result column
  carries the origin the *driver* reported. A column that resolves to a
  protected `table.column` is refused (`PII_COLUMN`) even if the query never
  named it; a column whose origin the database will not state is refused as
  `PII_UNPROVABLE`. It runs on the one path rows can leave the engine, so
  nothing is formatted, logged or printed until it passes. `nyet explain`
  returns a plan and no rows, so net A alone applies there.

Net B is a **cross-check on the wire**: it sees what the server actually
returned, which is how a divergence between nyet's parse and the server's
becomes visible. On PostgreSQL and MySQL/MariaDB it keys on the same names net A
checks (the driver reports a view as a view); on SQLite it additionally resolves
a *bare* view column to its base table, which under `deny` refuses the query and
under `mask` refuses it just the same — nyet masks only what the query asked for
by name, never a column it merely discovered. It cannot judge computed columns at
all — those carry no origin.

**Marked in `nyet schema`, checked by `nyet doctor`.** A protected column carries
`"pii": "deny"` / `"pii": "mask"` in `nyet schema` (and `pii deny` / `pii mask`
in the table form), so an agent plans around it instead of spending a round trip
on a refusal. The marking runs after the privilege filter, so a column the role
cannot read is simply absent. `nyet doctor <alias>` adds a `pii_columns` check
that asks the SERVER whether the role can read the marked columns: `ok` when it
cannot (the database enforces the same line), a `warn` naming them when it can —
because then the `[pii]` policy is the only thing there, and anything connecting
with those credentials outside nyet gets the real values. On SQLite the check is
an honest `na`: there are no roles, so nothing can be hidden below nyet.

**Honest limits** (UX-7 — we do not claim what we do not do):

- **A mask is not amnesia.** Redacting a value now does nothing about what the
  agent already read, logged or wrote into its own context before the rule
  existed — and nothing about data reachable outside nyet.
- **Views are not followed.** The rules apply to the names nyet sees, and on
  PostgreSQL and MySQL/MariaDB the driver reports a view column's origin as *the
  view*, not the base table. So a view over a protected table is **not** covered
  by a rule on that table — list the view's own columns too
  (`columns = ["users.email", "v_users.contact"]`). **This holds for computed
  columns on every engine, SQLite included**: an expression carries no
  provenance at all, so while SQLite blocks `SELECT contact FROM v_users`, it
  does not block `SELECT contact || '' FROM v_users` or the row-count oracle
  `SELECT count(*) FROM v_users WHERE contact LIKE 'a%'`. Refusing every
  computed column would close that, and was rejected on **cost**, not because it
  would gain nothing: it would refuse every aggregate, every expression and every
  set operation on every PII connection. Listing the view is the fix that
  actually holds. The same applies to anything else that renames data
  server-side: materialized views, **set-returning functions**
  (`CREATE FUNCTION f() RETURNS SETOF users` — `SELECT * FROM f()` returns
  everything, and net B reports the function, not the base table), foreign
  tables.
- **Counting oracles are not closed.** `row_count`, the guardrail's row
  `estimate` and query timing still respond to filters on *unmarked* columns
  that correlate with protected ones. Refusing every filter would refuse every
  query. This is the same under `mask`: the row count of a masked answer is the
  real one (masking cells is not row filtering), so a correlated *unmarked*
  column still narrows things down.
- **Row ORDER can leak the sort order of a masked column.** `mask` refuses an
  explicit `ORDER BY` on the protected column, but the engine may still return
  rows in that order for free: with an index on the column (measured on SQLite
  and MySQL 8.4, a covering index) a plain `SELECT id, email FROM users` comes
  back sorted by `email`. The values stay `[REDACTED]`; their relative order —
  and therefore the ranking of the *other* columns by the hidden value — does
  not. There is nothing to refuse there short of refusing the projection itself,
  which is the feature; if the ranking matters, do not mark the column, hide it
  with a column-level `GRANT`.
- **A GENERATED column is a renaming layer inside the protected table.** A rule
  on `users.email` does not cover `users.email_upper GENERATED ALWAYS AS
  (upper(email)) STORED`: the driver reports that column's own name, so both
  modes return it, and `WHERE email_upper LIKE 'A%'` is a working
  character-by-character oracle (measured on PostgreSQL). This is the view
  limitation living inside the very table you marked, so it is easy to miss —
  **list the derived columns too**
  (`columns = ["users.email", "users.email_upper"]`), or, better, drop them from
  the role's grants.
- **The real boundary is the database.** nyet is one process an agent with shell
  access can walk around (threat model). Column-level privileges, views and RLS
  are enforced by the server for *every* client:

  ```sql
  -- PostgreSQL: grant the columns, not the table
  REVOKE SELECT ON users FROM nyet_ro;
  GRANT SELECT (id, org_id, created_at) ON users TO nyet_ro;
  -- or expose a curated view and grant only that
  CREATE VIEW users_public AS SELECT id, org_id, created_at FROM users;
  GRANT SELECT ON users_public TO nyet_ro;
  -- row-level policies compose with the above
  ALTER TABLE users ENABLE ROW LEVEL SECURITY;
  CREATE POLICY users_own_org ON users FOR SELECT TO nyet_ro USING (org_id = 7);
  ```

  ```sql
  -- MySQL/MariaDB: column-level grants
  REVOKE SELECT ON app.users FROM 'nyet_ro'@'%';
  GRANT SELECT (id, org_id, created_at) ON app.users TO 'nyet_ro'@'%';
  -- or a view, granted alone (MySQL has no RLS; a WHERE in the view is the idiom)
  CREATE VIEW app.users_public AS SELECT id, org_id, created_at FROM app.users;
  GRANT SELECT ON app.users_public TO 'nyet_ro'@'%';
  FLUSH PRIVILEGES;
  ```

  With those in place `nyet schema` reports only what the role may read, and a
  bypass attempt gets nothing either. The `[pii]` section is the fast, local,
  reviewable layer on top — not a replacement.

**PII on MongoDB.** The same `[pii]` section works on a MongoDB connection, but
the mechanics are inverted, because the two things the SQL nets stand on do not
exist there — a schema to resolve names against, and column provenance from the
server:

- A rule is **exactly `collection.field`** (a deeper path like
  `users.profile.ssn` is a config error) and protects the field **name at
  every depth** of every document — `email` at the top level, inside
  `profile`, inside an array of subdocuments. A same-named field that is not
  personal data is refused too; that is the fail-closed price of having no
  schema to tell them apart.
- **Net A refuses any query that names the field** — a filter key (even inside
  an equality literal: guessing is an oracle), a sort, a projection, a
  `"$field"` reference in a pipeline, `distinct`, a `$lookup`
  `localField`/`foreignField`. The rules follow every collection the query
  reads: `$lookup`/`$graphLookup`/`$unionWith` sources included.
- **Net B scans the result documents themselves.** Documents carry their own
  field names, so before anything is returned nyet walks every document at
  every depth: a protected key refuses the whole answer under `deny` — even
  when the query never named the field (`find({})` returns everything) — and
  is replaced with `[REDACTED]` in place under `mask`, with the same
  `PII_MASKED` warning.
- **Mask's one relaxation** is a plain projection: `{email: 1}` (arrives
  redacted), `{email: 0}` or `$unset` (excluded). Under `deny`, project the
  fields you need (`{name: 1, city: 1}`) so the field never enters the result.
- **A handful of operators is refused on a PII connection**
  (`PII_UNPROVABLE`): `$objectToArray`, `$arrayToObject`, `$getField`,
  `$setField`, `$unsetField`, `$densify`, `$fill`. They move values around
  without naming the field — the one thing the two nets cannot see.
- The server cannot enforce any of this: MongoDB has **no field-level
  privileges**, so unlike the SQL engines there is no `REVOKE` twin of the
  policy. `nyet doctor` reports that as a warning with the honest recipe — a
  view created with `$unset` over the protected fields, and a role granted
  `find` on the view only.

### SSH tunnels (a database behind a bastion)

The common production setup — the database is only reachable from a jump host —
works for PostgreSQL and MySQL/MariaDB by adding an `[ssh]` section to the
connection:

```toml
[connections.prod.ssh]
host = "deploy@bastion.corp:22"     # [user@]bastion[:port]; port defaults to 22
remote = "db.internal:5432"         # the db host:port as resolved from the bastion
control_persist = "15m"             # optional (default 15m); see reuse below
reuse_forward = true                # optional (default true); see reuse below
```

When a query runs, `nyet` shells out to the **system `ssh`** to open a local
port forward (`ssh -f -N -L 127.0.0.1:<random>:db.internal:5432 deploy@bastion.corp -p 22`),
then connects the database engine to `127.0.0.1:<random>`. The `url`'s host and
port are replaced by the tunnel; its user, database and query parameters are
kept, and the password still comes from `password_env`. A free local port is
picked automatically.

- **The forward is reused between runs — at most one per database.** Both the
  `ssh` *master* (`ControlMaster=auto ControlPersist=<control_persist>` over a
  per-destination `ControlPath`) and the *port forward* itself stay in the
  background, so the next `nyet` call opens **no `ssh` process at all**: it only
  asks the master "are you still the one that owns this forward?" (`ssh -O
  check`, a local socket round-trip) and reuses the port. That removes the two
  `ssh` spawns each call used to pay — about 10 ms on a local bastion and over
  100 ms across a WAN one, on every single agent query.

  The rule that keeps this safe: **at most one nyet forward per (bastion, remote
  host:port) pair.** It is recorded in one file under
  `$XDG_RUNTIME_DIR/nyet/` (or `~/.ssh/nyet/`), a directory only your user can
  read, and it is only reused when the port is still occupied *and* the master
  that opened it is still alive with the same pid. If either is not true —
  master gone, forward already released, file corrupt or describing another
  pair — nyet does not reuse it: it opens a fresh forward on a fresh random
  port.

  **Where that inference stops (no security theatre).** "The same master is
  alive and the port is still taken" is not proof that the *listener* is ours:
  nyet cannot see who owns a socket, and no portable way to ask exists. There
  is one state it cannot see through — a forward removed with `ssh -O cancel`
  while its master keeps running. The port then frees, any ordinary local
  process can take it (the kernel hands out that same range), and the next call
  would adopt it and send the database handshake there. That is why `nyet
  doctor` tells you to clean up with `ssh -O exit` — which shuts the master
  down, changes the pid and makes adoption impossible — and never with `ssh -O
  cancel`. If you run `-O cancel` on a nyet forward by hand, either take the
  master with it or expect the next call to be the one that finds out.

  The local port is random, though not as a secret (any local process can list
  loopback listeners). Random means it cannot be captured *before* nyet runs,
  only raced in the instant it frees, and there is no fixed port to hold as a
  denial-of-service handle.

  `control_persist` accepts `yes`/`no` or a time like `15m`/`1h`/`900`; an
  invalid value is a config error (exit 3).
- **What that means in practice (the honest part).** A forward **outlives the
  `nyet` process** — that is the point, and it is a change from earlier
  versions. Consequences to know:
  - it is a loopback listener to your database that stays up between calls, and
    **any process on this machine can reach the database through it** for as
    long as it lives (it does not hand out your password — the database still
    asks — but the network path is open). Previously that window was the length
    of one query; now it is the master's lifetime: `control_persist` of
    inactivity, 15 minutes by default. `control_persist = "yes"` means
    *forever*, until you kill it. On a shared machine, set `reuse_forward =
    false` or a short `control_persist`;
  - `nyet doctor <alias>` shows it — port, whether this call reused it, how old
    it is — and prints the exact `ssh -O exit …` command that removes it (that
    shuts down the shared master, so any other forward through the same bastion
    goes with it and is rebuilt on demand);
  - changing `remote` (or pointing the connection at another database) leaves
    the *old* forward running until its master times out; `doctor` reports the
    pair you are configured for now, not the retired one. `ssh -O exit` clears
    everything at once;
  - if someone kills the master from outside (`ssh -O exit`, a reboot, `pkill`),
    nothing breaks: the next call sees the port free and rebuilds the tunnel;
  - if the network dies silently (laptop suspend, NAT timeout), the master's
    keepalives (`ServerAliveInterval=15`, 3 strikes) tear it down in ~45 s, and
    the next call rebuilds. A query that lands inside that window fails as
    `CONNECTION_FAILED` (exit 6), not as a database error;
  - set `reuse_forward = false` to opt out: the forward is then removed when the
    command exits, exactly as before, at the cost of two `ssh` spawns per call.
    `control_persist = "no"` (no background master at all) implies the same.

  On systems where the `ControlPath` socket would exceed the OS length limit,
  `nyet` skips both master and forward reuse — the tunnel still works, each run
  just pays a fresh handshake.
- **`~/.ssh/config` is inherited.** `nyet` runs your system `ssh`, so host
  aliases, `IdentityFile`, `ProxyJump`, `User`, known-hosts and everything else
  from `~/.ssh/config` apply — put a `Host` block there and set
  `host = "myalias"` in the config if you like.
- **Key/agent auth only — no interactive password.** The tunnel runs with
  `BatchMode=yes`, so `ssh` never prompts: authentication must be non-interactive
  (an SSH key, `ssh-agent`, or `ProxyJump`). A password-only bastion is not
  supported. If auth fails, `nyet` fails fast with `CONNECTION_FAILED` (exit 6)
  and a hint — it never hangs waiting for input. An unreachable bastion is
  bounded by `ConnectTimeout` (derived from the query timeout, capped at 10s), so
  a blackholed host also fails fast.
- **First connection needs a known host key.** With `BatchMode`, `ssh` will not
  interactively accept an unknown bastion key — connect once by hand (or add the
  key to `~/.ssh/known_hosts`) so the host is trusted; the failure hint says so.
- **TLS on the tunnel leg is off by default — and the bastion→DB hop is
  plaintext.** The `nyet`→bastion hop is already encrypted by SSH, so a `url`
  that says nothing about `sslmode`/`ssl-mode` (or asks for `prefer`/`disable`)
  connects to the loopback forward in plaintext and skips a pointless TLS
  handshake. An **explicit `require` or stricter survives the tunnel**, because
  some servers refuse plaintext outright — a managed PostgreSQL behind a pooler
  (Yandex MDB's odyssey answers `SSL is required`) is only reachable that way, so
  put `?sslmode=require` in the `url`. `verify-ca` survives as it is — it
  authenticates the certificate chain without looking at the hostname. Only
  `verify-full` is downgraded, to `verify-ca`: it is the one mode that checks the
  hostname, and the certificate names the real host while the connection goes to
  `127.0.0.1`, so that single step could not succeed anyway. But
  `ssh -L` is a raw TCP forward that **terminates at the bastion**: the
  bastion→database hop is a separate connection. So the database must be in a
  network segment trusted relative to the bastion (or the bastion co-located
  with the DB). To verify the server's identity end to end, use a **direct**
  connection with `sslmode=verify-full`/`ssl-mode=VERIFY_IDENTITY` instead of a
  tunnel.
- **A tunnel failure is `CONNECTION_FAILED` (exit 6)** with a hint: `ssh` missing
  from `PATH`, the bastion unreachable, auth rejected, an unknown host key, or
  the forward refused (`ExitOnForwardFailure=yes`). Try the same `ssh -N -L ...`
  by hand to debug.
- **`host`/`remote` are strictly validated** (exit 3): `[user@]hostname[:port]` /
  `host:port` with safe characters (`A–Z a–z 0–9 . - _`) only. A value that could
  be read as an `ssh` option — a leading `-`, or a `${VAR}` that expands to
  `-oProxyCommand=...` — is rejected at config parse, since the environment is
  agent-controlled (threat model) and would otherwise be an option-injection
  foothold. **IPv6 address literals are not supported** — use a named host.
- **SQLite + `[ssh]` is rejected** (exit 3): a tunnel forwards a TCP port, but
  SQLite is a local file, so ssh does not apply.

> **TLS behavior — encrypt direct connections; the tunnel leg is plaintext
> unless the url asks otherwise.** Direct (non-tunnelled) connections use
> `nyet`'s TLS backend (rustls) and honor the `sslmode`/`ssl-mode` in the `url`.
> Three things to know: (1) the **default** (`prefer`/`PREFERRED`) uses TLS *when
> the server offers it* but silently falls back to plaintext if it does not — set
> `require`/`REQUIRED` to force encryption, and `verify-full`/`VERIFY_IDENTITY`
> to also authenticate the server (recommended for production; a bare `require`
> encrypts but does not verify the certificate, so it does not stop a MITM);
> (2) over an **SSH tunnel** with no `sslmode` in the url, the client→bastion hop
> is encrypted by SSH but the bastion→database hop is a separate plaintext TCP
> connection, so for an end-to-end-encrypted DB link prefer a direct
> `verify-full` connection over a tunnel; (3) an explicit `require` or stricter
> **is kept on the tunnel leg** (see the TLS bullet above) — TLS then runs
> end to end through the forward, and only `verify-full`/`VERIFY_IDENTITY` is
> downgraded, to `verify-ca`/`VERIFY_CA`, because the hostname cannot match
> `127.0.0.1`.

Rules:

- `${VAR}` is substituted in any string value; a missing variable is a hard
  error (exit 3), never an empty string. Exception — **policy values must be
  literal**: `allowed_dirs`, `validator.allow_functions` / `deny_functions` and
  `guardrail.mode` reject `${VAR}` outright, because the environment is
  controlled by the calling agent and substitution there would let it widen its
  own scope, un-deny a function or switch the guardrail off.
- Unknown keys are hard errors — typos fail loudly.
- If the config file is readable by group/others, `nyet` prints a warning to
  stderr (run `chmod 600` on it). Not a refusal, so CI/containers keep working.
- `allowed_dirs` is compared on canonicalized paths (symlinks resolved, `~`
  expanded), by whole path components: `/a/b` does not match `/a/bc`. Entries
  must be static literal paths, absolute or `~/`-relative; relative entries
  (they would depend on the current directory), `~//...` (a rooted remainder),
  `..` components and `${VAR}` substitution (the environment is controlled by
  the calling agent) are rejected — all of them would widen the scope. This is
  a UX guardrail against pointing an agent at the wrong database, not a
  security boundary.

## Usage

```sh
nyet list                  # connections available from the current directory
nyet list --format table   # human-friendly table (envelope goes to stderr)
nyet schema <alias> [table] [--format json|table]
nyet explain <alias> <sql> [--format json|table]
nyet query <alias> <sql> [--format json|jsonl|table|csv] [--limit N] [--timeout SECS]
nyet doctor [alias] [--format json|table]
nyet agent-setup [--format markdown|json]
```

`nyet list` prints aliases and engines only — never URLs or credentials:

```json
{"v":1,"ok":true,"connections":[{"alias":"localdev","engine":"sqlite"}]}
```

### nyet query

```sh
$ nyet query localdev "SELECT id, email FROM users ORDER BY id LIMIT 2"
{"v":1,"ok":true,"rows":[{"id":1,"email":"a@b.c"},{"id":2,"email":"d@e.f"}],"meta":{"row_count":2,"truncated":false,"duration_ms":3,"connection":"localdev"}}
```

Row objects keep column order. `--limit` / `--timeout` beat the
per-connection `row_limit` / `timeout_secs`, which beat `[defaults]`, which
beat the built-ins (1000 rows / 30 s). All of them must be at least 1 — a
zero limit/timeout is rejected (config: exit 3; flag: exit 2); to get the
built-in default, omit the key.

**Ceilings the agent cannot raise.** The flags let an agent go *above* your
configured `row_limit` / `timeout_secs`, which is usually what you want — until
it is not (`--timeout 999999`). Set `max_row_limit` / `max_timeout_secs` (in
`[defaults]`, or per connection, where it overrides `[defaults]`) and the
effective value is capped there: the ceiling beats the flag, and it also caps a
`row_limit`/`timeout_secs` you configured above it — a contradiction in the
config resolves the strict way. Clamping is **silent**: you see the effective
value in the ordinary answer (a `TRUNCATED` warning, or `TIMEOUT` at the
ceiling), and a warning on every call would just cost tokens. Omit the keys and
nothing changes — there is no ceiling by default. If the result has more rows than the limit,
it is cut off and marked — both in `meta` and in `warnings`:

```json
{"v":1,"ok":true,"rows":[...],"meta":{"row_count":1000,"truncated":true,"duration_ms":18,"connection":"localdev"},"warnings":[{"code":"TRUNCATED","message":"result truncated to 1000 rows; add WHERE/LIMIT or raise --limit"}]}
```

`warnings` is omitted when empty. If the result has duplicate column names
(`SELECT 1 AS a, 2 AS a`), json row objects keep both keys but most JSON
parsers let the last value win — nyet flags this with a `DUPLICATE_COLUMNS`
warning suggesting `AS` aliases.

### Output formats

With `--format json` (the default) the whole answer is one envelope on
stdout. The other three formats stream the data on stdout and put the
envelope (without `rows`) on stderr as one JSON line:

- `table` — aligned columns for human eyes;
- `jsonl` — one compact JSON object per row, keys in column order:

  ```sh
  $ nyet query localdev "SELECT id, email FROM users" --format jsonl
  {"id":1,"email":"a@b.c"}
  {"id":2,"email":null}
  ```

  ```
  # stderr: {"v":1,"ok":true,"meta":{"row_count":2,...}}
  ```

- `csv` — header + rows with RFC 4180 quoting (commas, quotes and newlines
  in values are quoted, inner quotes doubled), NULL as an empty field:

  ```sh
  $ nyet query localdev "SELECT id, note FROM notes" --format csv
  id,note
  1,"contains, a comma"
  2,
  ```

  A value beginning with `=`, `+`, `-`, `@` (or a tab/CR) is prefixed with a
  leading `'` to prevent spreadsheet formula injection (CWE-1236) — database
  content can be attacker-influenced, and such a value would otherwise run as
  a formula when opened in Excel/Sheets. This alters those values by one
  character; use `json`/`jsonl` for byte-exact data.

`nyet list` supports `json` and `table` only (it has no row stream); if
`[defaults].format` is `jsonl`/`csv`, `list` falls back to `json`. `nyet schema`
and `nyet explain` follow the same rule.

### MongoDB queries

A MongoDB connection takes a **subset of the mongosh read syntax**, not raw BSON
command documents — the agent writes what it would type in `mongosh`:

```sh
$ nyet query events 'db.users.find({active: true}, {name: 1, _id: 0}).sort({name: 1}).limit(3)'
{"v":1,"ok":true,"rows":[{"name":"ann"},{"name":"bob"}],"meta":{"row_count":2,...}}

$ nyet query events 'db.orders.aggregate([{$match: {status: "paid"}}, {$group: {_id: "$user_id", total: {$sum: "$amount"}}}, {$sort: {total: -1}}, {$limit: 10}])'
$ nyet query events 'db.users.countDocuments({active: true})'
$ nyet query events 'db.users.distinct("status", {active: true})'
```

**What is accepted** (everything else is refused — see below):

| form | notes |
|---|---|
| `db.<collection>.find(<filter>[, <projection>])` | plus `.sort({..})`, `.skip(n)`, `.limit(n)`, `.toArray()`, each at most once |
| `db.<collection>.findOne(<filter>[, <projection>])` | a `find` with `limit 1` |
| `db.<collection>.aggregate([<stages>])` | the pipeline only — no options document |
| `db.<collection>.countDocuments([<filter>])` | answers one row, `{"count": N}` |
| `db.<collection>.distinct("<field>"[, <filter>])` | answers one row per value, column `value`; run as a bounded aggregation, so the row limit applies. A dotted path (`"items.sku"`) is refused — see below |

Values are JSON plus the mongosh type constructors — `ObjectId("..")`,
`ISODate("..")` / `new Date("..")`, `NumberLong(..)`, `NumberInt(..)`,
`NumberDecimal("..")`, `UUID("..")` — regex literals (`/^acme/i`, options
`imsx` only), and **extended JSON in value position** (`{"$oid": ".."}`,
`{"$date": ".."}`, `{"$numberDecimal": ".."}`, ...). Comments (`// ...`,
`/* ... */`), trailing commas, single or double quotes and Unicode in keys and
strings are all fine.

**Everything nyet did not explicitly parse is a refusal, never an attempt.**
The interesting cases, because each is a deliberate decision:

- **Writes** — every writing method (`insertOne`, `updateMany`, `drop`,
  `bulkWrite`, ...) and the `$out`/`$merge` stages, refused **in every
  position**, nested pipelines included (`$lookup`, `$unionWith`, `$facet`).
  The server happens to accept those two stages only as the last top-level
  stage; nyet does not rely on that, because the rule that protects your data
  must not be the server's grammar. → `WRITE_OPERATION`.
- **Server-side JavaScript** — `$where`, `$function`, `$accumulator`,
  `mapReduce` and a `$code` BSON value are **never** allowlisted: they run
  arbitrary code inside the database process, and `maxTimeMS` does not bound
  them (measured). → `DENIED_FUNCTION`.
- **Any unknown `$`-key**, at any depth, in any position. The allowlist is
  closed by construction, which is the whole point: **a writing operator
  introduced by the next MongoDB major is refused by default**, before anyone
  has heard of it. That also covers the undocumented `$_internal*` stages
  (there are ~30, the list grows every release, and at least one of them
  writes under the plain `read` role), the unbounded `$changeStream`, the
  Atlas-only `$search`/`$vectorSearch`, and cluster introspection
  (`$currentOp`, `$collStats`, `$planCacheStats`, `$listCatalog`, ...) whose
  output can quote other sessions' query text. → `DENIED_OPERATOR`.
- **Command options** — `allowDiskUse`, `let`, `readConcern`, `writeConcern`,
  `comment`, `bypassDocumentValidation`, `lsid`, `apiVersion` and friends are
  not accepted: nyet owns the command document, and `limit`, `batchSize`,
  `singleBatch` and `maxTimeMS` are exactly the bounds that make the query
  safe. → `DENIED_COMMAND` (an options document) / `DENIED_OPERATOR` (a
  `$`-spelled one inside a filter).
- **Database-level commands** — `db.runCommand`, `db.adminCommand`,
  `db.getSiblingDB` — and the internal `system.*` catalogs (stored JavaScript,
  view definitions, profiler output that quotes real values). The `system.*`
  rule holds **wherever a collection is named**, not only in
  `db.<collection>`: a stage's own namespace argument (`$lookup.from`,
  `$unionWith`, `$graphLookup.from`) is checked by the same rule, and a
  `{db: ..., coll: ...}` namespace naming another database is refused outright
  — the connection's url names the one database nyet reads.
  → `DENIED_COMMAND`.
- **`distinct` into a sub-document** (`distinct("items.sku")`) is refused
  rather than answered approximately: nyet runs `distinct` as an aggregation so
  that the row limit applies, and that cannot descend through an array on the
  way to a sub-field — it would report whole arrays as distinct values. Write
  it out instead, which also makes what is unwound visible:
  `db.orders.aggregate([{$unwind: "$items"}, {$group: {_id: "$items.sku"}}])`.
  → `DENIED_COMMAND`.
- **A `$binary` value cannot be written** into a filter (it can be read back
  out of a result). For the common case — a UUID — use `UUID("..")`.
  → `DENIED_OPERATOR`.
- **Duplicate field names** in one document (`{a: 1, a: 2}`) are refused.
  BSON permits them and every JSON parser silently keeps one; either choice
  would mean nyet classified a document the server does not evaluate.
  → `PARSE_FAILED`.
- **Nesting past 100 levels** (MongoDB's own BSON limit) and inputs past 64 KiB
  are refused rather than parsed. → `PARSE_FAILED`.

**The row limit and the timeout work as everywhere else.** nyet fetches
`row_limit + 1` documents (`limit` + `batchSize` for a find, a trailing
`$limit` plus a matching `batchSize` for an aggregation) and marks the answer
`truncated`. Your own `.limit(n)` can only **lower** the effective limit, never
raise the connection's. `maxTimeMS` carries the timeout to the server, so a
runaway query is cancelled there (exit 8) rather than only abandoned locally.

**A reply can also be cut by MongoDB itself.** The server caps a batch at
16 MiB, which it can reach *before* the row limit — a collection of megabyte
documents comes back with fewer rows than you asked for. nyet detects that (the
server leaves its cursor open) and reports `truncated: true` with a `TRUNCATED`
warning that says so, instead of presenting a partial answer as the whole
result. Narrow the query or project away the large fields; raising `--limit`
will not help there. (A truncated read leaves a server-side cursor that MongoDB
reaps after ten minutes.)

**Results are documents, so the columns are the union of the top-level field
names** in first-seen order; a document missing one gets `null` there, and
nested documents and arrays stay nested JSON. `--format table` and `--format
csv` therefore work exactly as they do for a PostgreSQL `jsonb` column: the
nested value is rendered as compact JSON in its cell.

**Through an SSH tunnel** nyet forces `directConnection=true` and drops TLS on
the tunnel leg. Both are deliberate: without `directConnection` the driver reads
the replica set's configuration and connects to the members' **real** addresses,
straight around your bastion; and the driver can only verify a certificate
against the address it dialed (`127.0.0.1`), which the server's certificate does
not carry — the ssh hop already encrypts the traffic, and accepting invalid
certificates instead would be security theatre. Two combinations are therefore
refused at config time (exit 3) rather than half-supported: `[ssh]` together
with a `mongodb+srv://` url (SRV re-resolves the cluster's members through DNS
while nyet runs), and `[ssh]` together with an explicit
`directConnection=false`. So is `[ssh]` together with an explicit
`tls=true`/`ssl=true`: nyet would have to ignore it, and leaving you to believe
in encryption it did not apply is worse than an error at startup. Note the
difference from PostgreSQL/MySQL, which keep TLS on the tunnel leg — their
driver can verify a certificate chain without checking the hostname, MongoDB's
cannot, so on that leg the ssh hop is the only encryption.

### MongoDB schema, explain and doctor

**`nyet schema <alias>` lists, `nyet schema <alias> <collection>` describes.**
The listing is one round trip — names and kinds only — because describing a
collection in MongoDB means *sampling* it, and doing that for every collection
would cost several round trips each for an answer nobody asked for. It comes
with a `SCHEMA_TRUNCATED` warning that says exactly that.

**Nothing in that answer pretends to be a schema it is not.** Each field
carries a `source`:

| `source` | what it is | how much to trust it |
|---|---|---|
| `validator` | the collection's declared `$jsonSchema` | a rule the **server enforces on every write** |
| `sample` | inferred by nyet from `sampled` random documents | a guess about the rest of the collection |

A `sample` field also carries `seen` — in how many of the sampled documents it
appeared — because a field present in 3 of 100 documents is not a column, and
an agent has to be able to tell. `sampled` (how many documents were drawn — at
most 100, fewer in a smaller collection) and `count` (the
collection's document count, from its metadata, not a scan) sit on the table
itself, nested paths are dotted (`profile.city` — the spelling a filter takes),
`type` is the BSON type name `{$type: "..."}` takes (several joined by `|` when
the documents disagree), `_id` is marked as the key and indexes come from
`listIndexes`. Every such answer carries the `SCHEMA_SAMPLED` warning.

```json
{"name":"users","kind":"collection","count":51234,"sampled":100,
 "columns":[{"name":"_id","type":"objectId","nullable":false,"pk":true,"source":"sample","seen":100},
            {"name":"email","type":"string","nullable":false,"unique":true,"source":"validator","seen":100},
            {"name":"profile.city","type":"string","nullable":true,"source":"sample","seen":37}],
 "indexes":[{"name":"created_at_-1","columns":["created_at"]}]}
```

The sample size is not configurable (like the 50-object detail limit): when you
want a bigger one, ask for it as what it is — a query:
`nyet query <alias> 'db.users.aggregate([{$sample: {size: 1000}}])'`. At most
100 inferred fields are listed per collection (rarest dropped first) and paths go three
levels deep — a schemaless "field names are user ids" collection must not burn
your agent's context. If the role may not run `listCollections` (the common
case when it is scoped to a single view), the listing still works
(`authorizedCollections`) and a named collection is still sampled — but nyet
then cannot read the declared validator, so **the absence of `source:
"validator"` never means "there is no validator"**.

**`nyet explain <alias> '<query>'` plans, and only plans.** nyet asks for
`verbosity: "queryPlanner"` and nothing else, because `executionStats` and
`allPlansExecution` *execute* the query (measured: 1 ms vs 4 s on the same
pipeline). The same layer 1 applies as for `query`, so `explain` is not a way
around the allowlist — `db.c.aggregate([{$out: "copy"}])` is refused here too
(exit 5). The plan carries `stages` (a `COLLSCAN` means no index was usable, an
`IXSCAN` means one was), the `indexes` used, the `rejected` plans and the
winning plan verbatim (`indexBounds` included — that is where "why did my regex
not use the index" is answered). There is **no cost and no row estimate**:
MongoDB publishes neither before execution, and nyet does not manufacture one.
`collection_documents` is the size of the *collection*, so that "COLLSCAN"
reads as "COLLSCAN over 40 million documents" — it is not an estimate of the
query.

**`nyet doctor <alias>` proves read-only by asking, not by writing.** On the SQL
engines doctor runs a probe write inside a transaction it rolls back; on
MongoDB it runs none at all — `connectionStatus {showPrivileges: true}` lists
every action these credentials hold on every resource of the cluster, and nyet
checks that none of them writes. It checks the **whole cluster**, not just this
database: a role that is `read` here and `readWrite` in a scratch database can
copy a collection out with `$out: {db: "scratch", coll: "exfil"}` (measured) —
nyet's own allowlist refuses `$out`, but another client with the same
credentials will not. Write actions elsewhere are a `warn`, write actions here
(or on the cluster) a `fail`, and an action nyet cannot classify is reported
rather than assumed harmless. The MongoDB-only `server_side_js` check is the
honest one: `$where`/`$function`/`$accumulator` run arbitrary code in the
database process, the plain `read` role is allowed to use them and `maxTimeMS`
does not bound them (measured: 8 s and 12 s under a 500 ms limit). nyet refuses
all of it — but only for queries going through nyet. MongoDB exposes no runtime
parameter for the setting, so doctor reads the server's startup options if the
account may (`--noscripting` → `ok`), and otherwise says **"could not check"**
with the reason. It will not probe by running JavaScript.

### nyet schema

```sh
nyet schema <alias>          # every table and view
nyet schema <alias> <table>  # one object, always in full detail
```

Introspection without writing catalog SQL: tables and views with their
columns, primary keys, unique constraints, indexes and foreign keys, in one
envelope.

```sh
$ nyet schema prod users
{"v":1,"ok":true,"schema":{"tables":[{"name":"users","kind":"table","columns":[{"name":"id","type":"bigint","nullable":false,"pk":true,"default":"nextval('users_id_seq'::regclass)"},{"name":"email","type":"text","nullable":false,"unique":true},{"name":"org_id","type":"bigint","nullable":true}],"indexes":[{"name":"users_org_idx","columns":["org_id"]}],"fks":[{"columns":["org_id"],"ref_table":"orgs","ref_columns":["id"]}]}]},"meta":{"table_count":1,"duration_ms":12,"connection":"prod"}}
```

How to read it:

- `kind` is `"table"` or `"view"`. Views carry columns but never indexes or
  foreign keys.
- `nullable` is always present. `pk` and `unique` appear **only when true**,
  and `default` only when the engine reports one — omitted fields mean
  "false"/"none" (bytes an agent does not pay for).
- **`pk`** marks every member of the primary key, so a composite key has
  `pk: true` on each of its columns. A pk column is always reported
  `nullable: false`.
- **`unique`** on a column means there is a unique index/constraint whose only
  key part is that very column, unconditional and valid — precisely the case
  where the flag says everything, so that index is not repeated under
  `indexes`. Everything else stays an index entry: multi-column unique indexes
  (with `"unique": true`), partial or invalid ones (see below), and any index
  whose key is an expression rather than a plain column — an expression never
  becomes a column flag, whatever its text happens to read like.
- **`indexes`** therefore lists only what the column flags cannot express:
  non-unique indexes and multi-column ones. The index backing the primary key is
  never listed, and neither is the autoindex behind a single-column `UNIQUE`
  (SQLite's `sqlite_autoindex_*` does show up for a *composite* `UNIQUE (a, b)`,
  since no column flag can hold that). A key part that is an expression rather
  than a column reads as `(expression)` — PostgreSQL prints the real expression
  text instead — so the key's shape is never silently shortened.
- A **partial (filtered) unique index** — `CREATE UNIQUE INDEX ... WHERE ...` —
  is reported as an ordinary index, *without* `unique` and without its
  predicate: its uniqueness holds only for the rows the predicate matches, so
  claiming a key would be a lie. Same for a PostgreSQL index left invalid by a
  failed `CREATE INDEX CONCURRENTLY`.
- **`fks`** are arrays on both sides, in key order, so a composite foreign key
  reads as `{"columns":["org_id","seq"],"ref_table":"orders","ref_columns":["org_id","seq"]}`.
  An empty `ref_columns` (SQLite only) means the reference could not be
  resolved to named columns — a `REFERENCES parent` whose parent declares no
  primary key, or a parent that does not exist.
- `type` is the type **as the engine reports it**: PostgreSQL `format_type`
  (`bigint`, `character varying(50)`, `timestamp with time zone`), MySQL/MariaDB
  `COLUMN_TYPE` (`bigint(20) unsigned`, `varchar(255)`, `enum('a','b')`), SQLite
  the declared type verbatim (empty for an untyped column).
- Tables are ordered by name; columns keep the table's own order.

**Auto-increment** shows up in `default`, in each engine's own words:
PostgreSQL `serial` → `"nextval('users_id_seq'::regclass)"` and an `IDENTITY`
column → `"generated as identity"`; MySQL/MariaDB `AUTO_INCREMENT` →
`"auto_increment"` (the server keeps it outside `COLUMN_DEFAULT`, nyet folds it
in); SQLite's `INTEGER PRIMARY KEY` (the rowid alias) has no default at all —
`pk: true` on an `INTEGER` column *is* the auto-assigned key. The portable
signal across all three is `pk`.

**Adaptive listing.** Without `[table]`, a database of **at most 50** tables +
views comes back in full. Past that, the answer is names and kinds only, with a
`SCHEMA_TRUNCATED` warning pointing at the way to the details:

```json
{"v":1,"ok":true,"schema":{"tables":[{"name":"accounts","kind":"table"},{"name":"v_active","kind":"view"}]},"meta":{"table_count":312,...},"warnings":[{"code":"SCHEMA_TRUNCATED","message":"schema listing truncated to names: 312 objects exceed the 50-object detail limit; run nyet schema prod <table> for one table's details"}]}
```

Naming `[table]` always returns the full detail, whatever the object count. An
unknown name is a `DB_ERROR` (exit 7) whose hint points back at the listing.

**What you see is bounded by your role's privileges — with the exact rules
spelled out, because "we filter it" is not a promise worth guessing at:**

- **PostgreSQL** covers every non-system schema (`pg_*` and `information_schema`
  are excluded) that the role may actually read: an object appears if the role
  has `USAGE` on its schema and `SELECT` on the object *or on any of its
  columns*, and each column appears only if the role may `SELECT` that column.
  So a `GRANT SELECT (id, note) ON t` shows `t` with `id` and `note` and
  nothing else — matching what `nyet query` would let you read. Defaults of
  columns you cannot read (they are literal values — secrets do get parked
  there) never reach the agent.
- **Under a partial (column-level) grant, keys are dropped whole.** The
  catalogs still describe primary keys, indexes and foreign keys over columns
  you cannot read, so any of them touching an invisible column is omitted
  entirely — never shortened. A `PRIMARY KEY (id, api_key)` with only `id`
  granted disappears rather than reading as a one-column key on `id`: a missing
  key costs you a round trip, a *wrong* key costs you a wrong query. Keys over
  granted columns only are unaffected — with one deliberate exception: a
  PostgreSQL index on an *expression* is always dropped under a partial grant,
  even when the expression only uses columns you were granted, because its text
  is never matched against the grants. With full table-wide `SELECT` nothing is
  filtered at all.
- Two things that are *not* hidden, both identifiers only — no data, no
  defaults, no column lists:
  - a foreign key on columns you can read names its **parent table and the
    parent columns it points at** (`ref_table` / `ref_columns`) even when the
    parent itself is outside your privileges — the constraint is part of the
    child's own definition, and `psql`'s `\d` shows it the same way;
  - on **MySQL/MariaDB** a *functional* index stays listed under a partial
    grant even when its expression uses a column you cannot read: the server
    gives nyet no expression text (it shows as `(expression)`), so there is
    nothing to hide there — but the **index name** may itself mention the
    hidden column. Dropping such indexes wholesale would also blind
    fully-privileged accounts to every functional index, which is the worse
    trade.
- **MySQL/MariaDB** inherits `information_schema`'s own visibility rule, which
  is *not* SELECT-specific: an object shows up if the account holds **any**
  privilege on it (an `INSERT`-only account sees the table and its column
  defaults). Its column list *is* privilege-filtered, so the key-dropping rule
  above applies here too. Grant a genuinely read-only user (see the recipe
  above) if that matters to you.

Objects in `public` read as bare names; anything else is qualified —
`sales.orders` — which is also the form `[table]` accepts. An unqualified
`[table]` matches in every schema, so it can return more than one object;
qualify it to pin one down. Materialized views are reported as `kind: "view"`
(and, like every view, without indexes); foreign tables are reported as
`kind: "table"` (they read like one). **MySQL/MariaDB** introspects the
connection's own database (the one in the url) and nothing else; a foreign key
that points into another database keeps the qualifier (`other_db.parent`).

**Name matching follows each engine's own rules**, so `[table]` behaves like the
name in a query: SQLite is ASCII-case-insensitive (`USERS` finds `users`);
PostgreSQL also tries the lowercase form, since unquoted identifiers fold that
way (`ORGS` finds `orgs`; if both `ORGS` and `orgs` exist you get both);
MySQL/MariaDB follow the server's collation. A `[table]` containing a dot is
split on the **first** dot (PostgreSQL), so a bare `sales.orders` always reads
as schema + table — a table whose *name* contains a dot is still reachable by
qualifying it (`public.sales.orders`). Two objects that render to the same
display name (a schema-qualified one and a quoted dotted name) are listed as
two entries with identical `name` values; qualify the argument to fetch the one
you mean.

Introspection runs through the same read-only session, timeout (`timeout_secs`)
and SSH tunnel as a query — and `--format table` renders a compact human view,
with the envelope on stderr as usual:

```sh
$ nyet schema prod users --format table
users table
  id      bigint  not null  pk  default nextval('users_id_seq'::regclass)
  email   text    not null  unique
  org_id  bigint  null
  index users_org_idx (org_id)
  fk (org_id) -> orgs (id)
```

### nyet explain

```sh
nyet explain <alias> <sql> [--format json|table]
```

The query plan, whatever estimate the engine publishes, and the guardrail
verdict — **without running the query**. The SQL goes through the same
validator as `nyet query` (planning a write is refused the same way), and the
EXPLAIN nyet builds is never `ANALYZE` — `ANALYZE` executes the statement.

```sh
$ nyet explain prod "SELECT id FROM users WHERE email = 'a@b.c'"
{"v":1,"ok":true,"estimate":{"mode":"cost","verdict":"ok","cost":8.29,"rows":1,"threshold":1000000.0,"plan":[{"Plan":{"Node Type":"Index Scan",...}}]},"meta":{"duration_ms":11,"connection":"prod"}}
```

- `mode` — the connection's guardrail mode (`cost` / `rows` / `off`).
- `verdict` — `ok` (under the threshold), `expensive` (above it: `nyet query`
  would refuse this query), or `no_estimate` (nothing to compare — the engine
  publishes no estimate, the mode is `off`, or this particular plan carried no
  usable number).
- `cost` / `rows` / `threshold` appear only when they exist; `plan` is the plan
  as the engine reports it (PostgreSQL's `FORMAT JSON` tree, MySQL/MariaDB's
  classic EXPLAIN rows, SQLite's `EXPLAIN QUERY PLAN` lines).
- `--format table` prints the verdict line plus a readable plan on stdout, with
  the envelope on stderr — the usual convention.

`nyet explain` does not run the query, so an `expensive` verdict is
information, not a refusal: it exits 0. It plans under the same budget as
`nyet query` — derived from the same `timeout_secs`, at every timeout — so the
two agree: if planning outruns that budget you get `verdict: no_estimate` with an
empty plan and a warning saying `nyet query` would refuse this statement. Two
honest caveats:

- It expects a *query*. `SHOW`, `DESCRIBE` and a statement you already wrapped
  in `EXPLAIN` have no plan to ask for: nyet says so without touching the
  database (`verdict: "no_estimate"`, an empty `plan`, and a `NO_PLAN` warning
  telling you to run it with `nyet query`), rather than sending the server a
  nonsensical double EXPLAIN.
- "Does not run the query" means the *statement* is not executed. Planning is
  not free, and not perfectly side-effect-free on every engine: PostgreSQL
  evaluates constant `IMMUTABLE` expressions while planning, so
  `SELECT md5(repeat('x', 100000000))` does that work at plan time — measured,
  and the reason the guardrail refuses a query whose planning outruns its budget
  rather than waving it through. It happens inside the same read-only
  transaction and `timeout_secs` as a query would. `EXPLAIN ANALYZE`
  — the thing that really executes — is refused outright by the validator
  (`EXPLAIN_ANALYZE`), by `nyet explain` and by `nyet query` alike.

### The auto-guardrail

Before `nyet query` runs anything, nyet asks the database to **plan** the query
and compares the estimate with the connection's threshold. Over the threshold,
the query is not executed:

```json
{"v":1,"ok":false,"error":{"code":"NYET","reason":"EXPENSIVE_QUERY","message":"nyet: the query plan's estimated cost is 25000165000, above the guardrail limit of 1000000 for connection 'prod' — the query was NOT executed","hint":"narrow the query (add a WHERE filter or a LIMIT, join on an indexed column) — the plan is in `estimate` of this envelope; if the query really is legitimate, ask the person who owns the config to raise [connections.prod.guardrail] max_cost"},"estimate":{"mode":"cost","verdict":"expensive","cost":25000165000.0,"rows":1,"threshold":1000000.0,"plan":[...]}}
```

Exit code **5**, like every other `NYET` refusal, with `reason` =
`EXPENSIVE_QUERY` and the plan attached so the query can be fixed without
another round trip.

**It is on by default, with a deliberately generous limit** — it exists to stop
a full scan of tens of millions of rows, not to second-guess your analytics.
Per engine:

| engine | modes | default | default limit |
|---|---|---|---|
| PostgreSQL | `cost`, `rows`, `off` | `cost` | `max_cost = 1000000.0` (`max_rows = 10000000`) |
| MySQL/MariaDB | `rows`, `off` | `rows` | `max_rows = 10000000` |
| SQLite | `off` only | `off` | — |
| MongoDB | `off` only | `off` | — |

```toml
[connections.prod.guardrail]
mode = "cost"           # cost | rows | off
max_cost = 5000000.0    # raise it if your legitimate queries are bigger
max_rows = 20000000
```

- **`cost`** is the PostgreSQL planner's own cost number (`Total Cost` of the
  top plan node). It has no unit — it is the planner's internal currency — so
  the threshold is calibrated empirically: 1 000 000 is far above an ordinary
  indexed read or an aggregate over a few million rows, and far below a
  cross join or a scan of tens of millions.
- **`rows`** is the estimated row count. On PostgreSQL it is the **largest**
  `Plan Rows` in the plan, not the top node's: the top node of
  `SELECT count(*) FROM huge` is an Aggregate returning one row over a scan of
  millions, and judging by that would let every such query through. On
  MySQL/MariaDB it is the classic EXPLAIN `rows` column — multiplied across the
  tables of one select (that product is exactly what makes a cross join
  enormous), summed across independent selects (UNION arms, cached subqueries)
  and multiplied by the correlated ones (`DEPENDENT`/`UNCACHEABLE`, which the
  server re-runs per outer row — unless such a subquery is estimated at a single
  row, which is added instead, or it would vanish from the product). Both are
  estimates of *work*, not a promise: the PostgreSQL maximum does not add up
  sibling branches (it can under-count a wide plan) and the MySQL product
  over-counts sibling correlations (it can refuse one) — see docs/DEV.md.
- **MySQL/MariaDB have no `cost` mode.** MySQL 8 and MariaDB do not report a
  comparable plan cost through a form that works on both, and nyet does not
  invent one: `mode = "cost"` on those engines is a config error (exit 3), not a
  silent fallback.
- **SQLite has no guardrail.** `EXPLAIN QUERY PLAN` publishes no cost and no row
  estimate at all, so the only accepted mode is `off` (the default) and
  `nyet explain` answers `verdict: "no_estimate"` with the plan text. Saying so
  is the honest answer; a made-up number would not be.
- **MongoDB has no guardrail either.** `explain` in `queryPlanner` mode
  publishes neither a cost nor a row estimate, and `executionStats` mode *runs*
  the query — so there is nothing to compare a threshold against without doing
  the very thing the guardrail exists to prevent. `off` is the only accepted
  mode; the row limit and `maxTimeMS` are the backstops.
- A `mode` an engine cannot honor is always a **config error (exit 3)** — never
  a silent downgrade to "unguarded". So is a threshold the active mode never
  reads (`max_rows` under `mode = "cost"`, or either one under `off`): a limit
  that quietly does nothing is worse than no limit.
- **Metadata statements are not estimated.** `SHOW`, `DESCRIBE` and an explicit
  `EXPLAIN ...` you send yourself carry no plan to judge, so they run unguarded.
  (`EXPLAIN ANALYZE` is a different story: it *executes* the statement, so the
  validator refuses it outright — see `EXPLAIN_ANALYZE` below.)
- **A recursive CTE downgrades the verdict, it does not erase it.** PostgreSQL
  does not estimate the iteration of a `WITH RECURSIVE`, so an unbounded
  recursion plans at a cost near zero. Such a plan is treated as a **lower
  bound**: if it is *already* over the limit the query is refused as usual (so
  gluing a two-row recursive CTE onto a monster does not hide it), and if it is
  under, the verdict is `no_estimate` rather than "ok" (and the `cost`/`rows` it
  shows are a lower bound, not a prediction) — `nyet explain` says so,
  and `nyet query` runs it with a `GUARDRAIL_SKIPPED` warning (refusing every
  recursive CTE would be a false refusal for the ordinary hierarchy walks people
  write). Bound those queries yourself — a depth predicate, a `LIMIT`, or a
  smaller `--timeout`.
- **The backstops behind the guardrail are yours to bound too.** When the
  guardrail cannot judge a plan, what is left is `timeout_secs` and the row
  limit — and an agent can raise both with `--timeout` / `--limit` unless you
  set `max_timeout_secs` / `max_row_limit` (see the section above). If you rely
  on the timeout as the real backstop, set the ceiling.
- If a plan comes back without a usable number, the query **runs anyway** and
  the answer carries a `GUARDRAIL_SKIPPED` warning. The guardrail is a
  best-effort catcher of monsters, not a gate: refusing everything nyet cannot
  parse would break legitimate work, and the timeout plus the row limit are
  still there.
- The EXPLAIN runs on the same connection and in the same read-only transaction
  as the query it guards — no extra connection, no extra login — and it has a
  budget of its own (5 s, or a fraction of `timeout_secs` when that is smaller),
  enforced by the server as well as by nyet. The two ways it can come back
  empty are treated **differently**, and the rule is whether an agent can cause
  them on purpose:
  - **the database refuses to plan the statement** (a role that may `SELECT` a
    view but not `EXPLAIN` it — MySQL needs `SHOW VIEW` for that — or a form the
    server dislikes): the estimate is dropped and **the query still runs**, with
    a `GUARDRAIL_SKIPPED` warning. A guard that turns a working query into an
    error would be the worse bug. **If your role reads views, grant it
    `SHOW VIEW` on them** — otherwise any query mentioning such a view switches
    the guardrail off for that connection (the warning still records it);
  - **planning outruns the budget** (which is always strictly inside your
    `timeout_secs`, so the refusal beats the timeout to the answer): the query is
    **refused** (`EXPENSIVE_QUERY`, exit 5, no plan to show). Planning time is something a
    query can inflate on purpose — PostgreSQL evaluates constant `IMMUTABLE`
    expressions while planning, and a MySQL EXPLAIN over `information_schema`
    can take tens of seconds — so "no plan in time" must not become a way to
    switch the guardrail off. A statement whose *plan* takes seconds was never
    going to be cheap to run.
  The EXPLAIN shares the query's `timeout_secs` and counts inside
  `meta.duration_ms` (that number is the whole database phase).

**A plan exposes more than a result does.** It names the base tables, indexes
and predicates behind a view, and shows the qualifiers a row-level-security
policy adds — so an account restricted *by a view* still learns the shape of
what is underneath it (`nyet explain` and the plan attached to a refusal both
show this). Restrict an agent's account with real grants (see the read-only role
recipes above), not by pointing it at a view.

**There is no `--force` flag, on purpose.** The threshold belongs to the person
who owns the config: a flag that lets the agent lift its own guardrail is
security theatre (a refusal it can wave away is not a limit). The hint on a
refusal says exactly that — narrow the query, or ask the human to raise
`max_cost` / `max_rows` for that connection.

### nyet doctor

```sh
nyet doctor              # config-file checks + the connections reachable from here
nyet doctor <alias>      # full per-connection diagnosis
```

`nyet doctor` is the one command written for a **human**: it checks your setup
honestly and names the weak spots (UX-7 — no security theatre). Unlike the other
commands it defaults to `--format table`; `--format json` gives the same checks
as an envelope.

```sh
$ nyet doctor prod
ok    connectivity         connected to the database
warn  transport_encrypted  the transport is not guaranteed encrypted or verified: the url's sslmode/ssl-mode is below require and there is no ssh tunnel, so nyet may talk to the server in plaintext
                           → set sslmode=verify-full (Postgres) or ssl-mode=VERIFY_IDENTITY (MySQL) in the url to encrypt and authenticate the connection, or route it through an ssh tunnel
fail  read_only_role       these credentials CAN write to the database directly: a probe write (a rolled-back CREATE TABLE) succeeded, so an agent with shell access could bypass nyet and modify data — layer 3 is not in place
                           → create a read-only role and point the url at it:
                           → CREATE ROLE nyet_ro LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE;
                           → ...
ok    not_superuser        the role is not a superuser (the role is not a PostgreSQL superuser)
warn  pii_columns          the role can read 1 of the 2 marked column(s) directly (users.email): nyet refuses or masks them (mode = "mask"), but the database itself does not — anything connecting with these credentials outside nyet gets the real values
                           → make the boundary the database's: REVOKE SELECT ON <table> FROM <role> and GRANT SELECT (<the columns the agent may read>) ON <table> TO <role> ...
ok    config_permissions   the config file is readable only by its owner (mode 0600)
```

Each check carries a `status` and a human `message`; every `warn`/`fail` adds an
actionable `hint`. **Statuses** (a closed list): `ok`, `warn` (a weak spot, fix
recommended), `fail` (a real problem for the read-only guarantee), `na` (the
check does not apply to this engine — never a faked pass or a made-up metric).

`nyet doctor` **always exits 0 when it ran** — the verdicts live in the checks,
not the exit code (a failed *connection* is a `fail` check, not exit 6:
diagnosing that is the whole point). The only non-zero exits are the config-level
ones every command shares: a config that cannot be read or an unknown alias
(exit 3), or an engine this build does not ship (exit 1).

**Unknown is never `ok`.** When doctor cannot actually verify something — the
write probe hit an error that does not prove read-only (a dropped connection, a
timeout), or the superuser status could not be read — it reports `warn` ("could
not verify …"), never a green `ok`. A false pass in a security tool is worse than
a false warning.

What each check means and what to do about it:

- **connectivity** — can nyet reach the database (through the ssh tunnel, if
  any)? A `fail` carries the connection error and its hint.
- **transport_encrypted** — is the channel encrypted? An ssh tunnel or a direct
  url at `sslmode`/`ssl-mode` ≥ `require` is `ok`; anything below that with no
  tunnel is a `warn` (nyet may talk plaintext). The check reports the
  *guarantee* from the config, so a `require`-mode url reads `ok` here even if
  the connect itself then fails against a server without TLS. Fix: set
  `sslmode=verify-full` / `ssl-mode=VERIFY_IDENTITY`, or use a tunnel.
- **read_only_role** (layer 3) — *hybrid*: metadata (superuser? replica?
  read-only default?) explains **why**, and a **probe write proves the fact**.
  The probe runs a write (a `CREATE TABLE nyet_doctor_probe_…`) with nyet's
  layer-2 read-only session **deliberately removed**, so it tests whether the
  **server** refuses this role's write. If it is refused → `ok` (a direct
  connection with these credentials is read-only — layer 3 holds; a replica /
  read-only default is noted). If it succeeds → `fail` (the role can write
  directly, bypassing nyet). **The probe targets no real object** (a
  uniquely-named `nyet_doctor_probe_…` table): on PostgreSQL it runs inside a
  transaction that is only ever rolled back (never committed), so it leaves
  nothing; on MySQL/MariaDB (where DDL auto-commits) it is a create-then-drop —
  which normally leaves nothing, **but if the role lacks `DROP`, the connection
  drops, or the probe times out, a `nyet_doctor_probe_…` table may remain, and
  doctor NAMES it in the output** so you can remove it by hand (a SELECT-only role
  never gets that far — its CREATE is refused before anything is written). Fix a
  `fail` with the read-only role recipe the hint prints (see the
  layer-3 recipes above). Only a *known* server read-only refusal reads as `ok`;
  any other probe error is `warn` ("could not verify"), never a false pass. One
  honest limitation: the probe proves the role cannot run a `CREATE` (a DDL
  write), which for the recommended **SELECT-only** role is genuinely read-only —
  but a role granted `INSERT`/`UPDATE`/`DELETE` yet not `CREATE` would also read
  `ok` here, so grant your agent's role **only `SELECT`** (the recipes above), not
  "everything except CREATE".
- **not_superuser** — is the role a superuser / all-privileges account (which
  bypasses every read-only layer)? Superuser → `fail`. Fix: use a dedicated
  `NOSUPERUSER` role with only the `SELECT` grants the agent needs.
- **pii_columns** (only with a `[pii]` section) — do the columns marked in
  `[connections.X.pii]` actually sit
  behind a database boundary? Doctor asks the server whether this role may read
  each of them (PostgreSQL `has_column_privilege`; MySQL/MariaDB the
  privilege-filtered `information_schema`). It cannot → `ok`. It can → `warn`
  naming the columns: nyet still refuses or masks them, but the database does
  not, so anything using these credentials outside nyet reads the real values —
  the hint prints the column-grant fix. A column the server will not answer about
  (most often a typo in the rule) is `warn` ("could not verify"), never a pass.
  The check is omitted entirely for a connection with no `[pii]` section.
  **One honest gap, MySQL/MariaDB only:** the server answers "denied" before it
  checks whether the column exists, so for an account that already lacks the
  grant (the recommended least-privilege one) a *misspelled* rule reads as `ok`
  rather than "could not verify" — `nyet doctor` cannot tell "you may not read
  it" from "it is not there". PostgreSQL distinguishes the two. Check spellings
  against `nyet schema` when you add rules; the marking there is the reliable
  confirmation that a rule matched something.
- **ssh_forward** (only with an `[ssh]` section) — what the tunnel left running:
  the loopback port, whether this call reused an existing forward and how old it
  is, and the literal `ssh -O cancel …` command that removes it. Always `ok` —
  a kept forward is the intended state, not a problem — but it exists so a
  forward that outlives the process is something you can see and kill, not
  folklore. With `reuse_forward = false` it says so and offers no command,
  because nothing is left behind.
- **server_side_js** (MongoDB only) — does the SERVER evaluate JavaScript
  (`$where`, `$function`, `$accumulator`, `mapReduce`)? nyet refuses all of it,
  but only for queries that go through nyet: the plain `read` role may run it,
  and `maxTimeMS` does not bound it (measured: 8 s and 12 s under a 500 ms
  limit), so it is unbounded arbitrary code in the database process for any
  other client with the same credentials. MongoDB publishes **no runtime
  parameter** for the setting, so doctor reads the server's startup options
  (`--noscripting` → `ok`, scripting on → `warn` with the fix). If the account
  may not read them — the normal case for a read-only role — the answer is
  `warn`, **"could not check"**, with the reason: nyet will not probe by
  RUNNING JavaScript, which is precisely what it promises never to send.
- **config_permissions** — is the config file `0600` (owner-only)? Group/other
  bits → `warn`. Fix: `chmod 600` on the config file.

**MongoDB proves layer 3 without writing anything.** There is no probe write
there: `connectionStatus {showPrivileges: true}` publishes every action these
credentials hold on every resource, so `read_only_role` is decided by reading a
list. It looks at the WHOLE cluster (a `readWrite` role in another database is
an exfiltration path through `$out`, measured), and an action nyet cannot
classify as a read is reported, not assumed harmless — see "MongoDB schema,
explain and doctor".

**SQLite is reported honestly.** It has no roles, no server and no network, so
`transport_encrypted`, `read_only_role`, `not_superuser` and `pii_columns` (when
a policy exists) come back `na` with a plain explanation (nyet opens the file read-only via `mode=ro`;
there is no role to make read-only, and no column privileges to hide a PII column
behind — on SQLite the `[pii]` policy is the only thing enforcing it) — nyet does
not invent a metric where there is none.

`nyet doctor` with **no alias** checks the config-file permissions and lists the
connections reachable from the current directory (a named alias, by contrast, is
diagnosed regardless of `allowed_dirs` — you own the config and may be testing
it from anywhere).

### nyet agent-setup

```sh
nyet agent-setup > .claude/skills/nyet/SKILL.md   # install as a Claude Code skill
nyet agent-setup --format json                    # the SKILL.md inside a JSON envelope
```

Generates a **Claude Code skill** (a `SKILL.md`: YAML frontmatter with
`name`/`description` + a Markdown body) that teaches an AI agent to use nyet —
the commands with examples, how to read the JSON envelope and exit codes, and
how to recover from a `NYET` refusal via `reason`+`hint`. It needs no database
or network (pure local generation), and works **even without a config**: the
instruction is emitted regardless (its value is teaching the agent before
setup), so a missing or unreadable config is not an error, just a degraded
section.

The content is a **hybrid**: a stable instruction plus a dynamic "Your
connections" section listing the real aliases and engines **reachable from the
current directory** (the same scope as `nyet list`), with a concrete
`nyet query <alias> "..."` example using one of them. Run it from the project
directory where the skill will live. With no reachable connections (or no
config) that section degrades to a hint pointing at `nyet list` and
`allowed_dirs`.

Output defaults to the raw `SKILL.md` on stdout (redirect it to a file; the
success envelope goes to stderr as one JSON line, like the other data formats);
`--format json` wraps the whole `SKILL.md` in the `skill` field of a JSON
envelope on stdout for programmatic access. A missing or broken config never
fails it (exit 0), and a closed reader (broken pipe) is exit 0 too; like any
command, only a non-broken-pipe stdout write failure (e.g. a full disk) errors
(exit 1).

## Security

`nyet` enforces read-only in layers, assuming a cooperative but fallible
agent (see the threat model in [docs/DESIGN.md](docs/DESIGN.md)):

1. **SQL validator** (this section) — pure AST classification before
   anything touches the database; fail closed: anything not understood is
   denied.
2. **Session/file read-only** — SQLite files are opened `mode=ro`; PostgreSQL
   runs each query in an explicit `BEGIN READ ONLY` transaction on a
   `default_transaction_read_only=on` connection with a server `statement_timeout`.
3. **Read-only database roles** — recommended; makes even direct access
   (bypassing nyet) read-only. See the PostgreSQL role recipe above.

The validator pipeline: strip invisible Unicode (Cf/Cc) characters → (MySQL/
MariaDB only) reject executable comments / optimizer hints → parse (the engine's
SQL dialect — SQLite, PostgreSQL or MySQL) → exactly one statement → recursive
AST walk. The walk denies write/DDL statements anywhere in the tree (CTE bodies
including data-modifying CTEs like `WITH x AS (DELETE ... RETURNING)`, derived
tables, subqueries), locking clauses (`FOR UPDATE`/`FOR SHARE`), `COPY`, `SET`,
`EXPLAIN ANALYZE` (which executes what it explains) and denylisted functions.

**MySQL/MariaDB executable comments.** MySQL runs the body of `/*! ... */`,
`/*M! ... */` (MariaDB) and optimizer-hint `/*+ ... */` comments, but a SQL
parser drops them as ordinary comments — so `SELECT 1 /*! SLEEP(10) */` would
look like `SELECT 1` to the AST while the server executes `SLEEP`. Before
parsing, nyet scans MySQL queries (string-aware, so a `/*!` inside a quoted
literal is data, not a comment) and denies any such opener outside a literal
(`EXECUTABLE_COMMENT`). This is MySQL-only — PostgreSQL and SQLite do not
execute comment bodies.

### How to read a refusal

A refusal has `code = "NYET"`, exits with 5, and always says why and what
to do:

```json
{"v":1,"ok":false,"error":{"code":"NYET","reason":"WRITE_OPERATION","message":"nyet: 'DELETE FROM' is not a read operation","hint":"nyet is read-only; only SELECT, EXPLAIN, SHOW and DESCRIBE statements are accepted — rewrite the task as a read query"}}
```

`error.reason` is a closed list:

| reason | meaning |
|---|---|
| `PARSE_FAILED` | the query could not be parsed — anything not understood is denied (fail closed) |
| `MULTI_STATEMENT` | more than one statement in a single query |
| `WRITE_OPERATION` | not a read statement (DML/DDL/PRAGMA/ATTACH/...), anywhere in the query: top level, CTE bodies (`WITH x AS (DELETE ...)`), derived tables (`SELECT * FROM (DELETE ...)`), subqueries, `SELECT INTO`, `EXPLAIN <write>`. On MongoDB: a writing method (`insertOne`, `updateMany`, `drop`, ...) and the `$out`/`$merge` stages **in every position**, nested pipelines (`$lookup`, `$unionWith`, `$facet`) included |
| `TXN_CONTROL` | transaction or session control (BEGIN/COMMIT/ROLLBACK/SET) |
| `LOCKING_CLAUSE` | `SELECT ... FOR UPDATE` / `FOR SHARE` — takes row locks, not a plain read |
| `DENIED_FUNCTION` | a function on the denylist for this connection (the message names it). On MongoDB: anything that runs server-side JavaScript — `$where`, `$function`, `$accumulator`, `mapReduce`, a `$code` BSON value — none of which is ever allowlisted |
| `EXPLAIN_ANALYZE` | `EXPLAIN ANALYZE ...` (or PostgreSQL's `EXPLAIN (ANALYZE, ...)`) — it *runs* the statement it claims to explain, so it is an execution wearing a plan's clothes; use `nyet explain` for a plan, a plain `EXPLAIN` is fine as a query |
| `EXPENSIVE_QUERY` | the query plan's estimate is above this connection's guardrail limit, so the query was not executed — the envelope carries the plan. Also used when *planning itself* outran the guardrail's budget (then there is no plan to carry): see the auto-guardrail section |
| `EXECUTABLE_COMMENT` | a MySQL/MariaDB executable comment or optimizer hint (`/*! … */`, `/*M! … */`, `/*+ … */`) — the server runs its body but a SQL parser drops it, so nyet cannot see what it does; remove the comment |
| `PII_COLUMN` | the query could expose a column this connection's `[pii]` policy protects — named directly, wrapped in an expression, swept up by `*`, used as a filter, or resolved from the result's provenance. See "PII columns" |
| `DENIED_COMMAND` | (MongoDB) the collection method is not on the read allowlist — a write (`insertOne`, `drop`, ...), a database-level command (`db.runCommand`, `db.adminCommand`), a cursor method nyet does not run (`.forEach`, `.count`), or an internal `system.*` catalog. The message names it |
| `DENIED_OPERATOR` | (MongoDB) a `$`-prefixed key — pipeline stage, query operator, aggregation expression or accumulator — that is not on the read allowlist, at any nesting depth. Everything nyet has not reviewed is refused by default, including operators a newer MongoDB adds, undocumented `$_internal*` stages, Atlas-only `$search`/`$vectorSearch`, cluster introspection (`$currentOp`, `$collStats`, `$planCacheStats`) and the options nyet sets itself |
| `PII_UNPROVABLE` | the database would not state where a result column came from, on a connection with a PII policy — an undetermined origin is refused rather than guessed |
| `INTERNAL_ERROR` | nyet's own validator crashed while checking the query (or the result it came back with) — a bug in nyet, not in your SQL. The crash is caught and turned into this refusal, so a bug cannot become an unchecked query or an unchecked result: no result is returned either way. Please report it with the statement that triggered it |

PRAGMA is refused with a pointer instead of a dead end: schema questions
have a SELECT answer (`SELECT name, sql FROM sqlite_master WHERE type = 'table'`).

### Unicode normalization

Invisible Unicode format/control characters (categories Cf and Cc, except
`\t` `\n` `\r`) are stripped before validation and execution — they can
smuggle keywords past a reviewer (`SEL<zero-width joiner>ECT`). The verdict
applies to the cleaned text; if anything was stripped from an accepted
query, the success envelope carries a `UNICODE_STRIPPED` warning.

### Function denylist

Some functions are dangerous even inside a read-only query. The built-in
lists (per engine; rationale in [docs/DEV.md](docs/DEV.md)):

- **SQLite:** `load_extension`, `fts3_tokenizer`, `readfile`, `writefile`, `edit`.
- **MySQL/MariaDB:** `load_file` (reads a server file), `sleep` and `benchmark`
  (connection-tie-up / CPU DoS), `sys_exec`/`sys_eval` (the `lib_mysqludf_sys`
  UDFs — shell/command execution if installed), the named-lock family
  `get_lock`/`release_lock`/`release_all_locks` (`GET_LOCK(name, -1)` blocks the
  connection forever — DoS; the read half of that family, `is_free_lock`/
  `is_used_lock`, takes nothing and stays allowed), and the replication-wait
  family `master_pos_wait`/
  `source_pos_wait`/`master_gtid_wait`/`wait_for_executed_gtid_set`/
  `wait_until_sql_thread_after_gtids` (block until a replica position — DoS).
  `SELECT ... INTO OUTFILE`/`INTO DUMPFILE` (writing a server file) is refused too
  (it fails to parse — fail closed).
- **PostgreSQL:** `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`,
  `pg_promote`, the `pg_sleep` family (`pg_sleep`/`pg_sleep_for`/`pg_sleep_until`),
  `nextval`/`setval`/`pg_logical_emit_message` (sequence mutation and
  non-transactional WAL writes — Postgres runs these even inside a read-only
  transaction, the durable writes that bypass both layers; `currval`/`lastval`
  stay allowed), `lo_import`/`lo_export`, `pg_stat_file`, and the prefix families
  `dblink*`, `pg_read_*` (server-file read) and `pg_ls_*` (server-dir listing).
  These act outside the read-only transaction, so the validator is the only
  guard. Also the whole **`*_to_xml` export family** — `query_to_xml`,
  `table_to_xml`, `schema_to_xml`, `database_to_xml`, `cursor_to_xml` and their
  `*_to_xmlschema` / `*_to_xml_and_xmlschema` variants. These are built into
  `pg_catalog`, need no extension and no DBA, and they defeat the validator
  outright: `query_to_xml` **executes a SQL string** nyet never parses (so
  `query_to_xml('select pg_sleep(3)', …)` ran a denied function), and the
  `table_/schema_/database_to_xml` forms dump a whole relation, schema or
  database without naming a single column. Same class as `dblink`, only
  built in. And the whole **advisory-lock family** — `pg_advisory_lock`,
  `pg_try_advisory_lock`, their `_shared`, `_xact_` and `_unlock` variants and
  `pg_advisory_unlock_all` (all 11 names): taking a lock is not a read, the
  blocking forms hang the query until the server's `statement_timeout`, and a
  *session* advisory lock is **not** released by `ROLLBACK` — it lives until the
  backend dies. Reading the lock catalog (`SELECT … FROM pg_locks`) stays
  allowed. Prefix families are built-in and not tunable via `allow_functions`;
  the enumerated names (including `pg_sleep`, the `*_to_xml` and the advisory
  family) are.

Matching is case-insensitive and is done on the **terminal** name component, so
qualified targets (`pg_catalog.pg_sleep`, `main.load_extension`) and table-valued
calls (`SELECT * FROM dblink(...)`) are caught, but a column or table merely
*named* like a denied function (`pg_sleep.some_col`) is not a call and stays
allowed. `allow_functions` / `deny_functions` therefore take **unqualified**
names — a dotted entry is matched literally and never hits.

Per-connection tuning in the config:

```toml
[connections.localdev.validator]
allow_functions = ["load_extension"]   # remove a built-in entry — a conscious risk
deny_functions = ["my_scary_fn"]       # add your own bans
```

`allow_functions` removes entries from the built-in list, `deny_functions`
adds new ones; if a name appears in both, deny wins. **Every
`allow_functions` entry is a risk you consciously accept** — the function
runs with the database user's privileges even in a read-only session.

### Warning codes

`warnings[].code` is a closed list: `TRUNCATED` (row limit cut the result),
`GUARDRAIL_SKIPPED` (the plan carried no estimate the guardrail could use — a
recursive CTE, an unreadable plan shape, or an EXPLAIN the server refused — so
the query was not checked against the limit; it ran anyway, bounded by the
timeout and row limit), `NO_PLAN` (`nyet explain` was given a metadata statement,
which has no plan),
`DUPLICATE_COLUMNS` (json rows would collapse same-named keys),
`UNICODE_STRIPPED` (invisible characters removed from the query),
`INSECURE_TRANSPORT` (a direct server connection whose url `sslmode`/`ssl-mode`
is below `require` and has no ssh tunnel — the transport is not guaranteed
encrypted or verified; the message says how to force TLS),
`SCHEMA_TRUNCATED` (`nyet schema` listed objects by name only — more than 50
tables + views, or a MongoDB listing, which is always names-only),
`SCHEMA_SAMPLED` (MongoDB: part of that schema answer was INFERRED from a
sample of documents — see "MongoDB schema, explain and doctor"),
`PII_MASKED` (`[pii] mode = "mask"`: the named columns came back as
`[REDACTED]` — see "PII columns").

The full allow/deny specification is the public test corpus in
[`tests/corpus/`](tests/corpus/): every validator rule exists there as at
least one allow and one deny case, and every known bypass is pinned as a
corpus case first, then fixed.

## Audit log

Letting an agent near a database is only safe if you can see afterwards what it
did — so the audit log is part of the contract, not an optional extra (UX-8).
Every command that reaches a database (`query`, `schema`, `explain`, and
`doctor <alias>`) appends one JSON line to

```
$XDG_DATA_HOME/nyet/audit.jsonl        # default: ~/.local/share/nyet/audit.jsonl
```

`list`, `agent-setup` and `nyet doctor` with no alias never touch a database,
so they are not logged.

**On by default.** A refusal (`NYET`), a database error and a timeout are logged
too — the log shows what the agent *tried*, not only what succeeded.

Example lines (one JSON object per line — a successful query, then a refusal):

```json
{"audit_v":1,"ts":"2026-07-26T12:34:56.789Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/me/app","sql":"SELECT id, email FROM users LIMIT 5","verdict":"ok","exit_code":0,"row_count":5,"truncated":false,"duration_ms":12}
{"audit_v":1,"ts":"2026-07-26T12:35:01.114Z","command":"query","alias":"prod","engine":"postgres","cwd":"/home/me/app","sql":"DELETE FROM users","verdict":"refused","reason":"WRITE_OPERATION","exit_code":5,"duration_ms":0}
```

Fields: `audit_v` (the record-schema version, independent of the envelope `v`),
`ts` (ISO 8601 UTC, ms), `command`, `alias`, `engine`, `cwd`, `sql`
(query/explain — the RAW text, so a hidden-character injection is visible) or
`table` (schema's argument), `verdict` (`ok`/`refused`/`error`), `reason` (the
NYET reason or the `error.code`), `exit_code`, `row_count`+`truncated` (query),
`duration_ms`, and `warnings` (the warning codes). **Never logged: passwords,
`password_env` values, or the connection url** — only the alias and engine, so
an inline-password url can never leak into the log.

Read it with `jq`, e.g. every write an agent attempted against `prod`:

```sh
jq -c 'select(.alias=="prod" and .verdict=="refused")' ~/.local/share/nyet/audit.jsonl
```

**Logging the results too.** `log_responses = true` adds a `response` field with
the exact rows the agent received (post-truncation, in column order) — off by
default because of volume and the PII in the data itself. Same rule: no
credentials.

**Fail-closed.** The record is written *before* the result is handed to the
agent. If the log cannot be written (bad path, no permission, full disk), the
query result is **withheld**: the agent gets `AUDIT_FAILED` (exit 1) and no
data, so you never miss an event the agent acted on. Fix the path/permissions,
or turn auditing off:

```toml
[audit]
enabled = false                              # default true; for CI/containers
path = "/var/log/nyet/audit.jsonl"           # default $XDG_DATA_HOME/nyet/audit.jsonl
log_responses = false                        # default; true logs result rows too
```

An explicit `path` is a literal — `${VAR}` substitution is rejected there, so a
config owner who pins the path controls it and the calling agent cannot rewrite
that pin through the environment. **But the *default* path is resolved from
`XDG_DATA_HOME`/`HOME`, which the agent's environment controls**: an agent that
sets `XDG_DATA_HOME=/tmp/junk` (leaving `HOME` so the config still resolves)
sends the log there, and you would find `~/.local/share/nyet/audit.jsonl` empty
and wrongly conclude the agent did nothing. This is the same known boundary as
cwd spoofing (see the threat model: an agent with shell/environment access is
out of scope; the real defense is layer 3, a read-only DB role). **If you need a
trail that survives an agent with environment control, set an explicit literal
`[audit] path`** somewhere the agent's env does not steer, and back it with a
read-only role. The file is created `0600` (it holds the agent's SQL); an
existing file with looser permissions gets a stderr warning (nyet warns, it does
not chmod — like the config file). The parent directory is created if missing.
Durability is a process-level flush, not `fsync`: the record survives a process
crash and is visible to readers immediately, but a full power loss may drop the
very last line — the accepted trade for not paying an fsync on every query.

**Rotation is external.** nyet only appends; point `logrotate` (or your tool of
choice) at the file. It stays valid jsonl across a rotation because each line is
written whole under an advisory lock, so concurrent `nyet` processes never
interleave.

## Output contract

stdout always carries exactly one compact JSON envelope. For data formats
other than json, the data goes to stdout and the envelope — success or error
alike — to stderr as one JSON line; on error stdout stays empty. The
envelope's place is decided by the format, not the outcome. stderr is
otherwise human-readable diagnostics. Errors:

```json
{"v":1,"ok":false,"error":{"code":"DIR_NOT_ALLOWED","message":"...","hint":"..."}}
```

Every error carries an actionable `hint`. Error codes today:
`CONFIG_INVALID`, `DIR_NOT_ALLOWED`, `NOT_IMPLEMENTED`, `INTERNAL`,
`AUDIT_FAILED` (the audit log could not be written — the result is withheld,
see [Audit log](#audit-log)), `NYET` (with `reason`, see above),
`CONNECTION_FAILED`, `DB_ERROR`, `TIMEOUT`.
Warning codes: `TRUNCATED`, `DUPLICATE_COLUMNS`, `UNICODE_STRIPPED`,
`INSECURE_TRANSPORT`, `SCHEMA_TRUNCATED`, `SCHEMA_SAMPLED`,
`GUARDRAIL_SKIPPED`, `NO_PLAN`.

`nyet doctor` carries a `checks` array instead — one object per diagnostic
(`{name, status, message, hint?}`) — and always `ok: true` (it ran; the verdicts
are per-check). `status` is a closed list: `ok`, `warn`, `fail`, `na`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success (including success with warnings) |
| 1 | internal error / engine not implemented yet / audit log unwritable (`AUDIT_FAILED`) |
| 2 | CLI usage error |
| 3 | config error (not found, invalid, unknown alias) |
| 4 | connection not allowed from the current directory |
| 5 | query refused by the validator or the guardrail (`error.code = "NYET"`) |
| 6 | connection failed (file missing/unreadable, network, auth, ssh tunnel) |
| 7 | the database returned an execution error |
| 8 | timeout |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
