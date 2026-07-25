# nyetdb

> **Your AI agent can look. For everything else — nyet.**

`nyet` is a safety-first CLI for read-only database access by AI agents
(Claude Code, Cursor, and other harnesses). One user-owned config file with
credentials, per-directory scoping, layered read-only enforcement (SQL AST
validation + session-level read-only + read-only roles), and JSON output
designed for agents.

Planned support: PostgreSQL, MySQL/MariaDB, SQLite, Redis, MongoDB, ClickHouse.

## Status

**In development.** What works today:

- config: parsing, validation (unknown keys are hard errors), `${VAR}`
  substitution, `password_env`, file permission warnings;
- directory scoping (`allowed_dirs`) and `nyet list`;
- `nyet schema` for all three engines: tables, views, columns, primary keys,
  unique constraints, indexes and foreign keys as structured JSON (see below);
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
- the stable JSON envelope and exit-code contract.

Redis, MongoDB and ClickHouse arrive in later releases; `nyet query` against a
not-yet-supported engine resolves the connection and returns `NOT_IMPLEMENTED`.
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

[connections.prod]
engine = "postgres"                    # postgres | mysql | sqlite | ...
url = "postgres://nyet_ro@db.internal:5432/app"
password_env = "PROD_DB_PASSWORD"      # NAME of an env var; no password in the file
# Directories this connection is reachable from (subdirectories included).
# Empty or absent = denied everywhere (fail closed). "Everywhere" is an
# explicit choice: allowed_dirs = ["~"].
allowed_dirs = ["~/Workspace/app"]
row_limit = 500
timeout_secs = 10

# Validator policy tuning — see the Security section below.
# CAUTION: every allow_functions entry is a conscious risk you take.
[connections.prod.validator]
allow_functions = ["pg_sleep"]         # remove from the built-in denylist
deny_functions = ["my_scary_fn"]       # add your own bans

# SSH tunnel to reach the database through a bastion (see the section below).
[connections.prod.ssh]
host = "deploy@bastion.corp:22"     # [user@]bastion[:port]
remote = "db.internal:5432"         # host:port to forward to, as seen from the bastion
control_persist = "15m"             # optional; default 15m

[connections.analytics]
engine = "mariadb"                     # or "mysql" — same driver/dialect
url = "mysql://nyet_ro@db.internal:3306/shop"
password_env = "ANALYTICS_DB_PASSWORD"
allowed_dirs = ["~/Workspace/shop"]

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
`max_statement_time` in seconds — which nyet sets for you). `url` is required
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

### SSH tunnels (a database behind a bastion)

The common production setup — the database is only reachable from a jump host —
works for PostgreSQL and MySQL/MariaDB by adding an `[ssh]` section to the
connection:

```toml
[connections.prod.ssh]
host = "deploy@bastion.corp:22"     # [user@]bastion[:port]; port defaults to 22
remote = "db.internal:5432"         # the db host:port as resolved from the bastion
control_persist = "15m"             # optional (default 15m); see reuse below
```

When a query runs, `nyet` shells out to the **system `ssh`** to open a local
port forward (`ssh -f -N -L 127.0.0.1:<random>:db.internal:5432 deploy@bastion.corp -p 22`),
then connects the database engine to `127.0.0.1:<random>`. The `url`'s host and
port are replaced by the tunnel; its user, database and query parameters are
kept, and the password still comes from `password_env`. A free local port is
picked automatically.

- **The forward lives only for the query; the master is reused.** The port
  forward is opened for the query and **torn down when the query finishes** (so
  forwards do not pile up across a session). What persists between runs is the
  `ssh` *master* connection: opened with `ControlMaster=auto
  ControlPersist=<control_persist>` over a per-destination `ControlPath`, it stays
  in the background so the *next* `nyet` call reuses it with no new handshake.
  (`control_persist` accepts `yes`/`no` or a time like `15m`/`1h`/`900`; an
  invalid value is a config error, exit 3. On systems where the `ControlPath`
  socket would exceed the OS length limit, `nyet` skips reuse — the tunnel still
  works, each run just pays a fresh handshake.)
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
- **TLS is disabled on the tunnel leg — and the bastion→DB hop is plaintext.**
  The `nyet`→bastion hop is encrypted by SSH, so `nyet` forces `sslmode=disable`
  for the loopback connection (any `sslmode` in the `url` is ignored when
  tunnelled — TLS verification against `127.0.0.1` would fail against a
  certificate naming the real host anyway). But `ssh -L` is a raw TCP forward
  that **terminates at the bastion**: the bastion→database hop is a separate
  plaintext TCP connection. So the database must be in a network segment trusted
  relative to the bastion (or the bastion co-located with the DB). To encrypt
  the DB link end to end, use a **direct** connection with `sslmode`/`ssl-mode`
  instead of a tunnel.
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

> **TLS behavior — encrypt direct connections; the tunnel leg is plaintext by
> design.** Direct (non-tunnelled) connections use `nyet`'s TLS backend (rustls)
> and honor the `sslmode`/`ssl-mode` in the `url`. Two things to know: (1) the
> **default** (`prefer`/`PREFERRED`) uses TLS *when the server offers it* but
> silently falls back to plaintext if it does not — set `require`/`REQUIRED` to
> force encryption, and `verify-full`/`VERIFY_IDENTITY` to also authenticate the
> server (recommended for production; a bare `require` encrypts but does not
> verify the certificate, so it does not stop a MITM); (2) over an **SSH tunnel**
> the client→bastion hop is encrypted by SSH but the bastion→database hop is a
> separate plaintext TCP connection (`nyet` forces `sslmode=disable` on the
> loopback leg — see the TLS bullet above), so for an end-to-end-encrypted DB
> link prefer a direct `verify-full` connection over a tunnel.

Rules:

- `${VAR}` is substituted in any string value; a missing variable is a hard
  error (exit 3), never an empty string. Exception: `allowed_dirs` — see below.
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
nyet query <alias> <sql> [--format json|jsonl|table|csv] [--limit N] [--timeout SECS]
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
built-in default, omit the key. If the result has more rows than the limit,
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
`[defaults].format` is `jsonl`/`csv`, `list` falls back to `json`. `nyet
schema` follows the same rule.

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
and denylisted functions.

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
| `WRITE_OPERATION` | not a read statement (DML/DDL/PRAGMA/ATTACH/...), anywhere in the query: top level, CTE bodies (`WITH x AS (DELETE ...)`), derived tables (`SELECT * FROM (DELETE ...)`), subqueries, `SELECT INTO`, `EXPLAIN <write>` |
| `TXN_CONTROL` | transaction or session control (BEGIN/COMMIT/ROLLBACK/SET) |
| `LOCKING_CLAUSE` | `SELECT ... FOR UPDATE` / `FOR SHARE` — takes row locks, not a plain read |
| `DENIED_FUNCTION` | a function on the denylist for this connection (the message names it) |
| `EXECUTABLE_COMMENT` | a MySQL/MariaDB executable comment or optimizer hint (`/*! … */`, `/*M! … */`, `/*+ … */`) — the server runs its body but a SQL parser drops it, so nyet cannot see what it does; remove the comment |

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
  connection forever — DoS), and the replication-wait family `master_pos_wait`/
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
  guard. Prefix families are built-in and not tunable via `allow_functions`; the
  enumerated names (including `pg_sleep`) are.

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
`DUPLICATE_COLUMNS` (json rows would collapse same-named keys),
`UNICODE_STRIPPED` (invisible characters removed from the query),
`INSECURE_TRANSPORT` (a direct server connection whose url `sslmode`/`ssl-mode`
is below `require` and has no ssh tunnel — the transport is not guaranteed
encrypted or verified; the message says how to force TLS),
`SCHEMA_TRUNCATED` (`nyet schema` listed objects by name only — more than 50
tables + views).

The full allow/deny specification is the public test corpus in
[`tests/corpus/`](tests/corpus/): every validator rule exists there as at
least one allow and one deny case, and every known bypass is pinned as a
corpus case first, then fixed.

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
`CONFIG_INVALID`, `DIR_NOT_ALLOWED`, `NOT_IMPLEMENTED`, `INTERNAL`, `NYET`
(with `reason`, see above), `CONNECTION_FAILED`, `DB_ERROR`, `TIMEOUT`.
Warning codes: `TRUNCATED`, `DUPLICATE_COLUMNS`, `UNICODE_STRIPPED`,
`INSECURE_TRANSPORT`, `SCHEMA_TRUNCATED`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success (including success with warnings) |
| 1 | internal error / engine not implemented yet |
| 2 | CLI usage error |
| 3 | config error (not found, invalid, unknown alias) |
| 4 | connection not allowed from the current directory |
| 5 | query refused by the validator (`error.code = "NYET"`) |
| 6 | connection failed (file missing/unreadable, network, auth, ssh tunnel) |
| 7 | the database returned an execution error |
| 8 | timeout |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
