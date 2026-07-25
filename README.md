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
- `nyet query` for **SQLite** and **PostgreSQL**: the full SQL validator
  (read-only allowlist, recursive AST walk, Unicode stripping, locking clauses,
  per-engine function denylist with per-connection policy), session read-only
  enforcement (SQLite `mode=ro`; PostgreSQL `default_transaction_read_only` +
  server `statement_timeout` + an explicit `BEGIN READ ONLY`), row limit,
  timeout, json / jsonl / csv / table output;
- the stable JSON envelope and exit-code contract.

MySQL/MariaDB and SSH tunnels arrive in later releases; `nyet query` against a
not-yet-supported engine resolves the connection and returns `NOT_IMPLEMENTED`.
PostgreSQL over TLS is not wired up yet (connect to localhost, e.g. via the
coming SSH tunnel).

- [Roadmap](ROADMAP.md)
- [Design](docs/DESIGN.md)
- [Development](docs/DEV.md)

## Install

```sh
cargo install --path .
```

(Prebuilt binaries, installer and Homebrew come with v0.1.)

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

# SSH tunnel (takes effect when tunnels land).
[connections.prod.ssh]
host = "deploy@bastion.corp:22"
remote = "db.internal:5432"
control_persist = "15m"

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
returns a DB_ERROR asking you to `::text`-cast the column.

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
`[defaults].format` is `jsonl`/`csv`, `list` falls back to `json`.

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

The validator pipeline: strip invisible Unicode (Cf/Cc) characters → parse
(the engine's SQL dialect — SQLite or PostgreSQL) → exactly one statement →
recursive AST walk. The walk denies write/DDL statements anywhere in the tree
(CTE bodies including data-modifying CTEs like `WITH x AS (DELETE ... RETURNING)`,
derived tables, subqueries), locking clauses (`FOR UPDATE`/`FOR SHARE`),
`COPY`, `SET`, and denylisted functions.

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
`UNICODE_STRIPPED` (invisible characters removed from the query).

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
Warning codes: `TRUNCATED`, `DUPLICATE_COLUMNS`, `UNICODE_STRIPPED`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success (including success with warnings) |
| 1 | internal error / engine not implemented yet |
| 2 | CLI usage error |
| 3 | config error (not found, invalid, unknown alias) |
| 4 | connection not allowed from the current directory |
| 5 | query refused by the validator (`error.code = "NYET"`) |
| 6 | connection failed (file missing/unreadable, network, auth) |
| 7 | the database returned an execution error |
| 8 | timeout |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
