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
- `nyet query` for **SQLite**: SQL validation (read-only allowlist), the
  database file opened read-only (`mode=ro`), row limit, timeout, json and
  table output;
- the stable JSON envelope and exit-code contract.

Server engines (PostgreSQL, MySQL) arrive in later releases; `nyet query`
against them resolves the connection and returns `NOT_IMPLEMENTED`.

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
format = "json"        # default output format: json | table

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

# Validator policy tuning (parsed and validated now; takes effect when the
# function denylist lands).
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
nyet query <alias> <sql> [--format json|table] [--limit N] [--timeout SECS]
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
warning suggesting `AS` aliases. With `--format table` the rows go to
stdout as an aligned table and the envelope (without `rows`) goes to stderr
as one JSON line.

### How to read a refusal

Every query passes a SQL validator before touching the database. A refusal
has `code = "NYET"`, exits with 5, and always says why and what to do:

```json
{"v":1,"ok":false,"error":{"code":"NYET","reason":"WRITE_OPERATION","message":"nyet: 'DELETE FROM' is not a read operation","hint":"nyet is read-only; only SELECT, EXPLAIN, SHOW and DESCRIBE statements are accepted — rewrite the task as a read query"}}
```

`error.reason` is a closed list:

| reason | meaning |
|---|---|
| `PARSE_FAILED` | the query could not be parsed — anything not understood is denied (fail closed) |
| `MULTI_STATEMENT` | more than one statement in a single query |
| `WRITE_OPERATION` | not a read statement (DML/DDL/PRAGMA/ATTACH/..., including writes dressed as reads: `WITH ... DELETE`, `SELECT INTO`, `EXPLAIN <write>`) |
| `TXN_CONTROL` | transaction or session control (BEGIN/COMMIT/ROLLBACK/SET) |

PRAGMA is refused with a pointer instead of a dead end: schema questions
have a SELECT answer (`SELECT name, sql FROM sqlite_master WHERE type = 'table'`).

The full allow/deny specification is the public test corpus in
[`tests/corpus/`](tests/corpus/).

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
Warning codes: `TRUNCATED`, `DUPLICATE_COLUMNS`.

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
