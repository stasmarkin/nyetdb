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
- the stable JSON envelope and exit-code contract.

`nyet query` is not implemented yet — it fully resolves the connection
(so alias and directory-scoping errors are real) and then honestly returns
`NOT_IMPLEMENTED`. Query execution arrives in the next release.

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
# Global defaults, overridable per connection
# (parsed and validated now; takes effect when query execution lands).
[defaults]
row_limit = 1000       # max rows returned per query
timeout_secs = 30      # per-query timeout
format = "json"        # default output format

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

# Validator policy tuning (takes effect when the SQL validator lands).
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
nyet query <alias> <sql>   # not implemented yet; resolves and says so
```

`nyet list` prints aliases and engines only — never URLs or credentials:

```json
{"v":1,"ok":true,"connections":[{"alias":"localdev","engine":"sqlite"}]}
```

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
`CONFIG_INVALID`, `DIR_NOT_ALLOWED`, `NOT_IMPLEMENTED`, `INTERNAL`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | internal error / not implemented yet |
| 2 | CLI usage error |
| 3 | config error (not found, invalid, unknown alias) |
| 4 | connection not allowed from the current directory |

Codes 5–8 (validator refusal, connection, DB error, timeout) are reserved and
arrive with query execution — see [docs/DESIGN.md](docs/DESIGN.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
