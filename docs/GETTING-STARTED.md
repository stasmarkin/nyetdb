# Getting started

Install `nyet`, describe your databases once, and point your agent at it.

## Install

Pick **one**:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/stasmarkin/nyetdb/releases/latest/download/nyetdb-installer.sh | sh
```
```sh
brew install stasmarkin/tap/nyetdb
```
```sh
cargo binstall nyetdb              # the same prebuilt archive, no compile
cargo install nyetdb               # or compiled here, from crates.io
```
```sh
npm install -g @stasmarkin/nyetdb  # for machines with Node and no Rust
```

The installer and Homebrew pin the archive by SHA-256 and install a binary
carrying a GitHub build-provenance attestation — check it with
`gh attestation verify <archive> --repo stasmarkin/nyetdb`. The npm wrapper
does **not** verify a checksum at install time; prefer the others.

macOS and Linux, x86_64 and aarch64. No Windows build yet (SSH tunnels and
some tests are unix-only). The MSRV is `rust-version` in `Cargo.toml`.

## Five minutes to the first query

```sh
nyet settings                                  # 1. write the config (below)
nyet secret-set prod-db                        # 2. store the password (macOS)
nyet doctor prod                               # 3. check it, honestly
mkdir -p .claude/skills/nyet                   # 4. teach the agent
nyet agent-setup > .claude/skills/nyet/SKILL.md
nyet query prod "SELECT count(*) FROM users"   # 5. read something
```

Already have the databases in a JetBrains IDE? `nyet import datagrip` writes
the connection blocks for you — see [Import from DataGrip](#import-from-datagrip).

## The config file

`nyet` reads exactly **one** file, resolved in this order:

1. `--config <path>`
2. `$NYET_CONFIG`
3. `~/.config/nyet/config.toml`

There is deliberately no per-project config: a file in a repository could be
written by an agent or arrive in a PR, and this file must be yours alone.

`nyet settings` opens it in `$VISUAL` / `$EDITOR` / `vi`, creating the
directory and the file (mode `0600`) if missing. It does not validate what you
saved — run `nyet doctor` after.

A complete example:

```toml
[defaults]
row_limit = 1000
timeout_secs = 30
format = "json"
max_row_limit = 10000       # ceilings the agent's --limit/--timeout cannot pass
max_timeout_secs = 60

[audit]
enabled = true
log_responses = false

[connections.prod]
engine = "postgres"
url = "postgres://nyet_ro@db.internal:5432/app?sslmode=verify-full"
password = { keychain = "prod-db" }
allowed_dirs = ["~/Workspace/app"]
row_limit = 500
timeout_secs = 10

[connections.prod.pii]
columns = ["users.email", "users.phone"]
mode = "deny"               # deny | mask

[connections.prod.guardrail]
mode = "cost"               # cost | rows | off
max_cost = 1000000.0

# A tunnelled connection. Note it does NOT ask for sslmode=verify-full: over a
# tunnel that is downgraded to verify-ca, since the certificate cannot name
# 127.0.0.1. See "SSH tunnels" below.
[connections.analytics]
engine = "mariadb"
url = "mysql://nyet_ro@db.internal:3306/shop"
password = { keychain = "analytics-db" }
allowed_dirs = ["~/Workspace/shop"]

[connections.analytics.ssh]
host = "deploy@bastion.corp:22"
remote = "db.internal:3306"

[connections.localdev]
engine = "sqlite"
path = "./dev.db"           # sqlite takes path, not url
allowed_dirs = ["~/Workspace/app"]
```

### Keys

**`[defaults]`** — overridable per connection, and by CLI flags.

| Key | Default | Meaning |
|---|---|---|
| `row_limit` | `1000` | max rows returned per query |
| `timeout_secs` | `30` | per-query timeout |
| `format` | `"json"` | `json` \| `jsonl` \| `table` \| `csv` |
| `max_row_limit` | none | ceiling: `--limit` cannot go above it |
| `max_timeout_secs` | none | ceiling: `--timeout` cannot go above it |

**`[audit]`** — see [Audit log](SECURITY-MODEL.md#audit-log).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` disables logging (CI, containers) |
| `path` | `~/.local/share/nyet/audit.jsonl` | `$XDG_DATA_HOME/nyet/audit.jsonl`; a literal, no `${VAR}` |
| `log_responses` | `false` | `true` also logs the result rows |

**`[connections.<alias>]`**

| Key | Required | Meaning |
|---|---|---|
| `engine` | yes | `postgres` \| `mysql` \| `mariadb` \| `sqlite` \| `mongodb` \| `clickhouse` \| `redis` |
| `url` | all but sqlite | includes the database name; never the password |
| `path` | sqlite only | the database file; relative resolves against the cwd |
| `password` | no | where the secret lives — see below |
| `allowed_dirs` | **yes, in practice** | absent or empty means *denied everywhere* |
| `row_limit`, `timeout_secs` | no | override `[defaults]` |
| `max_row_limit`, `max_timeout_secs` | no | ceilings for this connection |

Limits and timeouts must be at least `1`; a zero is rejected (in the config,
exit 3; as a flag, exit 2). Omit a key to get the built-in default.

**Sub-tables**, each optional and per connection:

| Table | Keys |
|---|---|
| `[connections.X.validator]` | `allow_functions`, `deny_functions` — see [the denylist](SECURITY-MODEL.md#function-denylist) |
| `[connections.X.pii]` | `columns`, `mode` (`deny` default, or `mask`) — see [PII columns](SECURITY-MODEL.md#pii-columns) |
| `[connections.X.guardrail]` | `mode` (`cost` \| `rows` \| `off`), `max_cost` (`1000000.0`), `max_rows` (`10000000`) — see [the guardrail](COMMANDS.md#the-auto-guardrail) |
| `[connections.X.ssh]` | `host`, `remote`, `control_persist` (`15m`), `reuse_forward` (`true`) — see [SSH tunnels](#ssh-tunnels) |

### Rules that bite

- **Unknown keys are hard errors.** A typo fails loudly instead of doing
  nothing.
- **`${VAR}` is substituted in string values**, and a missing variable is an
  error (exit 3), never an empty string.
- **Policy values reject `${VAR}` outright** — `allowed_dirs`,
  `validator.allow_functions` / `deny_functions`, `guardrail.mode`, the `[pii]`
  rules and mode, and an explicit `[audit] path`. The environment belongs to
  the calling agent, and it must not be able to widen its own scope.
- **There is no CLI flag that overrides a policy.** A limit the agent can lift
  is not a limit.
- A config file readable by group or others earns a stderr warning
  (`chmod 600`), not a refusal.

## Where the password lives

```toml
password = "hunter2"                                 # in the config
password = { keychain = "prod-db" }                  # macOS Keychain
password = { env = "PROD_DB_PASSWORD" }              # environment variable
password = { command = "op read op://vault/db/pw" }  # stdout of a command
url = { keychain = "prod-db-url" }                   # not even the address
```

The question is not whether the password is written down, but **whether the
agent can get it too** — and the agent runs under your uid, so it reads
whatever `nyet` reads.

| Source | Can the agent get it? |
|---|---|
| `{ keychain = "..." }` | **No.** macOS checks the caller's code signature; the agent's shell is not `nyet`, so it gets a prompt only you can answer. |
| config literal, `{ env }`, `{ command }` | **Yes.** Same file, same variable, same command. |

Store a keychain item with `nyet secret-set <name>`: it reads the secret from
stdin (never argv, which shows up in `ps`), and `nyet` creates the item
**itself** so the ACL trusts this binary alone. Installing a new build makes a
different binary — the next query then fails with a clear message and you hand
the item over deliberately by re-running `secret-set`. Reads on the normal path
never raise a dialog.

A source that cannot deliver — missing variable, failing command, absent
keychain item — is a hard error (exit 3), never a silent empty password. With
no `password` key at all, `nyet` connects without one (local trust/peer auth).

**What this does not do:** the config file is yours to write, and so is the
agent's. It can repoint `url` at a database it controls and have `nyet` hand
the real password over. Keeping the file out of reach is a different problem —
see [SECURITY.md](../SECURITY.md).

## Directory scoping

`allowed_dirs` lists the directories a connection is reachable from,
subdirectories included. **Absent or empty means denied everywhere** — fail
closed. "Everywhere" is an explicit choice: `allowed_dirs = ["~"]`.

Paths are canonicalized (symlinks resolved, `~` expanded) and compared by whole
components, so `/a/b` does not match `/a/bc`. Entries must be static literal
paths, absolute or `~/`-relative; relative entries, `~//…`, `..` components and
`${VAR}` are all rejected because each would widen the scope.

This is a guardrail against pointing an agent at the wrong database, not a
security boundary — an agent that controls its own working directory is out of
scope. The boundary is a read-only role.

## SSH tunnels

Reaching a database through a jump host works on every server engine (SQLite is
a local file, so `[ssh]` there is a config error):

```toml
[connections.prod.ssh]
host = "deploy@bastion.corp:22"   # [user@]bastion[:port]; 22 by default
remote = "db.internal:5432"       # host:port as resolved from the bastion
control_persist = "15m"           # yes | no | 15m | 1h | 900
reuse_forward = true
```

`nyet` shells out to the **system `ssh`** for a local port forward and connects
the engine to `127.0.0.1:<random port>`. Only host and port are replaced — the
user, database, query parameters and password ride along unchanged.

- **The forward is reused between runs**, at most one per (bastion, remote)
  pair, so the usual call spawns no `ssh` process at all.
- **It outlives the `nyet` process.** A loopback listener to your database stays
  up for `control_persist` of inactivity (15 min by default), and any process on
  the machine can reach the database through it while it lives. On a shared
  machine set `reuse_forward = false` or a short `control_persist`. `nyet doctor`
  shows the forward and prints the `ssh -O exit` that removes it — use that,
  never `ssh -O cancel`.
- **`~/.ssh/config` is inherited**: host aliases, `IdentityFile`, `ProxyJump`,
  known hosts.
- **Key or agent auth only.** The tunnel runs `BatchMode=yes`, so a
  password-only bastion is unsupported and the host key must already be known.
- **The tunnel leg is plaintext unless the url asks otherwise** — SSH already
  encrypts `nyet`→bastion, so a url that says nothing about TLS skips a
  pointless handshake, and then the **bastion→database hop is plaintext**: the
  database has to sit in a segment you trust relative to the bastion. An
  explicit `require` or stricter survives the tunnel instead, and the database's
  own TLS then runs end to end through the forward — with `verify-full`
  downgraded to `verify-ca`, because a certificate cannot name `127.0.0.1`. To
  verify the server's identity too, use a direct connection rather than a
  tunnel. On MongoDB the choice does not arise: an explicit `tls=true` together
  with `[ssh]` is a config error.
- `host` and `remote` are strictly validated (exit 3) — `[user@]host[:port]`
  with `A–Z a–z 0–9 . - _` only, so a value readable as an `ssh` option is
  rejected. No IPv6 literals; use a name.
- Any tunnel failure is `CONNECTION_FAILED` (exit 6) with a hint.

## Import from DataGrip

```sh
nyet import datagrip              # print the sections for review
nyet import datagrip --write      # append them to the config
nyet import datagrip --path ~/proj  # one project instead of a search
```

Without `--path` it reads every installed JetBrains IDE and every project each
one remembers, carrying over the engine, the url and enabled SSH tunnels;
ClickHouse urls are rewritten to the HTTP interface. Engines `nyet` does not
speak are named on stderr, and `--write` skips an alias the config already uses.

Two things are deliberately **not** imported. **Passwords** — each connection
gets a `password = { keychain = "<alias>" }` reference plus the `nyet secret-set`
line that fills it. And **`allowed_dirs`**, emitted empty (*denied everywhere*):
DataGrip does not record which project a database belongs to, and guessing
`["~"]` would open every production database the moment you ran the import.

## Next

- [Commands](COMMANDS.md) — everything `nyet` can do, and what it answers with
- [Engines](ENGINES.md) — per-engine specifics and the read-only account recipes
- [Security model](SECURITY-MODEL.md) — the three layers, PII, the audit log
