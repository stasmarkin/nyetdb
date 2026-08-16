# Commands

```sh
nyet list                       # connections reachable from the current directory
nyet schema  <alias> [table]    # tables, columns, keys, indexes, foreign keys
nyet sample  <alias> <table>    # a random handful of rows
nyet query   <alias> <sql>      # run a read query
nyet explain <alias> <sql>      # the plan and the estimate, without running it
nyet doctor  [alias]            # diagnose the setup
nyet settings                   # open the config in your editor
nyet agent-setup                # generate a Claude Code skill
nyet secret-set <name>          # store a password in the macOS Keychain
nyet import datagrip            # write config blocks from a JetBrains IDE
```

`query`, `sample`, `schema`, `explain` and `doctor <alias>` reach a database and
are [logged](SECURITY-MODEL.md#audit-log). The rest never touch one.

## Flags

| Flag | Applies to | Notes |
|---|---|---|
| `--config <path>` | all | overrides `$NYET_CONFIG` and the default path |
| `--format json\|jsonl\|table\|csv` | `query`, `sample` | `json` by default |
| `--format json\|table` | `list`, `schema`, `explain`, `doctor` | no row stream to shape; `doctor` defaults to `table`, the others to `json` |
| `--format markdown\|json` | `agent-setup` | `markdown` by default |
| `--limit N` | `query`, `sample` | rows |
| `--timeout SECS` | `query`, `sample` | seconds |

`settings`, `secret-set` and `import` take no `--format` at all — passing one is
a usage error (exit 2).

`--limit` / `--timeout` beat the per-connection `row_limit` / `timeout_secs`,
which beat `[defaults]`, which beat the built-ins (1000 rows, 30 s). Where you
set `max_row_limit` / `max_timeout_secs`, the ceiling beats the flag, silently —
the effective value shows up in the answer (`TRUNCATED`, or `TIMEOUT`).

A `jsonl`/`csv` in `[defaults].format` degrades to `json` for `list`, `schema`
and `explain`, which have no row stream. `doctor` ignores `[defaults].format`
entirely: only an explicit `--format` moves it off `table`.

## nyet list

Aliases and engines — never urls, never credentials.

```json
{"v":1,"ok":true,"connections":[{"alias":"localdev","engine":"sqlite"}]}
```

## nyet query

```console
$ nyet query prod "SELECT id, email FROM users ORDER BY id LIMIT 2"
{"v":1,"ok":true,"rows":[{"id":1,"email":"a@b.c"},{"id":2,"email":"d@e.f"}],"meta":{"row_count":2,"truncated":false,"duration_ms":3,"connection":"prod"}}
```

Row objects keep column order. A result longer than the limit is cut and marked
in `meta.truncated` and as a `TRUNCATED` warning; duplicate column names earn a
`DUPLICATE_COLUMNS` warning. What each engine accepts is in
[ENGINES.md](ENGINES.md); what gets refused, in
[SECURITY-MODEL.md](SECURITY-MODEL.md).

## nyet schema

```sh
nyet schema <alias>          # every table and view
nyet schema <alias> <table>  # one object, always in full detail
```

```console
$ nyet schema prod users --format table
users table
  id      bigint  not null  pk  default nextval('users_id_seq'::regclass)
  email   text    not null  unique
  org_id  bigint  null
  index users_org_idx (org_id)
  fk (org_id) -> orgs (id)
```

How to read it:

- `kind` is `table` or `view`; views carry columns, never indexes or keys.
- `nullable` is always present. `pk`, `unique` and `default` appear only when
  true or present — an omitted field means false/none.
- `unique` marks a single-column unique constraint, and that index is not
  repeated under `indexes`. A **partial** unique index is listed as an ordinary
  index *without* `unique`: it holds only for the rows its predicate matches.
- `indexes` lists what column flags cannot express — non-unique and
  multi-column. An expression key part reads as `(expression)`.
- `fks` are arrays on both sides, in key order.
- `type` is whatever the engine calls it. Auto-increment shows up in `default`;
  the portable signal is `pk`.
- A `[pii]`-protected column is marked `"pii": "deny"` / `"mask"`.

**Adaptive listing.** Without `[table]`, up to **50** tables + views come back
in full; past that, names and kinds with a `SCHEMA_TRUNCATED` warning. Naming a
table always returns full detail; an unknown name is a `DB_ERROR` (exit 7).

**You see only what your role may read.** Under a partial, column-level grant
**keys are dropped whole rather than shortened** — a missing key costs a round
trip, a wrong one costs a wrong query. Objects in `public` read as bare names,
everything else is qualified (`sales.orders`), which is the form `[table]`
accepts too.

## nyet sample

```sh
nyet sample <alias> <table> [--limit N] [--timeout SECS]
```

Ten rows at random by default (`--limit` up to 1000000). It is **sugar over
`nyet query`**: nyet writes the statement and runs it through the same
validator, guardrail, `[pii]` policy, row limit and audit log, so a sample can
never see a row a query could not.

The draw is random, because the first ten rows of a table are not a sample of
it — which means sorting the whole table, so on a big one the guardrail refuses
it. nyet then retries **once** with the first N rows, inside what is left of the
timeout, and marks it `SAMPLE_FALLBACK`. Only that refusal is retried; a PII
refusal, a database error or a timeout is the answer.

A `SELECT *` of a table with a `[pii]` column is refused in **both** modes,
`mask` included — name the columns with `nyet query` instead. Redis has no table
to draw from, so `sample` is refused there.

## nyet explain

```console
$ nyet explain prod "SELECT id FROM users WHERE email = 'a@b.c'"
{"v":1,"ok":true,"estimate":{"mode":"cost","verdict":"ok","cost":8.29,"rows":1,"threshold":1000000.0,"plan":[...]},"meta":{...}}
```

The plan, whatever estimate the engine publishes, and the guardrail verdict —
**without running the query**.

- `verdict` — `ok`, `expensive` (`nyet query` would refuse this), or
  `no_estimate` (nothing to compare).
- `cost` / `rows` / `threshold` appear only when they exist.
- It exits **0** even on `expensive`: this is information, not a refusal.
- A metadata statement (`SHOW`, `DESCRIBE`, an `EXPLAIN` you wrote yourself) has
  no plan to ask for — `no_estimate` plus a `NO_PLAN` warning, without touching
  the database.

The same validator applies, so `explain` is no way around it, and `EXPLAIN
ANALYZE` is refused everywhere. "Does not run the query" means the *statement*
is not executed; planning itself is not free, and PostgreSQL evaluates constant
`IMMUTABLE` expressions while it plans.

## The auto-guardrail

Before `nyet query` runs anything, nyet asks the database to **plan** it and
compares the estimate with the connection's threshold. Over it, the query is not
executed:

```json
{"v":1,"ok":false,"error":{"code":"NYET","reason":"EXPENSIVE_QUERY","message":"... above the guardrail limit of 1000000 for connection 'prod' — the query was NOT executed","hint":"narrow the query ..."},"estimate":{...,"plan":[...]}}
```

Exit 5, with the plan attached so the query can be fixed without another round
trip. On by default, with a deliberately generous limit: it exists to stop a
scan of tens of millions of rows, not to second-guess your analytics.

| Engine | Modes | Default | Default limit |
|---|---|---|---|
| PostgreSQL | `cost`, `rows`, `off` | `cost` | `max_cost = 1000000.0` |
| MySQL / MariaDB | `rows`, `off` | `rows` | `max_rows = 10000000` |
| ClickHouse | `rows`, `off` | `rows` | `max_rows = 10000000` |
| SQLite, MongoDB, Redis | `off` only | `off` | — |

- `cost` is the PostgreSQL planner's own unitless number; `rows` is an estimate
  of *work*, not a promise.
- **A mode an engine cannot honor is a config error (exit 3)**, never a silent
  downgrade — and so is a threshold the active mode never reads.
- **There is no `--force`.** The threshold belongs to whoever owns the config.
  Narrow the query, or ask for a higher `max_cost` / `max_rows`.
- A plan with no usable number lets the query **run anyway**, with a
  `GUARDRAIL_SKIPPED` warning; a recursive CTE's plan is treated as a lower
  bound, so already over the limit still refuses. Metadata statements carry no
  plan and run unguarded.
- If **planning itself** outruns its budget (always inside your `timeout_secs`),
  the query is **refused** — planning time is something a query can inflate on
  purpose.
- **A plan exposes more than a result does** — base tables, indexes, the
  predicates behind a view, the qualifiers RLS adds. Restrict an agent's account
  with grants, not by pointing it at a view.

## nyet doctor

```console
$ nyet doctor prod
ok    connectivity         connected to the database
warn  transport_encrypted  the transport is not guaranteed encrypted or verified ...
fail  read_only_role       these credentials CAN write to the database directly ...
                           → CREATE ROLE nyet_ro LOGIN PASSWORD '...' NOSUPERUSER ...
ok    not_superuser        the role is not a PostgreSQL superuser
ok    config_permissions   the config file is readable only by its owner (mode 0600)
```

The one command written for a **human**: it defaults to `--format table` and
names the weak spots instead of printing a green wall. Statuses are a closed
list — `ok`, `warn`, `fail`, `na` (does not apply to this engine). **Unknown is
never `ok`**: something doctor could not verify is a `warn`, because a false
pass in a security tool is worse than a false warning.

It **always exits 0 when it ran** — the verdicts live in the checks, and a
broken connection is a `fail` check, not exit 6. The only non-zero exits are the
ones every command shares: a config that cannot be read or an unknown alias
(exit 3), and an engine this build does not ship (exit 1).

| Check | Applies to | What a non-`ok` means |
|---|---|---|
| `connectivity` | all | nyet cannot reach the database (through the tunnel, if any) |
| `transport_encrypted` | server engines | the url is below `require` and there is no tunnel, so the link may be plaintext |
| `read_only_role` | all | **layer 3 is missing** — these credentials can write directly, bypassing nyet |
| `read_only_session` | Redis | always `na`: Redis has no layer 2, and saying nothing would hide that |
| `readonly_setting` | ClickHouse | `2` looks read-only but lets a client raise its own limits; `0` leaves only the grants |
| `not_superuser` | server engines | a superuser bypasses every read-only layer |
| `secret_source` | with a `password` | `na`: the password comes from a file, env var or command, so any process under your uid reads it too. A keychain item is `ok` |
| `pii_columns` | with `[pii]` | the role can read a marked column directly — only nyet is protecting it |
| `pii_views` | with `[pii]` | a view exposes a protected column; rules follow names, not lineage |
| `ssh_forward` | with `[ssh]` | always `ok` — reports the port, its age, and the `ssh -O exit` that removes it |
| `server_side_js` | MongoDB | the server may evaluate JavaScript for any other client with these credentials |
| `config_permissions` | all | the config is group/other-readable (`chmod 600`) |

`read_only_role` is proved, not assumed. On the SQL engines a probe write runs
against a uniquely named object with nyet's own read-only session **removed**
(rolled back on PostgreSQL; create-then-drop on MySQL/MariaDB, which can leave a
`nyet_doctor_probe_…` table if the role lacks `DROP` — doctor names it). MongoDB
publishes its privilege list instead, so nothing is written there at all. Redis
reads the account's own ACL — except on the account these docs recommend, which
cannot read it (`ACL` lives in `@admin`); doctor then falls back to a single
write, `SET <unique> 1 EX 1 NX`, which can overwrite nothing (`NX`) and expires
by itself within a second.

One honest limit: the probe proves the role cannot `CREATE`, so a role granted
`INSERT`/`UPDATE`/`DELETE` but not `CREATE` also reads `ok` — grant **only
`SELECT`**.

With no alias, `doctor` checks the config and lists the connections reachable
from here. A named alias is diagnosed regardless of `allowed_dirs`.

## nyet agent-setup

```sh
mkdir -p .claude/skills/nyet                      # `>` does not create it
nyet agent-setup > .claude/skills/nyet/SKILL.md   # install as a Claude Code skill
nyet agent-setup --format json                    # the same, inside an envelope
```

Generates a Claude Code skill that teaches an agent to use nyet: the commands
with examples, how to read the envelope and the exit codes, how to recover from
a refusal. It needs no database and no network, and works **even without a
config**. The dynamic half lists the connections reachable from the current
directory — run it from the project the skill will live in.

## nyet settings · secret-set · import

- `nyet settings` opens the config in `$VISUAL` / `$EDITOR` / `vi`. The value is
  split on whitespace (`EDITOR="code -w"` works) but is not shell-parsed. Quit
  without saving and the empty file nyet just created is removed again.
- `nyet secret-set <name>` stores a password in the macOS login keychain, read
  from stdin — see [Getting started](GETTING-STARTED.md#where-the-password-lives).
- `nyet import datagrip` writes connection blocks from your JetBrains IDEs — see
  [Getting started](GETTING-STARTED.md#import-from-datagrip).

## Output formats

With `--format json` (the default) the whole answer is one compact envelope on
stdout. The other three stream the data on stdout and put the envelope —
success or error alike — on **stderr**, as one JSON line; on error stdout stays
empty. The envelope's place is decided by the format, not by the outcome.

- `table` — aligned columns for human eyes.
- `jsonl` — one compact JSON object per row, keys in column order.
- `csv` — header + rows with RFC 4180 quoting, `NULL` as an empty field. A value
  starting with `=`, `+`, `-`, `@` (or a tab/CR) is prefixed with `'` to stop
  spreadsheet formula injection, which alters those values by one character —
  use `json`/`jsonl` when you need byte-exact data.

Nested values (a `jsonb` column, a MongoDB subdocument) render as compact JSON
inside their cell.

## The envelope

```json
{"v":1,"ok":true,"rows":[...],"meta":{"row_count":2,"truncated":false,"duration_ms":3,"connection":"prod"}}
{"v":1,"ok":false,"error":{"code":"DIR_NOT_ALLOWED","message":"...","hint":"..."}}
```

`warnings` is present only when non-empty. Every error carries an actionable
`hint`. `nyet schema` carries a `schema` object instead of `rows` (with `na` and
`databases` on an engine that has no schema), and `nyet doctor` carries a
`checks` array and always `ok: true`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including success with warnings) |
| 1 | internal error / engine not implemented / audit log unwritable |
| 2 | CLI usage error |
| 3 | config error (not found, invalid, unknown alias) |
| 4 | connection not allowed from the current directory |
| 5 | refused by the validator or the guardrail (`error.code = "NYET"`) |
| 6 | connection failed (file, network, auth, ssh tunnel) |
| 7 | the database returned an execution error |
| 8 | timeout |

### Error codes

`CONFIG_INVALID`, `DIR_NOT_ALLOWED`, `NOT_IMPLEMENTED`, `INTERNAL`,
`AUDIT_FAILED`, `NYET` (with a `reason` — see
[refusals](SECURITY-MODEL.md#how-to-read-a-refusal)), `CONNECTION_FAILED`,
`DB_ERROR`, `TIMEOUT`.

### Warning codes

| Code | Meaning |
|---|---|
| `TRUNCATED` | the row limit cut the result |
| `GUARDRAIL_SKIPPED` | no usable estimate, so the query ran unchecked against the limit |
| `NO_PLAN` | `nyet explain` was given a metadata statement |
| `DUPLICATE_COLUMNS` | JSON rows would collapse same-named keys |
| `UNICODE_STRIPPED` | invisible characters were removed from the query |
| `INSECURE_TRANSPORT` | a direct connection nyet cannot confirm is encrypted, with no tunnel |
| `SCHEMA_TRUNCATED` | `nyet schema` listed objects by name only |
| `SCHEMA_SAMPLED` | MongoDB: part of that schema was inferred from a sample |
| `SAMPLE_FALLBACK` | `nyet sample` returned the first rows, not a random draw |
| `PII_MASKED` | the named columns came back as `[REDACTED]` |

The envelope `v`, the exit codes and both code lists are a **contract**: closed
lists that an agent may branch on.
