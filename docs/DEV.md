# nyetdb — Development

## Build & test

```sh
cargo build                                # binary: target/debug/nyet
cargo test                                 # unit + integration (see Docker note below)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check                           # cargo install cargo-deny --locked (or brew install cargo-deny)
cargo audit                                # cargo install cargo-audit --locked (or brew install cargo-audit)
```

Stable Rust; no nightly features. `#![forbid(unsafe_code)]` on the whole crate.

### Integration tests need Docker

The PostgreSQL tests (`src/engine.rs` layer-2/decoding, `tests/postgres.rs` e2e via
the binary) spin a real `postgres:16-alpine` container through testcontainers. They
are **not** `#[ignore]`d — CI runs them, and they *fail* (not skip) without a Docker
daemon, on purpose. To run locally:

```sh
colima start                               # or Docker Desktop — any Docker daemon
docker pull postgres:16-alpine             # first run only; cached after
echo $DOCKER_HOST                           # testcontainers reads this (colima socket)
cargo test                                 # containers come up and are reaped per test
```

The SQLite and validator/config/resolver tests need no Docker.

## Module map (PRINCIPLES Д2)

```
cli (src/main.rs) — clap, orchestration, all IO, exit codes, tokio runtime
├─ config    (src/config.rs)    — pure: TOML text -> validated structures; env lookup injected
├─ resolver  (src/resolver.rs)  — pure: (cwd, allowed_dirs) -> allowed?; canonicalize injected
├─ validator (src/validator.rs) — pure: (SQL text, Policy) -> Allow{sql,warnings} |
│                                 Deny{reason,message,hint}; depends ONLY on
│                                 sqlparser + unicode-properties (+std)
├─ engine    (src/engine.rs)    — IO adapters behind trait Engine; knows sqlx,
│                                 nothing about clap/output
└─ output    (src/output.rs)    — pure: values -> envelope/table strings
```

Dependencies flow downward only: the pure modules do no IO and know nothing
about clap or each other; file reading, env access, cwd/realpath, the tokio
runtime and the query timeout live in the cli layer. The runtime is built
lazily, only when an engine actually executes (Д9: `list`, config errors and
validator refusals never start it).

## Dependencies (Д8: each one justified)

Runtime:

- `clap` (derive) — CLI parsing, usage errors with exit 2; the de facto standard.
- `serde` (derive) — typed config/output structures with `deny_unknown_fields`.
- `toml` — the config format; also gives the `Value` tree we walk for `${VAR}` substitution.
- `serde_json` (feature `arbitrary_precision`) — the agent-facing envelope;
  compact serialization. `arbitrary_precision` keeps JSON numbers exact instead
  of routing them through f64, so a `jsonb` value like
  `{"n": 123456789012345678901234567890}` is not silently rounded. The feature is
  global; verified against every envelope snapshot test — ordinary integers still
  serialize as bare numbers (`"row_count":2`, not `"2"`), nothing is quoted.
- `sqlparser` (no default features + `visitor`) — the SQL AST the validator
  classifies; writing a SQL parser ourselves is not 30 lines. The `visitor` feature
  drives the recursive walk (writes in CTE bodies / derived tables / subqueries,
  locking clauses, function calls) — one derived traversal instead of hand-walking
  every AST variant, which would silently miss new ones. Without the
  `recursive-protection` stack-growing feature the parser's built-in recursion limit
  turns absurdly nested input into a parse error — which we deny anyway (fail closed).
- `unicode-properties` (no default features, `general-category` only) — the Cf/Cc
  table for Unicode stripping. `char::is_control` covers only Cc; Cf (zero-width
  joiners, direction overrides, BOM) needs the General_Category data, and a
  hand-maintained range table would silently rot as Unicode evolves — fail closed
  wants the real table. Chosen over alternatives per Д8: unicode-rs org (the
  maintainers of the ecosystem's core unicode crates), zero dependencies, no_std,
  tiny generated tables.
- `sqlx` (runtime-tokio; `sqlite-bundled`, `postgres`, `bigdecimal`, `uuid`, `chrono`,
  `json`) — the SQLite and PostgreSQL drivers. `sqlite-bundled` (not the `sqlite`
  meta-feature) keeps `load-extension` and friends out of a security tool. The
  `postgres` feature is the built-in driver — no new top-level dependency. The four
  type features are the price of reading a real Postgres table: `bigdecimal` decodes
  `numeric` losslessly to a string (f64 would round money/ids), `uuid`, `chrono`
  (timestamp/date/time) and `json` (jsonb straight into the envelope) cover the types
  prod tables are full of; without them a normal `SELECT` would DB_ERROR on decode.
  No TLS feature yet (testcontainers and SSH-tunnelled prod are plaintext to
  localhost); TLS lands with a later step. Postgres layer 2 is server-enforced:
  connect options `-c default_transaction_read_only=on -c statement_timeout=<ms>`
  plus an explicit `BEGIN READ ONLY` around the read.
- `tokio` (rt, time, net) — sqlx requires an async runtime; `time` gives the query
  timeout, `net` the Postgres TCP connection. The per-query runtime uses
  `enable_all` (io + time). Single-threaded, built per query.
- `futures-util` (no default features) — `try_next()` on sqlx's row stream, to fetch
  limit+1 rows instead of the whole result. Already in sqlx's own tree.

Dev:

- `tempfile` — per-test isolated dirs with cleanup; symlink/permission fixtures
  without touching the real `~/.config`.
- `testcontainers-modules` (`postgres` feature) — the PostgreSQL integration and
  e2e tests need a real server; this spins a throwaway `postgres:16-alpine`
  container per test and tears it down. Chosen over a hand-rolled `docker run`
  wrapper (Д8): it owns image pull, readiness wait and cleanup (the ryuk reaper),
  and the `postgres` module ships the ready image config. Dev-only — it never
  reaches a release binary. Its (large) transitive tree passes `cargo deny`
  (licenses/advisories/bans/sources) as of this step.

## Tests

- Unit tests live next to the code (`src/*.rs`, `#[cfg(test)]`): config
  parsing/substitution/permissions, resolver path logic, envelope snapshots,
  validator corpus, engine read-only/decoding (on temp SQLite files).
- `tests/cli.rs` runs the real binary via `CARGO_BIN_EXE_nyet` with
  `env_clear()` + a temp `HOME`, pinning exit codes and envelope structure
  (Д7: the output is an API — changing codes/structure must break tests).
  Query tests build a fixture SQLite database with sqlx.
- `tests/postgres.rs` is the same for PostgreSQL against a testcontainers
  Postgres: success (json/table), row-limit truncation, DB_ERROR (exit 7),
  server-timeout (exit 8), CONNECTION_FAILED (exit 6, closed port), and a
  password-leak guard (a distinctive password must never appear in stdout/stderr).
  The container runs inside `block_on` so its async `Drop` (which removes the
  container) always has a runtime — even when an assertion unwinds.
- `src/engine.rs` holds the layer-2 proof for Postgres: a write issued *directly*
  to the engine (bypassing the validator) is refused by the read-only transaction
  (`EngineError::Db`), the table stays intact, common types decode as documented,
  and a server `statement_timeout` maps to `EngineError::Timeout` (not `Db`, so
  exit 8 is deterministic).

## Validator corpus (Д6)

`tests/corpus/*.yaml` is the public specification of what the validator
allows and denies. **A validator rule does not exist without corpus cases**
— every rule needs at least one allow and one deny case, and a discovered
bypass gets a failing corpus case first, then the fix.

Format — a deliberately tiny YAML subset (parsed by ~40 lines in
`src/validator.rs` tests; a yaml crate is not worth the supply-chain surface
for this, Д8):

```yaml
# comment
- query: SELECT * FROM users WHERE id = 1
  verdict: allow
- query: DELETE FROM users
  verdict: deny
  reason: WRITE_OPERATION
```

Rules: one case per `- query:` line (single-line queries only — semicolons
are fine, block scalars are not supported); `verdict` is `allow` or `deny`;
`deny` requires `reason` (one of `PARSE_FAILED`, `MULTI_STATEMENT`,
`WRITE_OPERATION`, `TXN_CONTROL`, `LOCKING_CLAUSE`, `DENIED_FUNCTION`);
optional `warnings` on an allow case is the comma-joined list of expected
warning codes (currently only `UNICODE_STRIPPED`) — allow cases without it
must produce none, deny cases never carry warnings; optional `dialect`
defaults from the **filename prefix** — `postgres_*.yaml` runs the PostgreSQL
dialect + `Policy::postgres`, everything else SQLite + `Policy::sqlite` — and a
per-case `dialect: postgres|sqlite` still overrides. Unknown lines fail the run
loudly. The runner (`validator::tests::golden_corpus`) reads every `*.yaml` in
the directory, so adding a case is: append it to a fitting file (or add a new
file), run `cargo test golden_corpus`. The corpus runs with the default policy
(`Policy::sqlite(&[], &[])` / `Policy::postgres(&[], &[])`); config-tuned policies are
covered by unit tests next to the merge logic. Note `sqlite_unicode.yaml`
contains REAL invisible characters (that is the point) — edit it with a
tool that shows them.

**Found a bypass?** The process is fixed (Д6): first add the bypass to the
corpus as a failing deny case (this documents it publicly and proves the
gap), then fix the validator until the corpus is green. Never the other
way around — a fix without a corpus case does not exist.

## Function denylist rationale (SQLite)

Everything here is defense in depth: nyet's own bundled SQLite
(`sqlite-bundled`, no `load-extension` feature) ships none of these attack
surfaces, but the validator is a public specification that must hold for
any SQLite build and any future engine reusing the mechanism.

- `load_extension` — loads an arbitrary shared library into the process:
  code execution. Blocked even though the bundled build compiles it out.
- `fts3_tokenizer` — the historical two-argument form accepted a raw
  pointer and enabled memory corruption; modern SQLite gates it behind a
  compile/runtime option. No read-only query needs it.
- `readfile` / `writefile` — file I/O helpers from the sqlite3 CLI shell
  and the fileio extension: arbitrary file read/write if present.
- `edit` — sqlite3 CLI helper that spawns an interactive editor process.

An empty list would also have been defensible for the bundled build; the
list is kept non-empty because it costs nothing and the corpus cases keep
the DENIED_FUNCTION machinery honest.

## Function denylist rationale (PostgreSQL)

Unlike SQLite these are real, always-present risks: they act *outside* the
read-only transaction (session/cluster/filesystem/network), so layer 2 does
not stop them — the validator (layer 1) is the only guard. Built-in list
(DESIGN §3 п.7), all `DENIED_FUNCTION`:

Exact names (config-tunable via `allow_functions` / `deny_functions`):

- `pg_terminate_backend` / `pg_cancel_backend` — kill or cancel another
  session's query: availability attack, works in a read-only txn.
- `pg_reload_conf` — reloads server config; `pg_promote` — promotes a
  standby (cluster-level state change).
- `pg_sleep`, `pg_sleep_for`, `pg_sleep_until` — silent DoS: tie up a pooled
  connection (DESIGN decision 3). **Enumerated on purpose** (not the prefix
  `pg_sleep`) so DESIGN's documented escape hatch `allow_functions = ["pg_sleep"]`
  still works — prefixes are not config-tunable.
- `nextval` / `setval` / `pg_logical_emit_message` — **the sharp ones:** Postgres
  runs these even inside `SET TRANSACTION READ ONLY`. `nextval` advances and
  `setval` resets a sequence; `pg_logical_emit_message` writes a non-transactional
  WAL record that survives ROLLBACK — durable writes that bypass BOTH layers, so
  the validator is the only guard. (`currval` / `lastval` are pure reads and stay
  allowed.)
- `lo_import` / `lo_export` — read a server file into / write a large object out
  to a server file: filesystem in/exfiltration.
- `pg_stat_file` — stats an arbitrary server file (not a `pg_read_`/`pg_ls_` name).

Prefix families (built-in only, **not** config-tunable — every current and
future member is dangerous and none is a legitimate agent read, so fail-closed
completeness beats an override nobody should use):

- `dblink*` — `dblink`, `dblink_connect`, `dblink_exec`, `dblink_send_query`, …
  open outbound connections and run SQL on other servers.
- `pg_read_*` — `pg_read_file`, `pg_read_binary_file`: arbitrary server-file read.
- `pg_ls_*` — `pg_ls_dir`, `pg_ls_logdir`, `pg_ls_waldir`, …: server-directory listing.

**enumerate vs prefix:** prefix where the whole family is uniformly dangerous
and un-overridable (`dblink`, `pg_read_`, `pg_ls_`) — fail closed on members we
did not list. Enumerate where an override is documented/plausible (`pg_sleep`
family) so `allow_functions` keeps working, or where no clean prefix exists
(`nextval`/`setval`/`lo_*`/`pg_stat_file`).

Deliberately *not* included: `pg_advisory_*` locks (session-scoped, released on
disconnect — low severity, and `pg_try_advisory_*` wouldn't share the prefix
cleanly). Add with a failing corpus case first (Д6) if it ever matters.

**Matching is on the terminal name component.** `check_function_name` compares
the denylist against the LAST component of a (maybe qualified) function name —
that component is the function name. So `pg_catalog.pg_read_file(...)` is caught
(terminal `pg_read_file` hits the `pg_read_` prefix), while `pg_sleep.safe_fn()`
(a schema/table happens to be named `pg_sleep`) is NOT a denied call — `safe_fn`
runs. Consequently the config denylists (`allow_functions` / `deny_functions`)
take **unqualified** names only: a dotted entry like `admin.mutate` is matched
literally and never equals a terminal name, so it is a no-op (use the bare
function name).

**Denylist matching limitation.** The policy matches by name only against
generic call syntax: `Expr::Function` (`f(...)` in any expression) and the
table-factor forms `TableFactor::Table { args }` / `Function` (`FROM f(...)`,
`FROM LATERAL f(...)`). SQL keyword-functions that sqlparser parses into
dedicated AST nodes — `TRIM`, `CAST`/`TRY_CAST`, `EXTRACT`, `SUBSTRING`,
`POSITION`, `OVERLAY`, `UNNEST` (as `TableFactor::UNNEST`), … — are NOT
matched by name, so a custom `deny_functions = ["trim"]` would not catch
`TRIM(...)`. This is fine for the built-in list: all five entries
(`load_extension`, `readfile`, `writefile`, `edit`, `fts3_tokenizer`) parse
as generic `Expr::Function` (verified), and the keyword-functions are
read-only builtins with no side effects worth denying. If a future denylist
entry needs a keyword-parsed function, add a dedicated visitor arm for its
AST node.

## CI (.github/workflows/ci.yml)

Three jobs on push/PR, stable toolchain:

- **check** — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (with `Swatinem/rust-cache`). Runs on `ubuntu-latest`, which ships
  a working Docker daemon, so the testcontainers Postgres tests run for real (they
  pull `postgres:16-alpine` over the runner's network). Nothing is weakened — the
  same suite CI runs is the one you run locally with Docker up.
- **deny** — `EmbarkStudios/cargo-deny-action` with `deny.toml`
  (advisories, license allowlist, bans, sources).
- **audit** — `cargo audit` against the RustSec advisory DB
  (installed via `taiki-e/install-action`).

## Error codes (closed list, part of the contract)

| code | exit | when |
|---|---|---|
| `CONFIG_INVALID` | 3 | config not found / unreadable / bad TOML / unknown key / missing `${VAR}` / unknown alias / sqlite without `path` / unsupported `[defaults].format` / zero `row_limit`/`timeout_secs`. One code for the whole class — deliberate; details live in `message`. |
| `DIR_NOT_ALLOWED` | 4 | alias exists but cwd is outside its `allowed_dirs` |
| `NYET` | 5 | query refused by the validator; `error.reason` from the closed list `PARSE_FAILED` / `MULTI_STATEMENT` / `WRITE_OPERATION` / `TXN_CONTROL` / `LOCKING_CLAUSE` / `DENIED_FUNCTION` (owner: `src/validator.rs`) |
| `CONNECTION_FAILED` | 6 | database unreachable (sqlite: file missing / unreadable / a directory; postgres: refused, auth failure, or a hung TCP handshake that exceeds the connect deadline — bounded separately inside the engine so a blackholed connect is 6, not 8) |
| `DB_ERROR` | 7 | the database accepted the connection but rejected the query |
| `TIMEOUT` | 8 | query did not finish within the per-query timeout (the future is dropped; a stuck sqlite worker may run until process exit). Postgres: the server `statement_timeout` (SQLSTATE 57014) maps here too, so the exit code is deterministic whichever timer fires; 57014 is `query_canceled` generally, so a manual `pg_cancel_backend` from another session also lands as TIMEOUT (rare, acceptable) |
| `NOT_IMPLEMENTED` | 1 | resolved connection uses an engine this version does not ship |
| `INTERNAL` | 1 | nyet's own failure (e.g. cwd cannot be resolved) |

Warning codes (`warnings[].code`, also closed and append-only): `TRUNCATED`,
`DUPLICATE_COLUMNS`, `UNICODE_STRIPPED`.

Codes are append-only; renaming/removing one is a breaking change (bump `v`).
Every error must carry an actionable `hint` (Д10) — tests enforce it.

`nyet query` pipeline order is pinned by tests: format (right after config
parse — it routes every later envelope) -> alias -> directory scoping ->
engine support / connection config -> validator -> execution. Scoping and
engine support answer before the validator so the agent gets the real
blocker, not a SQL lecture.
