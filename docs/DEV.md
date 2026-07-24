# nyetdb — Development

## Build & test

```sh
cargo build                                # binary: target/debug/nyet
cargo test                                 # unit + integration (no network, no real ~/.config)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check                           # cargo install cargo-deny --locked (or brew install cargo-deny)
cargo audit                                # cargo install cargo-audit --locked (or brew install cargo-audit)
```

Stable Rust; no nightly features. `#![forbid(unsafe_code)]` on the whole crate.

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
- `serde_json` — the agent-facing envelope; compact serialization.
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
- `sqlx` (runtime-tokio, sqlite-bundled only) — the SQLite driver with a first-class
  read-only open mode; `sqlite-bundled` instead of the `sqlite` meta-feature to keep
  `load-extension` and friends out of a security tool.
- `tokio` (rt, time only) — sqlx requires an async runtime; `time` gives the query
  timeout. Single-threaded runtime, built per query.
- `futures-util` (no default features) — `try_next()` on sqlx's row stream, to fetch
  limit+1 rows instead of the whole result. Already in sqlx's own tree.

Dev:

- `tempfile` — per-test isolated dirs with cleanup; symlink/permission fixtures
  without touching the real `~/.config`.

## Tests

- Unit tests live next to the code (`src/*.rs`, `#[cfg(test)]`): config
  parsing/substitution/permissions, resolver path logic, envelope snapshots,
  validator corpus, engine read-only/decoding (on temp SQLite files).
- `tests/cli.rs` runs the real binary via `CARGO_BIN_EXE_nyet` with
  `env_clear()` + a temp `HOME`, pinning exit codes and envelope structure
  (Д7: the output is an API — changing codes/structure must break tests).
  Query tests build a fixture SQLite database with sqlx.

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
defaults to `sqlite` (the only dialect in this step). Unknown lines fail
the run loudly. The runner (`validator::tests::golden_corpus`) reads every
`*.yaml` in the directory, so adding a case is: append it to a fitting file
(or add a new file), run `cargo test golden_corpus`. The corpus runs with
the default policy (`Policy::sqlite(&[], &[])`); config-tuned policies are
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
the DENIED_FUNCTION machinery honest. The PostgreSQL list (pg_sleep and
friends, DESIGN §3 п.7) deliberately does not exist yet — it lands with
the Postgres engine in step 4 (Д5: no data for engines that cannot run).

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
  `cargo test` (with `Swatinem/rust-cache`).
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
| `CONNECTION_FAILED` | 6 | database unreachable (sqlite: file missing / unreadable / a directory) |
| `DB_ERROR` | 7 | the database accepted the connection but rejected the query |
| `TIMEOUT` | 8 | query did not finish within the per-query timeout (the future is dropped; a stuck sqlite worker may run until process exit) |
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
