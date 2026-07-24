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
cli (src/main.rs) — clap, orchestration, all IO, exit codes
├─ config   (src/config.rs)   — pure: TOML text -> validated structures; env lookup injected
├─ resolver (src/resolver.rs) — pure: (cwd, allowed_dirs) -> allowed?; canonicalize injected
└─ output   (src/output.rs)   — pure: values -> envelope/table strings
```

Dependencies flow downward only: config/resolver/output do no IO and know
nothing about clap or each other; file reading, env access, cwd and realpath
live in the cli layer and are passed in as parameters/closures. `validator`
and `engines` join this map in later steps.

## Dependencies (Д8: each one justified)

Runtime:

- `clap` (derive) — CLI parsing, usage errors with exit 2; the de facto standard.
- `serde` (derive) — typed config/output structures with `deny_unknown_fields`.
- `toml` — the config format; also gives the `Value` tree we walk for `${VAR}` substitution.
- `serde_json` — the agent-facing envelope; compact serialization.

Dev:

- `tempfile` — per-test isolated dirs with cleanup; symlink/permission fixtures
  without touching the real `~/.config`.

No async runtime and no DB drivers yet — the query stub does not need them.

## Tests

- Unit tests live next to the code (`src/*.rs`, `#[cfg(test)]`): config
  parsing/substitution/permissions, resolver path logic, envelope snapshots.
- `tests/cli.rs` runs the real binary via `CARGO_BIN_EXE_nyet` with
  `env_clear()` + a temp `HOME`, pinning exit codes and envelope structure
  (Д7: the output is an API — changing codes/structure must break tests).

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
| `CONFIG_INVALID` | 3 | config not found / unreadable / bad TOML / unknown key / missing `${VAR}` / unknown alias. One code for the whole class — deliberate; details live in `message`. |
| `DIR_NOT_ALLOWED` | 4 | alias exists but cwd is outside its `allowed_dirs` |
| `NOT_IMPLEMENTED` | 1 | `nyet query` stub after successful resolution |
| `INTERNAL` | 1 | nyet's own failure (e.g. cwd cannot be resolved) |

Codes are append-only; renaming/removing one is a breaking change (bump `v`).
Every error must carry an actionable `hint` (Д10) — tests enforce it.
