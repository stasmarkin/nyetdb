# Working on nyet

A safety-first CLI for read-only database access by AI agents. Crate `nyetdb`,
binary `nyet`. This file is the map; it deliberately holds no detail that lives
somewhere better.

## Where the truth is

| Question | File |
|---|---|
| How to build, test, fuzz, release | `docs/DEV.md` |
| Why the design is what it is | `docs/DESIGN.md`, `docs/PRINCIPLES.md` |
| What ships when | `ROADMAP.md`, `docs/PLAN.md` |
| What the tool promises users | `README.md` (the error/warning code tables are contract) |
| What to run | `justfile` — `just` alone lists the recipes |

## Commands

- `just test-fast` — unit + cli tests, seconds, **no Docker**. The default loop.
- `just test` / `just check` — everything including testcontainers; `check` is the
  pre-commit gate (fmt, clippy `-D warnings`, tests, `cargo deny`, `cargo audit`).
  Both need a Docker daemon; the recipe says so plainly when there is none.
- `just mutants` — mutation-tests the validator's security boundary. ~12 min,
  pre-release only.

## Conventions

- **English only.** The repository was deliberately de-Russified (`e102ad3`),
  including the `Dn` / `§3 step N` anchors that deny.toml, the workflows and half
  of `src/` cite. The Cyrillic that remains is test data — homoglyph and unicode
  fixtures in `src/sample.rs` and `src/datagrip.rs` — and must stay.
- **Prose is hard-wrapped** at ~78 columns in every `.md` here. Follow the file
  you are editing; tables and code blocks run long.
- **Comments and commit messages explain WHY.** Subject line, blank line, then
  prose that argues the decision — what the alternative was and why it lost. The
  git log is the design record; match it rather than writing `fix: update deps`.

## Releasing

`docs/DEV.md` has the process. Two things worth knowing before you touch it:

- **Order by irreversibility.** Tag → wait for the pipeline to go green → then
  `cargo publish` → then `just npm-publish <version>`. A tag can be re-cut and a
  GitHub Release deleted; a crates.io version is spent forever, and npm gives you
  72 hours and no more. Never run the two publishes before the build is proven.
- **`dist generate` is destructive.** It rewrites `.github/workflows/release.yml`
  and reverts four hand-applied hardenings (SHA-pinned actions, per-job
  permissions, the `v`-prefixed tag regex, the attestation permissions block).
  `allow-dirty = ["ci"]` keeps dist off that file; adding a `publish-jobs` entry
  is what forces a regenerate, so weigh that against re-applying the four by hand.

Both traps have already cost a release: `v0.1.0` was tagged onto GitHub's retired
`macos-13` runner label, which matches no runner and queues silently rather than
failing, and the first npm publish shipped dist's 2024 lockfile. Runner labels and
lockfiles rot on their own schedule — check them when dist is upgraded, not when
a tag is already pushed.
