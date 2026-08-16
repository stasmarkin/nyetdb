# nyetdb — Implementation plan

The ROADMAP answers "what and why"; this plan answers "in what order". Rules
for slicing the steps:

- **Every step adds business value** — after the merge, a user (human or
  agent) can do something new that can be demonstrated.
- **Every step is self-contained** — no groundwork "for later": code needed in
  step N+2 gets written in step N+2 (YAGNI, step by step, D5).
- **Definition of Done for every step:**
  1. tests written and green (corpus / integration / snapshot — whichever the
     step calls for);
  2. README.md (the operating manual) extended for the new capability;
  3. DEV.md (the development manual) extended if the structure or the
     process changed;
  4. fmt + clippy (deny warnings) + cargo-deny clean;
  5. one step = one PR/commit into main with a meaningful message.

The order of engines is pragmatic and differs from the product priority in the
ROADMAP: SQLite comes first as a walking skeleton (the whole pipeline with no
servers and no testcontainers), PostgreSQL remains the flagship of the
release. v0.1 is declared after step 6.

---

## Step 1 — Skeleton: config + resolver + `nyet list` + CI

**Value:** the human writes a config and immediately checks that it is valid
and correctly scoped; the agent sees which connections are reachable from the
current directory.

**Scope:**
- clap skeleton (`list`, and `query` as a stub with an honest
  `NOT_IMPLEMENTED` error);
- config: toml → pure structures, `${VAR}` env substitution, `password_env`,
  unknown key = error, warning about file permissions;
- resolver: (cwd, config) → reachable connections (canonicalize, prefix);
- JSON envelope v1 (`ok`/`error`), exit codes 0/1/2/3/4;
- GitHub Actions CI: fmt, clippy (deny), test, cargo-deny + cargo-audit.

**Tests:** unit tests for config (valid / broken / env / permissions), unit
tests for the resolver (symlinks, `~`, nested paths), a snapshot of the `list`
envelope.

**Docs:** README: installation, a full config example, `nyet list`.
DEV.md is created: build, running tests, the module map (from PRINCIPLES
D2).

## Step 2 — `nyet query` for SQLite: the first end-to-end

**Value:** the agent reads local `.db` files safely — already useful in real
work (agents have SQLite at hand constantly).

**Scope:**
- trait `Engine` + the SQLite engine (sqlx, `mode=ro` — file-level read-only);
- the validator, minimal core: parse (fail closed) → single statement →
  top-level allowlist (`Query`/`Explain`/`Show*`/`Describe`);
- row limit (fetch limit+1 → `truncated`), timeout;
- output: json (default) + table; the `warnings` field; exit codes 5/7/8.

**Tests:** the first golden corpus (`tests/corpus/*.yaml`, SQLite dialect:
basic allow/deny), integration tests against a fixture database, snapshots of
the success / refusal / truncation envelopes.

**Docs:** README: `nyet query`, the formats, how to read a refusal (`NYET` +
reason + hint). DEV: how the corpus works and how to add a case.

## Step 3 — The whole validator (layer 1 as declared in DESIGN)

**Value:** the layer-1 security model fully matches DESIGN §3 — for every
current and future SQL engine; policy becomes configurable.

**Scope:**
- Unicode normalization (Cf/Cc) + the `UNICODE_STRIPPED` warning;
- recursive AST visitor: writes in CTEs and subqueries;
- locking clauses (`FOR UPDATE` / `FOR SHARE`);
- a per-engine function denylist + `validator.allow_functions` /
  `deny_functions` from the config;
- the jsonl (envelope on stderr) and csv output formats.

**Tests:** the corpus grows to hold every known bypass (CTE write,
multi-statement, SET, zero-width, denylist, locking) — that corpus *is* the
public security specification; unit tests for merging policy from the config.

**Docs:** README: a Security section — what is blocked, what is configurable.
DEV: the "found a bypass → failing test into the corpus → fix" process.

## Step 4 — PostgreSQL: the flagship engine

**Value:** the product's main scenario — an agent reading production or
staging PostgreSQL.

**Scope:**
- the Postgres engine: `default_transaction_read_only=on` plus a
  `SET TRANSACTION READ ONLY` wrapper plus `statement_timeout` (layer 2);
- PostgreSqlDialect in the validator, a Pg branch of the corpus.

**Tests:** testcontainers: layer 2 really holds (a write smuggled past the
validator by hand fails at the database level); e2e query / timeout /
row-limit.

**Docs:** README: connecting Postgres, the read-only role recommendation (with
the SQL to create it). DEV: how to run the integration tests locally (docker).

## Step 5 — SSH tunnels

**Value:** production behind a bastion — the most common real-world setup —
works.

**Scope:** shelling out to the system `ssh -N -L` with `ControlMaster=auto
ControlPersist=15m`, a random local port, tunnel failures → exit 6 with a
clear hint.

**Tests:** an integration test with an openssh container (a touch stand: a
bastion container plus a Postgres container); unit tests for building the ssh
command line and for parsing its errors.

**Docs:** README: the ssh config section with an example. DEV: how to bring up
the ssh stand.

## Step 6 — MySQL/MariaDB + the release pipeline → **release v0.1**

**Value:** a second server-side database; the tool installs with one command,
without cargo.

**Scope:**
- the MySQL engine (`SET SESSION TRANSACTION READ ONLY`,
  `max_execution_time`), a MySqlDialect branch of the corpus, testcontainers;
- dist: GitHub Releases + shell installer + Homebrew tap; version 0.1.0;
- README: the safety story as the main pitch (material for the announcement).

**Docs:** README: installing via the installer or brew. DEV: the release
process (tag → dist → artifacts).

---

## After v0.1 (the slicing will be refined by feedback)

Every item is the same kind of self-contained step, with its own value, tests
and docs:

7. ~~`nyet schema` — introspection in a token-optimized format (UX-3, UX-4).~~ **done**
8. ~~`nyet explain` + the auto-guardrail on plan cost.~~ **done**
9. ~~`nyet doctor` — honest diagnostics of the setup (UX-7).~~ **done**
10. ~~`nyet agent-setup` — generating a Claude Code skill (SKILL.md) for the agent (UX-3).~~ **done**
11. ~~The audit log (UX-8).~~ **done**
12. ~~An npm wrapper via dist.~~ **done** — `@stasmarkin/nyetdb`, scoped because
    npm's similarity rule leaves the short names to nobody; there was no name
    to close a backlog on.
13. The Redis engine (`COMMAND INFO`).
14. The MongoDB engine (its own command allowlist).
15. The ClickHouse engine (`readonly=1`).
16. The connection daemon — only after latency is measured (ROADMAP v0.5).

## Rules for keeping this plan

- The plan is alive: after every step we re-check, and the next step may be
  re-sliced.
- A step does not start until the previous one is deployed to main with green
  CI.
- If "groundwork we will need later" shows up mid-step, that is a signal to
  re-slice the steps, not to write the groundwork (D5).
