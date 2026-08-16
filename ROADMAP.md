# nyetdb — Roadmap

A Rust CLI for database access, aimed at AI agents (Claude Code, Cursor and
the like) and at harnesses.

> **Your AI agent can look. For everything else — nyet.**

**Name:** the brand, repository and crate are `nyetdb`, the binary is `nyet`
(the ripgrep→`rg` pattern: the brand is unique and searchable, the command is
short). Claimed (July 2026): GitHub (stasmarkin/nyetdb), crates.io (`nyetdb`
plus the `nyet` alias).
On npm neither short name is obtainable, and not by anyone: the registry's
name-similarity rule refuses `nyetdb` (too close to `nedb`) and `nyet` (`nyc`,
`net`, `ret`, `nuxt`, `next`, `nopt`, `uyat`). There is accordingly nothing to
reserve there — the package is scoped, `@stasmarkin/nyetdb`, and exists to be
installable rather than to hold a name. Domains are deferred (decision: not
buying any for now).

**Positioning:** a safety-first CLI. The differentiation is not the breadth of
database support (Google's MCP Toolbox covers ~47 sources) but the combination
of **plain CLI + layered read-only + directory scoping + agent UX**
(structured hints, schema introspection, an auto-guardrail via EXPLAIN). The
niche was confirmed by research (July 2026): universal CLIs (usql) have no
query validation, the AI-facing competitors (MCP Toolbox, DBHub) went the
MCP-server route, and benchmarks show that a CLI for agents costs fewer tokens
with no loss in success rate. The namespace and the "restrain the AI agent"
niche are being actively taken (nono, leash, declaw — all 2025–26).

## Principles

- **CLI-first.** If an MCP mode is ever needed (only on explicit user request
  — see "Deliberately out of scope"), it is a wrapper built from the same
  binary, not the other way around.
- **Layered security, not a single layer.** AST validation (sqlparser-rs, fail
  closed) + session read-only (`default_transaction_read_only=on`, `SET
  TRANSACTION READ ONLY`, single statement) + a recommended read-only
  role/replica (`nyet doctor`). A naive allowlist on `Statement::Query` is not
  enough (writes inside CTEs and so on).
- **Only the user creates the config.** Credentials never reach the LLM's
  context — the agent works with aliases.
- **Directory scoping is a UX barrier, not a security boundary** (cwd can be
  spoofed by the agent). We document that honestly; the real boundary is the
  read-only layers.
- **nyet talks to the agent**: the response carries a `warnings` field
  (truncation, timings, missing indexes), not just data. A refusal is a
  feature and a brand: the `NYET` code.

## Stack

| Area | Choice |
|---|---|
| PostgreSQL / MySQL / MariaDB / SQLite | sqlx (dynamic `query()`, no MSSQL support) |
| Redis / Valkey | redis-rs (`tokio-comp`, low-level `cmd()`, RESP3; write-command classification comes from the native `COMMAND INFO`) |
| MongoDB | the official `mongodb` crate (our own read/write command classification) |
| ClickHouse | hyper + hyper-rustls straight over the HTTP interface, `FORMAT JSONCompact` (the official crate is built around `#[derive(Row)]`/RowBinary — typed structs where arbitrary columns are needed) |
| Cassandra / ScyllaDB | the `scylla` crate (deferred, on demand) |
| SQL validation | sqlparser (apache/datafusion-sqlparser-rs), the `visitor` feature |
| CLI / config / output | clap, serde + toml (+ `${VAR}` env substitution), serde_json |
| Runtime | tokio |
| Driver composition | cargo feature flags; the release binary carries all of them |
| SSH tunnels | shelling out to the system `ssh` (inherits ~/.ssh/config, the agent, ProxyJump); russh only if people complain |
| Distribution | dist (a fork of astral-sh/cargo-dist): GitHub Releases, shell installer, Homebrew, an npm wrapper. Crate `nyetdb`, `[[bin]] name = "nyet"` |

## Database priority

1. **PostgreSQL** — the MVP, the reference vertical slice.
2. **MySQL/MariaDB, SQLite** — nearly free on top of sqlx; SQLite doubles as
   the demo and as the agents' local `.db` files.
3. **Redis** — cheap to implement, and "look at what is in the cache" is a
   frequent scenario.
4. **MongoDB** — a large audience, more expensive because of its own command
   classification.
5. **ClickHouse** — prioritized over Cassandra: popular with developers,
   analytics queries from agents, a native `readonly=1`, and the dialect
   exists in sqlparser-rs.
6. Cassandra/ScyllaDB, MSSQL (tiberius), Elasticsearch, DWHs — on user
   request.

Items 1–5 are done (August 2026).

## Milestones

### v0.1 — the vertical slice (PostgreSQL end-to-end)

- [x] Skeleton: clap, toml config + env substitution, a file permission check (warn if not 0600)
- [x] Resolver: alias + cwd → connection (`allowed_dirs`)
- [x] Trait `Engine`; the PostgreSQL implementation (sqlx)
- [x] Validator: sqlparser-rs — fail closed, single statement, transaction
      control and SET denied, a recursive AST walk (writes in CTEs and
      subqueries)
- [x] Session read-only + statement timeout + row limit (30s / 1000 rows by
      default, overridable per connection; `"truncated": true` on truncation)
- [x] SSH tunnels: the system ssh, `ControlMaster=auto ControlPersist=15m` by
      default → tunnel reuse between runs comes for free
- [x] Formatters: json (default) / jsonl / table / csv; token-thrifty JSON
- [x] `nyet list` — the connections reachable from cwd
- [x] The `warnings` field in the response
- [ ] Run the validator against a corpus of real-world queries (measure the
      share of false fail-closed refusals before freezing the behavior).
      Something else got done instead: a synthetic golden corpus
      `tests/corpus/*.yaml` (~2200 lines, allow/deny/pii across three
      dialects) as the public specification of the rules. That is not a
      measurement: the queries were written by hand against the rules
      themselves, and the false-refusal rate on real traffic is still unknown

### v0.2 — sqlx breadth + release

- [x] MySQL/MariaDB, SQLite (they reuse the pipeline)
- [x] dist: the release pipeline, installers, a Homebrew tap, an npm package.
      Shipped as **v0.2.0** (August 2026): GitHub Release with four attested
      archives, the shell installer, `stasmarkin/homebrew-tap` with the formula,
      and `nyetdb` on crates.io. The npm wrapper is wired into dist as
      `@stasmarkin/nyetdb` and ships from v0.3.0 on. `v0.1.0` was tagged and
      never announced — dist pointed the Apple builds at GitHub's retired
      `macos-13` image, which matches no runner and queues rather than fails
      (see docs/dev/DEV.md, release process)
- [ ] README: the safety story + a token benchmark against MCP servers
      (material for HN). The safety story is written in full (Status,
      Security, the read-only layers, warning codes, the audit log); the token
      measurement against MCP servers does not exist

### v0.3 — agent UX (the key differentiators)

- [x] `nyet schema <alias> [table]` — compact introspection (tables, columns,
      indexes, FKs) in a token-optimized format
- [x] `nyet explain` — EXPLAIN with a human-readable verdict
- [x] Auto-guardrail: EXPLAIN before a heavy query; cost above the threshold →
      do not execute, return the plan and advice
- [x] `nyet doctor` — connectivity, whether the role really is read-only (a
      write inside a rolled-back transaction), whether it is a superuser,
      config permissions (plus checks of transport encryption and of the
      role's rights on PII columns)
- [x] `nyet agent-setup` — a snippet for AGENTS.md or a skill with examples
      (generates a Claude Code `SKILL.md`; works without a config and without
      the network)
- [x] The audit log `~/.local/share/nyet/audit.jsonl`

### v0.4 — NoSQL

The milestone is closed: MongoDB was done first, while Redis and ClickHouse
went off into the wishlist (W8, W9) and came back done — see "Done outside the
milestones".

- [x] MongoDB (its own command classification): `query` — a parser for a
      subset of mongosh plus a closed allowlist (step 1);
      `schema`/`explain`/`doctor` — step 2. MongoDB has no schema, so `schema`
      marks the origin of every field (`validator` — a declared `$jsonSchema`,
      `sample` — a guess from a sample); `explain` runs strictly in
      `queryPlanner` mode (the others EXECUTE the query) and invents no
      estimates; `doctor` proves read-only from the privilege list, without a
      trial write. What is missing, stated plainly: layer 2 (session read-only
      does not exist in MongoDB) and the guardrail. `[pii]` started as a hard
      error and was implemented later in step PII-M1 (see v0.5).

### v0.5 — ecosystem

- [ ] Connection daemon: a background pool of live DB connections (unix socket
      0600, 15-minute idle kill, autospawn/autoexit, the gpg-agent pattern).
      The trigger was to be latency measurements after the MVP (ControlPersist
      already removed the tunnel's cost; a daemon is needed if 50–300 ms of
      TLS/auth still hurts, or because of MongoDB's topology discovery). The
      measurements were taken and they shifted the priority: what dominated
      was not the cost of connecting (4–6 round trips) but the protocol
      chatter (10 on PostgreSQL, 12 on MySQL) and a second `ssh` spawn per
      query (10.5 ms locally, ~118 ms through a WAN bastion). Two cheap things
      were done instead of a daemon — collapsing the control statements and
      reusing the forward (see "Done outside the milestones"). The daemon
      remains undone; decide again based on TLS/auth latency and MongoDB's
      topology discovery
- [x] `nyet sample <alias> <table>` — data sampling. Sugar over the `query`
      code path: nyet writes the query itself (a random sample, 10 rows by
      default; `$sample` on MongoDB) and drives it through the pipeline
      UNCHANGED — validator, guardrail, both PII nets, the limit, the
      formatters, one audit record. If the guardrail refuses the random sample
      as expensive (`EXPENSIVE_QUERY`), there is one automatic retry with a
      cheap `LIMIT` query and a `SAMPLE_FALLBACK` warning ("these are the
      first rows, not random ones"); for any other refusal (PII, a database
      error, a timeout) there is no retry
- [x] PII protection (per-connection columns). Step PII-1: the
      `[connections.X.pii] columns = ["users.email", ...]` section, refusing
      the whole query (`NYET`/`PII_COLUMN`/`PII_UNPROVABLE`, exit 5) by name
      before execution and by result-column provenance afterwards; the
      database's error text is not handed to the agent on such a connection.
      Step PII-2: `mode = "deny" | "mask"` — the mask returns a plain
      projection of a protected column as `[REDACTED]` (any type, NULL
      included) with a `PII_MASKED` warning, everything else is refused as
      before, and a column let through under the mask but not redacted by
      provenance produces a refusal (`mask` cannot return what `deny` would
      have withheld); PII columns are marked in `nyet schema`, `nyet doctor`
      checks whether the role's privileges close them off, and `nyet
      agent-setup` explains all this to the agent. Regex autodetection by
      values or names, partial masking and tokenization are not planned
      (leakage piece by piece, plus an equality oracle). Step PII-M1 (July
      2026): MongoDB — the nets are inverted, because there is no provenance
      from the server while the result is self-describing: a rule is strictly
      `collection.field` and protects the field NAME at any depth; net A
      refuses on any mention (keys, `"$field"` references, the name positions
      of `distinct`/`$lookup`) and forbids operators that convert names into
      values (`$objectToArray` and others, `PII_UNPROVABLE`); net B
      recursively scans the result documents — deny refuses the whole
      response, mask redacts in place. The only exception under mask is a
      literal 0/1 projection. `doctor` says honestly that MongoDB has no
      field-level privileges (the recipe: a view plus a role on the view). The
      completeness of the conversion-operator list is a surface for W7
- [ ] Writes with opt-in: `allow_writes = true` in the config +
      `--unsafe-allow-writes`
- [ ] A schema cache

## Done outside the milestones

Work that was in no milestone: it came up along the way and turned out to be
cheaper and more necessary than what had been planned.

- [x] **ClickHouse (W9, August 2026).** It was in the wishlist; the open
      questions were closed by measurement, and all of them in favor of
      "build it". **Dialect:** `ClickHouseDialect` does exist in sqlparser
      0.62, and the main fear did not materialize — not one write parses as a
      `Query` (either its own `Statement` variant or PARSE_FAILED, both = a
      refusal). The price is on the other side: `GLOBAL IN`, `GLOBAL ANY LEFT
      JOIN`, `ASOF JOIN`, `APPLY(...)`, `EXISTS TABLE`, `view(SELECT …)` and
      `EXPLAIN indexes = 1` do not parse — those are false refusals, written
      out in the README as a "how to write it instead" table. `FINAL`,
      `PREWHERE`, `ARRAY JOIN`, `SAMPLE`, `LIMIT BY`, `WITH FILL` and
      `EXCEPT/REPLACE` do parse. **Layer 2 is `readonly=1` on every request**,
      and it is stronger than expected: it also cuts table functions (see W7).
      `readonly=2` is distinguished by doctor in a dedicated `readonly_setting`
      check and is not passed off as the first. **The guardrail is `EXPLAIN
      ESTIMATE`**, and it really is the best of them all: it reads part
      metadata without executing anything; it is empty for `system.*`, for
      table functions and for whatever the server answers from metadata —
      which is an honest "no estimate", not a zero. **Transport:** hyper
      directly, and `FORMAT JSONCompact` delivers names, types and rows in one
      response. Two traps were found by measurement and both cost fixes: an
      account with a `readonly = 1` profile (the very one layer 3 recommends)
      **cannot change a single setting**, and a parameter in the url is
      precisely a settings change, so the first version of the engine did not
      work on it at all; and a `readonly = 2` profile will not let the setting
      be lowered to 1. Both are cured by a stepwise rollback of the
      parameters, and `doctor` names the consequences. A third: with the JSON
      format ClickHouse puts the exception **inside** a valid document
      (`"data": [], "rows": 0, "exception": …`) — so a failure looks like an
      empty successful response; nyet checks the status, the header and the
      field itself. `[pii]` works, but net B is weaker here (the HTTP
      interface returns no column provenance — result column NAMES are
      compared instead), and that is written down everywhere it matters
- [x] **Redis/Valkey (W8, August 2026).** Also from the wishlist; all five
      open questions got explicit answers. **The classification is
      server-side** (`COMMAND INFO` by the exact name, subcommand
      `object|encoding` included): there is no 250-command list of our own,
      and the server is honest where a hand-written list would have been wrong
      (see W7). The rule on top of the flags: `write` is a hard boundary
      `allow_functions` cannot reach; everything else (our own denylist,
      `admin`/`blocking`/`@dangerous`, "the server did not call this a read")
      is overridable by name by the config's owner. **Scripting is denied
      entirely** and explicitly — the same decision as for `$where` in
      MongoDB, plus a measured class of DoS against the whole server. **The
      output contract** (a fork in the road, decided by the owner): the shape
      of the answer follows the shape of the RESP3 response — Map →
      `field`/`value` columns, Array/Set → a row per element, a scalar → a
      single row, anything nested → JSON in the cell. RESP3 is not a
      preference here: in RESP2 the responses of `HGETALL` and `LRANGE` are
      indistinguishable on the wire, and we would have needed exactly the
      command list we are avoiding. **`nyet schema` answers `na`** (the
      owner's decision) plus what costs nothing: per-database key counters
      from `INFO keyspace`; nyet does not SCAN production on its own.
      `explain` is `no_estimate` (nothing has a plan), but layer 1 still runs
      so that `explain` does not become a way around the classifier; `sample`
      refuses on the merits. There is no layer 2 at all, and `doctor` says so
      in a dedicated `read_only_session: na` check rather than keeping quiet.
      `[pii]` on Redis is a **hard config error**: a `table.column` rule
      cannot match anything here, and a policy that reads as protection while
      protecting nothing is worse than none; the ACL key pattern, which the
      server itself enforces, is offered instead

- [x] **`nyet import datagrip` (August 2026).** Was in no milestone and no
      wishlist: the first setup step is transcribing connections a JetBrains
      IDE already holds, and on 30-odd databases that is where people give up.
      The command reads every installed IDE and every project it remembers
      (`recentProjects.xml` is what makes `.idea/dataSources.xml` findable
      without walking the filesystem), and emits config sections on stdout;
      `--write` appends them, `--path` narrows the search to one project. Two
      things it refuses to carry, and both are the product rather than a
      limitation: **passwords** (DataGrip's own store holds them; the import
      emits a `{ keychain = ... }` reference and the `secret-set` line that
      fills it — a tool selling "the agent does not get the secret even after
      finding the config" must not copy secrets into one) and **`allowed_dirs`**
      (emitted empty = denied everywhere; only the human knows which project a
      database belongs to, and guessing `["~"]` would open every production
      database at import time). SSH tunnels do come across, but only the ones
      DataGrip has switched on. Two things that had to be right or the output
      is worse than useless: alias uniqueness spans the WHOLE import (two
      projects naming a database `prod-01` would emit a duplicate section, and
      duplicate keys mean a config that no longer parses at all — found by
      running it against 33 real connections), and `--write` never overwrites
      an alias the config already has. XML parsing is `roxmltree`
      (`forbid(unsafe_code)`, one dependency): a hand-rolled scan would have to
      get `&amp;` right in every jdbc url that carries query parameters
- [x] **TLS for direct connections** (rustls): `sslmode`/`ssl-mode` in the url
      work, MySQL 8 `caching_sha2_password` with the password over TLS, and an
      `INSECURE_TRANSPORT` warning on unprotected transport
- [x] **A managed database behind a bastion**: the TLS mode survives the url
      being rewritten for the tunnel (only `verify-full` → `verify-ca` is
      downgraded, never down to `require`), and the polite goodbye (ROLLBACK +
      close) is time-bounded and moved outside the query's deadline — a pooler
      that does not send `close_notify` no longer eats an answer that has
      already arrived
- [x] **Fewer round trips per query**: control statements are collapsed into
      groups (PostgreSQL 10 → 7, MySQL 12 → 8; explain 8 → 5 and 10 → 6,
      schema on MySQL 12 → 10). The name of the timeout on MySQL/MariaDB is
      learned once per connection from error 1193 instead of being probed on
      every SET. The guardrail's guarantees are unchanged: the server-side cap
      is armed before any agent statement, and the agent's SQL still travels
      separately over the prepared protocol
- [x] **Reusing the SSH forward between calls** (`reuse_forward = true` by
      default): one `ssh` spawn per query instead of two, and the forward
      outlives the process and is adopted by the next call after an ownership
      check (the registry lives in `XDG_RUNTIME_DIR` and doubles as the lock;
      `ssh -O check` must return the same master pid). Measured on the stand:
      66.4 ms without reuse, 55.1 ms with it. The price is written down
      honestly in the README: the loopback listener to the database lives
      between calls for as long as the master does
- [x] **Denying PostgreSQL advisory locks** (all 11 names of the family, the
      list taken from a live catalog): a session advisory lock survives
      ROLLBACK, and a blocking one hangs until statement_timeout — a
      write-like effect from a read-only tool. Reading lock state (`pg_locks`,
      `is_free_lock`) stays allowed
- [x] **A `justfile`**: `test-fast` (unit plus cli without Docker, seconds),
      `test` (everything, with containers), `check` (fmt + clippy + tests +
      deny + audit), `build`/`install`. `DOCKER_HOST` is resolved
      automatically, and a dead daemon produces a clear line instead of a
      testcontainers stack trace
- [x] **Credentials out of the config** (`password`/`url` = a literal OR a
      reference to a source: `{ keychain = "item" }` / `{ env = "VAR" }` /
      `{ command = "..." }`; `password_env` was removed). The task was never
      "keep the password out of the file" but "the agent does not get the
      password even after finding the file" — and it runs under the same uid,
      so only a source that checks WHO is asking draws a boundary. On macOS
      that is the Keychain: an item created by nyet itself carries an ACL with
      nyet's signature. Two rules follow, both easy to lose: no shelling out
      to `/usr/bin/security` (that would make `security` the trusted
      application, and the agent can run it itself), and the item is created
      by nyet, not by Keychain Access. Reads happen with the UI disabled, so
      an agent's request gets an error code rather than a dialog on the
      human's screen. Measured with a prototype: our own binary reads
      silently, `security` runs into a keychain password prompt, a rebuilt
      nyet gets `errSecAuthFailed` (-25293) with no dialog, and overwriting
      the item prompts for the password again. Hence `nyet secret-set <item>`:
      the value is read from stdin (not from argv, which is visible in `ps`),
      and the command must be repeated after every install, because the ACL is
      bound to the cdhash. `env` and `command` remain as unprotected sources,
      and `doctor` names the class with a neutral statement of fact. What is
      NOT closed, and is written down in SECURITY.md: the config belongs to
      the same user, so an agent can rewrite `url` (or add an `[ssh] remote`)
      to point at its own database and make nyet hand it the real password —
      the threat model remains "a cooperative but mistaken agent", not
      phishing

## Wishlist (no milestone)

Ideas we want, but whose priority and design are not settled. They enter a
milestone once the decision is clear and demand shows up.

### W1 — A wire protocol for ordinary clients (TablePlus, DataGrip through nyet)

`nyet serve <alias>` listens on localhost as a PostgreSQL server (the `pgwire`
crate), the GUI client connects to it rather than to the database, and every
query goes through the same pipeline — validator, read-only, guardrail, PII,
audit. The value: the same guarantees for a human behind a GUI as for an
agent, plus a single SSH tunnel shared by everyone.

Open questions:
- The scope is larger than it looks: the extended query protocol
  (parse/bind/execute), prepared statements, COPY, cancel requests, client
  authentication to nyet itself, types in `RowDescription`.
- GUI clients fire dozens of introspection queries and housekeeping `SET`s on
  connect — a fail-closed validator will reject them. A separate mode that
  trusts the client's own introspection is needed, otherwise TablePlus simply
  will not open.
- MySQL/Mongo/Redis each have their own protocol; realistically one starts
  with PostgreSQL and may well stay there.
- It conflicts with the "CLI-first" principle: this is yet another front (like
  MCP, which is already out of scope). Saying no and leaving GUIs a direct
  connection under a read-only role may turn out cheaper.

### W3 — Resolving the SSH host through a custom script

The address of a live node is not always static: clusters, autoscaling, a
changing leader. What we want is `[connections.X.ssh] host_cmd = "..."` — nyet
runs the command, takes the host (or `host:port`) from stdout and substitutes
it into ssh. Once per connection, and the result lives as long as the
ControlPersist tunnel.

Open questions:
- The same discipline as W2: `${VAR}` forbidden, a timeout, a failing command
  means the connection is refused (fail closed), and the script's stderr is
  not handed to the agent verbatim.
- The interaction with `reuse_forward`: an adopted forward may point at a node
  that is no longer the leader. The reuse key has to account for the
  `host_cmd` result, otherwise we get a silent connection to the wrong place.
- Cost: a script along the lines of "go ask kubectl" means seconds on every
  cold connection; we have to decide whether to cache the result and where.
- The cheap alternative that may cover 80%: `Match exec` in `~/.ssh/config` —
  nyet already inherits the user's ssh config, so there is nothing to build.
  Test it on a real case before erecting `host_cmd`.

### W4 — A test matrix over real docker images

The foundation is in place: testcontainers brings up `postgres:16-alpine`,
`mysql:8.4`, `mariadb:11.4`, `mongo:8`, `clickhouse-server:24.8-alpine`,
`redis:7.4-alpine` and the SSH stand (all digest-pinned), the tests are not
`#[ignore]`, and CI runs them. What we want is breadth and depth — one version
per engine is not enough: timeout, type and `EXPLAIN` behavior drifts between
majors, and that is exactly where it catches us.

What we want:
- A version matrix: PostgreSQL 13…17, MySQL 8.0/8.4, MariaDB 10.11/11.4,
  MongoDB 6/7/8, ClickHouse 23.8/24.3/24.8/25.x, Redis 6/7 and Valkey — one
  container per version, and stands for all six engines already exist.
- The image version as a parameter (env or feature), not a constant in the
  test; one default locally, the full matrix in CI (nightly, not on every PR:
  time and GitHub Actions limits).
- A long-lived stand for local development: containers reused between runs
  instead of being brought up per test — that is currently the main cost of
  `cargo test`.
- What the matrix must cover specifically: server-side timeouts and their
  SQLSTATEs, type decoding, the shape of `EXPLAIN` for the guardrail, and
  column provenance for PII.

Open questions:
- Cost: a full matrix means dozens of containers, and CI time and flakiness
  grow nonlinearly. Depth may matter more than breadth: not "every major" but
  oldest + newest supported.
- Reused containers mean dirty state between tests; a discipline of unique
  schemas or databases per test is required, otherwise we get flapping
  failures.
- `just test` must keep "just working" without Docker instructions held in
  one's head: one recipe for the fast run (no containers) and one for the full
  one.
  **Done:** the `justfile` — `test-fast` (no Docker) and `test` (with
  containers), and `DOCKER_HOST` resolves itself; see "Done outside the
  milestones".

### W5 — Linters and secure development practices

The base layer is already standing and the job is to not lose it rather than
reinvent it: `#![forbid(unsafe_code)]`, `cargo fmt --check`, `cargo clippy
--all-targets -D warnings`, `cargo deny` (a closed license allowlist, `yanked
= "deny"`), `cargo audit`, actions pinned to full SHAs, `permissions: contents:
read`.

What we are doing (decisions taken):
- **A validator panic is a bug, not a refusal.** Right now a panic in parsing
  comes out as a crash: fail-closed is formally satisfied, but the exit code
  is the wrong one and there is no audit record. The validator call gets
  wrapped in `catch_unwind` and a panic is mapped onto the regular refusal —
  the same exit code, the same line in `audit.jsonl`. Otherwise every fuzzer
  find is a separate class of incident instead of an ordinary "no".
- **Fuzzing at two levels, and the main one is not `cargo-fuzz`.** A SQL
  generator built on `proptest` from a grammar with known write nodes and the
  invariant "a write node exists ⇒ the validator refused" — it checks exactly
  the declared guarantee and lives in an ordinary `cargo test`. The second
  level is `cargo-fuzz` for panic freedom over raw bytes: a separate
  `fuzz.yml` on a schedule (nightly, ~15 minutes per target), a crash files an
  issue with a repro, and the repro cases are committed into the corpus and
  become deterministic regressions. OSS-Fuzz comes after the public release:
  before that there is simply nothing to bring there.
- **A differential test on the containers from W4.** The oracle is the
  server's read-only: everything the validator let through is executed under
  it on PostgreSQL and MySQL (testcontainers) and on SQLite in-process; what
  the server rejects as a write while the validator allowed it is a hole. Plus
  a single-statement check through `PREPARE`: the server complains about a
  second statement where the validator saw one. The input is
  `tests/corpus/*` and the same proptest generator. A snapshot diff of the
  database state before and after is deferred to W7 and done pointwise on
  confirmed vectors: across the whole corpus it is expensive and almost always
  empty.
- **MSRV — the actual one, not the desired one.** `cargo msrv find`, the
  result in `rust-version` in `Cargo.toml`, and a `cargo check` job on that
  toolchain. We bump it freely; the promise is exactly one: it is stated and
  it is verified.
- **`SECURITY.md` — a reporting channel and an honest list of holes.** The
  channel is GitHub Private Vulnerability Reporting (not email: a mailbox has
  to be created and guarded), and only the latest release is supported. The
  important part of the file is the EXPLICIT list of what nyet does not
  guarantee: directory scoping is a UX barrier, not a sandbox; prompt
  injection cannot be cured at our layer; an oracle on a protected column
  through `WHERE` yields a bit of information. Honesty instead of obscurity: a
  boundary left unwritten gets found anyway, just not by us.
- **Branch protection without ritual review.** Required status checks, no
  force-push, linear history. Required review: no — there is a single
  maintainer, and a self-approval for the checkbox is worse than an honestly
  absent review. OpenSSF Scorecard is enabled as-is and we do not fight for
  the score — it is an indicator, not a goal.
- **Small linters at the price of one line of CI.** `typos` (with
  `tests/corpus/` excluded — it holds data — and the Cyrillic docs),
  `cargo-shear` instead of `cargo-udeps` (stable, no build), and `zizmor` over
  the workflows — SHA pins alone do not make a workflow safe.
- **Provenance — the one built into dist, not our own.**
  `github-attestations` in `dist-workspace.toml` plus `id-token` and
  `attestations` permissions in `release.yml`; the exact option name for dist
  0.28.7 must be **verified** against the docs, memory is not an argument
  here.
- **CodeQL — by fact, not by faith.** ✅ Rust in CodeQL has been GA since
  2025-10-14 (CodeQL CLI 2.23.3+, GitHub's changelog), verified 2026-07-27.
  `.github/workflows/codeql.yml` is in place: `push` to main + `pull_request`
  + a weekly `schedule`, `languages: rust` / `build-mode: none`,
  `github/codeql-action` init and analyze pinned to a SHA (v4.37.3), and
  `security-events: write` only in that job.
- **`cargo-mutants` on the validator — a one-off experiment outside CI.** It
  will show which mutations of the boundary logic the tests fail to notice;
  we decide about a schedule based on the result.
- **Dependabot** on `github-actions` and `cargo`, weekly: SHA pins without
  automated updates are not security, they are stale versions.

Deliberately rejected: `cargo-semver-checks` (a binary crate, no public API),
Miri (`unsafe` is forbidden by `forbid`, there is nothing to check), and a
conventional-commits lint.

### W6 — Translating the project into English — **done (August 2026)**

The goal is open source, so the whole public surface has to be in English. As
of July 2026 `README.md` was already fully English, and so were nearly all the
code comments; about 1100 lines of Cyrillic remained, concentrated in
`docs/dev/DESIGN.md`, `docs/dev/PLAN.md`, `docs/dev/PRINCIPLES.md`, this `ROADMAP.md`,
leftover comments in `src/*.rs` and `tests/*.rs`, and a couple of lines in
`ci.yml` and `deny.toml`.

All of it is translated now, and the open questions were closed as follows:
- `docs/EXECUTION_PROMPT.md`, `EXECUTION_PROMPT_V2.md` and
  `docs/superpowers/specs/` were artifacts of the development process rather
  than documentation — **deleted** rather than translated; the history stays
  in git.
- The Cyrillic in `tests/corpus/sqlite_unicode.yaml`,
  `tests/corpus/mongo/allow.yaml` and the postgres homoglyph case is **test
  data** (the point of those tests) and was left untouched, as were the fuzz
  seeds.
- The internal decision anchors, which were Cyrillic, were **renamed all at
  once** (`D8`, `§3 step 6`) across code, docs, corpora and workflows, so no
  reference dangles. `UX-N` and `PII-N` were already Latin and are unchanged.
- The docs were translated rather than rewritten: they are a record of
  reasoning, and rewriting them from scratch would have quietly dropped the
  parts that record why a decision went the way it did.

### W7 — An adversarial audit: how to break read-only

This is its own body of work, not a sub-item of W5: put agents to work
breaking the "read only" guarantee and turn what they find into a test corpus
(`tests/corpus/*_deny.yaml` is already the right format for it).

The attack surfaces to start from:
- **Dialect divergence.** sqlparser parses text differently from the server:
  nested comments, dollar quoting, `E''` escapes, unicode homoglyphs and
  identifier normalization, a `;` inside a literal. Everything the validator
  considers a `SELECT` and the server does not, quite.
- **Side effects inside a read.** A `SELECT` calling a function that writes:
  `setval()`, `lo_export`, `pg_read_file`, `dblink`, `COPY ... PROGRAM`, a
  call to a user's volatile function. The validator layer knows about
  functions (`allow_functions`/`deny_functions`), but the completeness of that
  list is not proven.
- **Bypassing session read-only**: a `SET`/`RESET` inside a wrapper the
  validator did not recognize as transaction control; functions that open
  their own transaction.
- **Multi-statement tricks**: anything that makes the driver send two
  statements where the validator saw one.
- **PII/guardrail**: column provenance through `UNION`, window functions,
  `RETURNING`, `CASE`, type casts; an oracle on a protected column through
  `WHERE` (a comparison does not return the value but does return a bit of
  information) — a known and deliberately accepted hole, but the boundary has
  to be written down explicitly.
- **Audit and tunnel**: silencing `audit.jsonl` (the path, permissions, a
  symlink) or latching onto someone else's `-L` forward under `reuse_forward`.

The output of this work is not a report but green tests for every confirmed
vector, plus an honest list of what cannot be protected, in `SECURITY.md`
(W5).

**First pass done (August 2026): PostgreSQL, side effects inside a read.**
Measured on a live `postgres:16-alpine`, by the same criterion that earned
`nextval`/`setval` their place: the function runs inside `BEGIN READ ONLY`,
which means layer 2 does not catch it. Found and closed by the denylist (+24
cases in `postgres_deny.yaml`): XID assignment (`txid_current`,
`pg_current_xact_id` — the only family that also gets through layer 3: three
calls moved the cluster's `xmax` by three, three ordinary SELECTs moved it by
nothing), WAL and backup (`pg_create_restore_point`, `pg_switch_wal`,
`pg_rotate_logfile`, `pg_backup_start`), replication slots and origins (a slot
holds WAL and can fill the disk; `get_changes` advances the slot, `peek_changes`
does not and stayed allowed), `pg_stat_reset*` (by prefix) and
`pg_stat_statements_reset`, index maintenance (`brin_summarize_new_values`,
`gin_clean_pending_list` — they write into the index straight through
read-only), `pg_import_system_collations`, `pg_notify` and `set_config` (which
is a `SET` wrapped in a function, while `SET` itself has long been refused as
TXN_CONTROL).

Checked and NOT confirmed: the denylist mechanism cannot be evaded through
qualification, case or quoting (`pg_catalog."PG_SLEEP"` is caught);
`set_config('transaction_read_only','off')` is forbidden by the server itself;
and a `statement_timeout` lifted through `set_config` does not save a query
already running — the timer is armed. The last one becomes a real vector once
the connection daemon exists (v0.5): the session will outlive the call.

**Second pass (August 2026): MySQL/MariaDB and SQLite.** Measured on
`mysql:8.4`: `asynchronous_connection_failover_add_source(...)` executes inside
`START TRANSACTION READ ONLY` and leaves a row in
`mysql.replication_asynchronous_connection_failover` — a durable write into a
system table from a "read"; only privileges stop it
(SUPER/REPLICATION_SLAVE_ADMIN). Closed together with the failover family, and
by class (the plugin is not loaded in a stock server, so it cannot be measured
— marked honestly in the code) — `group_replication_*` (primary switchover!),
`keyring_*` (it stores and RETURNS keys), `version_tokens_*`,
`flush_rewrite_rules`, `audit_api_message_emit_udf`, `service_*_locks` and
`masking_dictionary_*`.

**A SQLite finding the denylist cannot cure:** the engine is embedded in the
process, and there is no guardrail on SQLite (the server publishes no
estimates), so a query eats `nyet`'s own memory. Measured: `randomblob(1e9)` →
994 MB, and a recursive CTE doubling a string → **4.35 GB in 4 seconds**, with
no "dangerous" functions at all. Denying `randomblob`/`zeroblob` is pointless —
the CTE form is both simpler and more powerful. SQLite's own limits do not help
either: `hard_heap_limit` is not compiled into this build (it reads as 0), and
`soft_heap_limit` bounds the page cache rather than rows (at 256 MB the same
query produced 4.13 GB). Written into SECURITY.md as an accepted limitation
with an external recipe (ulimit/cgroup/container).

Checked and NOT confirmed: MariaDB rejects `NEXTVAL`/`SETVAL` inside READ ONLY
by itself ("Cannot execute statement in a READ ONLY transaction") — unlike
PostgreSQL, which is exactly why `nextval` is on the denylist there; optimizer
hints (`/*+ MAX_EXECUTION_TIME(...) */`, an attempt to raise the server-side
time limit) and executable comments `/*! */` are rejected as
EXECUTABLE_COMMENT; `INTO OUTFILE`/`DUMPFILE`, `DO`, `HANDLER` and `LOCK IN
SHARE MODE` do not parse → fail closed; and in SQLite `sqlite_dbpage`,
`sqlite_dbstat`, `sqlite_stmt` and `fsdir` are not compiled into the sqlx build
and are unreachable (nothing to deny).

**Third pass (August 2026): the parser against the server.** One real
divergence and one undeclared barrier were found. The divergence: under
`sql_mode=NO_BACKSLASH_ESCAPES` MySQL does not treat `\'` as an escape, so
`SELECT '\';SELECT 2;--'` is TWO statements to the server and one literal to
the validator (measured on both: the validator says `allow`, the server
executed `SELECT '\'` and `SELECT 2`). The barrier: it does not reach the
server anyway — queries travel as a prepared statement, and that does not
accept a second statement; measured through `nyet` itself — the server
rejected the whole string with a syntax error. Which means a multi-statement
trick has to beat both the parser and the wire protocol. It is written into
SECURITY.md exactly that way: it is a property of the current way of sending
queries, not a promise — switching to the simple query protocol would lose it
silently.

Checked and matching the server: nested comments (PostgreSQL nests them, MySQL
does not, and the validator is dialect-specific: it refuses on MySQL where it
allows on PostgreSQL), dollar quoting, `E''` escapes, a `;` inside a literal,
and unicode (a homoglyph in a keyword does not parse, zero-width characters
are cleaned out by normalization, and it is the normalized text that gets
executed). All of it is fixed in the corpus as a specification.

**Fourth pass (August 2026): PII, the audit log, the tunnel.**

The PII nets hold. On a live database with `columns = ["users.email"]` every
attempt to carry the value out past the name was rejected: an alias, a
subquery with renaming, `CASE`, `::text`, concatenation, `max()`/`string_agg()`,
`row_to_json(u)`/`to_jsonb(u)` (the whole row as one expression), a scalar
subquery, a window function, `UNION ALL` with a shifted position, and
`SELECT u FROM users u` (whole-row). The statistics catalogs
(`pg_stats.most_common_vals`, `pg_statistic`), where column values sit as
DATA, were already covered (`value_sampling_catalogs`). Filtering and sorting
by a protected column are refused — the oracle is closed for a direct mention.

A declared limitation was confirmed: **a view over a protected table returns
the PII** (`SELECT email FROM people`, where `people` is a view over `users`),
because the rule is bound to the relation's name while the server's provenance
points at the view. That is written into SECURITY.md, and now `doctor` does
not keep quiet about such views either: the `pii_views` check (PostgreSQL)
walks `pg_depend` and names every view or materialized view that reads a
protected column AND is SELECT-able by this role. Not
`information_schema.view_column_usage`: that one shows only tables owned by
the current role, so the recommended read-only role (which owns nothing) would
always get an empty answer — a false "all clear", which is worse than no check
at all.

The audit log: fail-closed works (the log is not writable → `AUDIT_FAILED`,
and the result is NOT handed to the agent), and the file is created 0600. **A
hole was found and closed:** if the log path led to `/dev/null` (directly or
through a symlink planted by the agent), `nyet` wrote into nowhere and calmly
returned the result — the trail silently switched off, the exact opposite of
the UX-8 promise. The type is now checked on the OPEN handle (swapping the
path after the check does not help): not a regular file → refusal, result
withheld. A symlink to a real file keeps working: the rule is about what the
path HOLDS, not about symlinks being suspicious.

The tunnel: no measurement was made (an ssh stand is needed), and the
invariant was worked through in code. It already names its residual risk
honestly and in detail — after `ssh -O cancel -L` the freed ephemeral port can
be taken by any local process, and the next run would send its handshake there;
which is exactly why `doctor` teaches `-O exit` rather than `-O cancel`. The
obvious should be added to that: the registry file belongs to the same user as
the agent, so it is not proof of ownership against DELIBERATE forgery — the
same class as the agent-controlled audit path.

**Fifth pass (August 2026): MongoDB.** Same method, on a live `mongo:7` with a
`users.email` policy. The nets hold: `$lookup`, `$unionWith` and `$graphLookup`
out of a protected collection are rejected (the rule is keyed on the name, but
touching the collection is caught), `$out` inside `$facet` and inside
`$lookup.pipeline` is WRITE_OPERATION, `$$ROOT` and `$getField` are
PII_UNPROVABLE, and the metadata stages (`$collStats`, `$indexStats`,
`$planCacheStats`, `$listSessions`, `$documents`) are outside the allowlist.
The single blind spot is the same as on SQL: **a view over a protected
collection**.

So `pii_views` was implemented for MongoDB too: `listCollections` gives
`viewOn` and the pipeline, and then every candidate is probed with `$type`
(which answers `"missing"` rather than a value — the diagnostic does not pull
protected data into nyet). That matters not for precision's own sake:
`pii_columns` ADVISES creating a view that `$unset`s the protected fields, and
without this probe doctor would have complained about its own recommendation.
Privileges on MongoDB objects cannot be checked cheaply, so the wording of the
mongo version promises exactly what was verified: "these views return the
field", with no claims about who may read them.

**Sixth pass (August 2026): fuzzing and differential tests.** The differential
tests (postgres/mysql/sqlite against live servers) are green. Fuzzing
`sql_validate` (707k runs, ~4 min) produced not a crash but a **slow unit —
and behind it was a real DoS against `nyet` itself**.

The pathology is in `sqlparser` 0.62: the cost of REFUSING an
over-deep expression is exponential not in the query but in the recursion
limit itself. Measured on `SELECT cast(cast(…)) as text)`: limit 18 → 0.15 s,
20 → 0.56 s, 22 → 2.2 s, 24 → 8.7 s, and the default of 50 NEVER finished
(checked up to 10 minutes). The threshold in query depth is exactly 47/48:
below it the parser takes the fast path, above it backtracking begins. Which
means ~700 bytes of SQL hung the validator forever — BEFORE any database was
touched, so neither `statement_timeout` nor `query_timeout` applied at all.

Closed with an explicit `with_recursion_limit(20)`: a malicious query is now
refused in 0.58 s. Ordinary SQL was verified to be unaffected — CTE chains,
nested CASEs, 8 levels of nested subqueries, 15 parentheses and 22 summands
all pass (the ceiling is ≈ 9 levels of subqueries). The text was fixed
separately: exceeding the nesting limit is not a syntax error, and the agent
is no longer advised to "fix the SQL syntax" but told plainly that the query
is nested too deeply and should be flattened with WITH. Two regression tests
in the unit suite (the refusal fits in seconds; ordinary nesting stays
allowed) plus a case in the corpus.

Along the way: the `mongo_pii` target had no seed directory, so `just fuzz
mongo_pii` failed with "No such file or directory" — 15 seeds were added
(mongosh queries with protected fields in every position, plus JSON documents
for net B), and a run of 1.6M iterations is clean. A repeat run of
`sql_validate` after the nesting fix is clean too, and the slow unit no longer
reproduces.

**Seventh pass (August 2026): ClickHouse and Redis, together with the engines
themselves** (W9 and W8 — see "Done outside the milestones"). Same method: a
candidate is executed on a live server through layer 2, and only what gets
through lands on the denylist.

ClickHouse (`clickhouse-server:24.8-alpine`, through `readonly=1`): through
went `cluster('default', …)` and `clusterAllReplicas(…)` — they **returned
rows**, meaning they reach other cluster nodes with the server's own service
credentials; `sqlite()` and scalar `file()` made it to their own path check
(`user_files`) rather than to readonly; the `dictGet*` family made it to
resolving the dictionary (and a dictionary can be
`SOURCE(HTTP(...))`/`SOURCE(EXECUTABLE(...))`); `sleep()`/`sleepEachRow()`
executed; `catboostEvaluate` made it to its argument check; and
`mergeTreeIndex()` returned primary-index granules — column values without the
column ever being named.

The negative results on ClickHouse, and there are more of them than positive
ones: `readonly=1` turned out to be stronger than W9 claimed — it rejects not
only writes and settings changes but **almost every table function** (`url`,
`file`, `s3`, `remote`, `executable`, `mysql`, `postgresql`, `mongodb`,
`hdfs`, `azureBlobStorage`, `merge`, `input`, `format`, `loop`, `dictionary`,
`zeros` — all `Code: 164 READONLY`), because to ClickHouse a table function is
not a read. Multi-statement is rejected by the server itself ("Multi-statements
are not allowed"). The sqlparser dialect let through **not one** write as a
`Query`: `INSERT`/`OPTIMIZE`/`TRUNCATE`/`DROP`/`RENAME`/`CREATE`/`GRANT`/
`SET`/`USE` are separate `Statement` variants, while `ALTER … UPDATE/DELETE`,
`SYSTEM`, `KILL`, `DETACH`, `ATTACH`, `BACKUP`, `RESTORE` and `EXCHANGE` do
not parse at all.

Redis (`redis:7.4-alpine`): the server provides the classification, and it is
honest where a list of our own would have been wrong — `GETEX` is marked
`write` by Redis itself ("RW and UPDATE because it changes the TTL"), and so
are `GETDEL`/`SPOP`/`SORT`/`BITFIELD`/`GEORADIUS`, while their `_RO` twins are
`readonly`. The only thing of our own on the denylist is the scripting family:
the server calls `EVAL_RO` and `FCALL_RO` reads, but Lua is opaque to layer 1
(the same decision as for `$where` in MongoDB), and a script executes on the
server's single thread without preemption — a loop puts the whole server into
BUSY until `SCRIPT KILL`.

A negative result on Redis that saves time: **the `SCAN` cursor is not
server-side** — taken on one connection, it continued correctly on another, so
the worry from W8 did not materialize and there is nothing to clean up.

Fuzzing was run over both new layer-1 implementations: the new `redis_check`
target (direct — `src/redis.rs` has no `catch_unwind`, and it hunts the
tokenizer: quote state, a trailing `\` escape at end of input, container
command splitting) did 3.07M runs in 241 s, clean; `sql_validate` with the
fourth dialect and the ClickHouse seeds/dictionary added is clean too, with no
artifacts.

What remains in W7: fuzzing as a continuous process (the `fuzz.yml` CI
workflow already exists and now has four targets, and it is worth running it
for longer than 4 minutes).

### W10 — Query input: `--file`/stdin and parameters instead of a string in argv

Today `nyet query <alias> <query>` takes the query only as a positional
argument; there is no `--file` and no stdin. A multi-line query with quotes
inside it (`WHERE slug IN ('a','b')`) has to be escaped for zsh — at 20 lines
that is annoying and produces typos that were never in the SQL. What we want
is `nyet query prod --file q.sql` and `nyet query prod -` (read stdin), plus
parameterization — `--param slug=a --param slug=b` or `--params-json` — so
that values are not inlined into the text by hand. For a read-only tool this
is not about safety but about manual string escaping being an extra source of
one's own mistakes.

Open questions:
- Placeholder style diverges across engines: `$1` in PostgreSQL, `?` in
  MySQL/SQLite, and Mongo has its own story. Either one neutral syntax
  (`:name`) translated per engine, or an honest "same as in your database" —
  the second is cheaper but breaks a single help text.
- Parameter types: everything arrives from the CLI as a string, and `WHERE id
  = :id` against a numeric column in PostgreSQL will not bind a string. Either
  an explicit type (`--param id:int=7`) or a JSON input, where the type is
  already present.
- The interaction with the validator and PII: parameters bypass the AST, and
  that is correct — but verify that column provenance and name-based `deny`
  rules do not depend on the text of literals.
- Is stdin already taken? Check whether reading stdin conflicts with ssh's
  interactive input (password or passphrase) — `ssh` is spawned from the same
  process.
- The argv limit (`ARG_MAX`) is not a real problem at 20 lines and is not
  worth building for; the motivation is purely UX.

### W11 — A cheap list of table names

`nyet schema <alias>` in full is tens of kilobytes (~27 KB on a live
database), while a targeted `nyet schema <alias> <table>` requires knowing the
table name already. Because of that it is cheaper to go to
`information_schema` by hand than to pull the whole dump for one name. What we
want is a way to get just the list of objects — say `nyet schema <alias>
--names` (or `nyet tables <alias>`): the names of tables and views, without
columns, indexes or FKs.

Open questions:
- A flag on `schema` or a separate subcommand: `--names` is cheaper and grows
  no surface, but an agent will find `nyet tables` in `--help` faster (UX-3).
- Does it overlap with `nyet list`: that one lists aliases and this one lists
  objects — but the command names sit next to each other and will be confused.
- `schema` already has a detail threshold (details up to 50 objects) — perhaps
  the right answer is not a new flag but a more aggressive degradation to
  names on large databases. Then the price is zero, but the behavior is
  implicit.
- For MongoDB "names" means collections, and they are cheap; for Redis there
  is no object list at all — `nyet schema` already answers `na` there plus key
  counters, and that is precisely the case where "names only" is impossible in
  principle.

### W12 — `agent-setup`: connection descriptions, skill neighborhood, size

Feedback from an agent that got the skill to work with (July 2026). Three
things, none of them done yet.

**A description per connection.** The "Your connections" section renders a flat
`alias  engine` (`src/skill.rs:266`), and `Conn` knows only those two fields.
With 32 aliases the name implies nothing: `prod-1000-bazinga` vs `prod-1000`
vs `startrek` — the agent guesses the shard or, worse, goes to production
where a local stand would have done. The generator cannot know this — only the
config's owner does. What we want is a `description = "..."` per connection,
which `agent-setup` prints verbatim next to the alias (and probably `nyet
list` too).

- The price is small: a field in `Connection` plus a line in the renderer. But
  `Connection` carries `deny_unknown_fields`, so this is a config schema
  change rather than an additive detail — an old nyet will fail on a new
  config.
- `${VAR}` inside it — forbid it? It is not policy but text, yet the text goes
  straight into the agent's context, and swapping it through the environment
  is a cheap instruction injection. Probably forbid, as in `allowed_dirs` and
  `pii`.
- The length needs a bound: a 200-line description is just another skill,
  minus the review.

**Neighborhood with other people's skills.** A user's skill (in the feedback,
`tracker-mongo`) says "there is no database access, ask a human", while the
nyet-generated skill says "do it yourself". Whichever gets pulled in decides
how the agent behaves. Fixing that by editing someone else's skill is the
user's job, but `agent-setup` can help: say in the command's output (not in
SKILL.md itself) that domain skills about the same database should be switched
to nyet as the transport, keeping their content — the schema and the domain
distinctions nyet knows nothing about. Open question: does this turn into
advice about other people's files that we do not control.

**Size and progressive loading.** ~11 KB is loaded in full on every trigger,
and the `description` in the frontmatter triggers on any read from a database.
The section about protected columns (~35 lines) is only needed if the config
actually has a `[connections.X.pii]`. Candidates: render the PII section
conditionally (the generator already has the data) and/or move the rarely
needed parts into a separate reference file the agent reads on demand. Not a
blocker — do it when the size starts to hurt; we still have no token
measurement (see v0.2).

### Deliberately out of scope

Dumps and backups (write territory, an enormous scope), an interactive REPL
(pgcli exists), cursor pagination (LIMIT plus a warning covers 95%).

**`nyet mcp` (an MCP mode).** Removed from the plan: we do not want to build
it. The "CLI-first" principle stands — if MCP ever appears, it will be a
wrapper built from the same binary on top of the finished pipeline — but only
on explicit user request, not proactively. Until such a request, the MCP space
is covered by competitors (MCP Toolbox, DBHub), and nyet's differentiation
lies elsewhere (plain CLI + layered read-only + agent UX).

## Known risks and open questions

- sqlparser-rs is syntax-only: the share of legitimate queries rejected by
  failing closed is unknown until it is run against a real corpus (a v0.1
  milestone).
- `default_transaction_read_only` is a session setting and can in theory be
  rolled back through SET; this is compensated by denying SET and
  multi-statement at the validator layer and by recommending a read-only role.
- Prompt injection through query results — complete protection does not exist;
  mitigations: read-only scoping, the audit log, a warning in the docs.
- There is no ready, maintained write-command classification for MongoDB or
  CQL — we maintain our own. Redis is covered through `COMMAND INFO` and
  verified on a live 7.4 (see W7): there is no command list of our own, only a
  rule on top of the server's flags.
- Credential storage: the MVP is a 0600 file plus env substitution; moving
  them into a secrets manager is wishlist item W2.
- The name `nyet` is an ordinary word: SEO is earned through content and the
  `nyetdb` brand; the cold-war flavor is a deliberate decision (punk branding,
  the author's self-irony).
