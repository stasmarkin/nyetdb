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

The server-engine tests spin real containers through testcontainers. They are
**not** `#[ignore]`d — CI runs them, and they *fail* (not skip) without a Docker
daemon, on purpose:

- PostgreSQL — `postgres:16-alpine` (`src/engine.rs` layer-2/decoding,
  `tests/postgres.rs` e2e via the binary).
- MySQL — `mysql:8.4` (`src/engine.rs` `mysql_layer2_types_and_timeout`: real
  `JSON` type, `max_execution_time`/SQLSTATE 3024, `BIGINT UNSIGNED`, `BIT`,
  full-range `TIME`; `mysql8_caching_sha2_password_over_tls`: a passworded
  `caching_sha2_password` user connecting over `ssl-mode=REQUIRED` — the TLS
  proof, since MySQL 8 auto-generates a self-signed cert and enables TLS at
  init).
- MariaDB — `mariadb:11.4`: `src/engine.rs` `mariadb_server_timeout_maps_to_timeout`
  proves the `max_statement_time`/SQLSTATE 1969 path directly (no outer tokio
  timeout — a `Timeout` can only come from the server), and `tests/mysql.rs` is
  the e2e via the binary on the `engine = "mariadb"` path with a
  `mysql_native_password` user, whose **password** works over the plaintext
  loopback without needing TLS (see the MySQL/TLS note below).

To run locally:

```sh
colima start                               # or Docker Desktop — any Docker daemon
docker pull postgres:16-alpine             # first run only; cached after
docker pull mysql:8.4
docker pull mariadb:11.4
docker pull linuxserver/openssh-server@sha256:9c5e178975fcc3917853f5e37cbf135ad7deb11de504ab0f460cc81a2e1eb539  # SSH tunnel stand (digest-pinned in tests/ssh.rs)
echo $DOCKER_HOST                           # testcontainers reads this (colima socket)
cargo test                                 # containers come up and are reaped per test
```

The SQLite and validator/config/resolver tests need no Docker.

### MySQL vs MariaDB, and the TLS backend (rustls)

The engine treats MySQL and MariaDB as one driver + one SQL dialect; the only
runtime difference is the **server-side query-timeout variable**, mutually
exclusive between the two (each server rejects the other's name with
ER_UNKNOWN_SYSTEM_VARIABLE, 1193; re-verified live on mysql:8.4 and mariadb:11.4
in July 2026): MySQL uses `max_execution_time` (ms), MariaDB `max_statement_time`
(seconds). Both timeout SQLSTATEs (3024 / 1969) map to `EngineError::Timeout` so
the exit code is deterministic (like Postgres 57014).

**The flavor is a hint-ordered SEARCH, learned once per connection
(`TimeoutVar`).** The engine used to send BOTH spellings on every call and
swallow the 1193 of whichever was wrong — three calls per guarded query × two
statements = **six round trips, half of them known-doomed**. Now the config
`engine` label only picks which name is tried FIRST; the other stays in the
search as the fallback, and the accepted one is remembered for the rest of the
connection. Consequences, in order of importance:

- a mislabelled server is **still capped** — the label cannot switch the server
  cap off, it can only cost one extra round trip, once per connection;
- a correctly labelled server never sees a 1193 at all;
- `TimeoutVar::Neither` (a proxy that knows neither name) is remembered too, so
  the discovery is not re-paid on every SET; there is no server cap then and the
  cli's own deadline is the backstop — exactly the behavior of the old
  swallow-both code.

**`Neither` warns nobody and refuses nothing — on purpose.** "Fail closed" is the
rule for SECURITY doubt, and a missing server cap is not that: the read-only
transaction, the validator and the read-only role are untouched by it, and the
query is still bounded by nyet's own deadline plus a dropped socket. SQLite ships
with no server-side timeout at all for the same reason. Refusing here would also
be a behavior change for a setup that works today (the old code swallowed both
SETs and ran on), and the agent cannot summon the condition on an arbitrary query
— which is the project's standing test for fail-open (see the guardrail section).
The branch itself is covered by `the_timeout_variable_is_searched_by_hint_and_learned_once`
(no candidates left, no statement produced); the "send the transaction on its own"
fallback next to it is unreachable today (every phase starts from a fresh
`Unknown`) and exists so that a future reuse of the flavor across statements
cannot silently drop layer 2.

Reading `@@version_comment` at connect was the obvious alternative and was
rejected: it costs a round trip of its own on EVERY connection to learn what the
first SET tells us for free, and it answers about the server's marketing name
rather than about the variable we are about to set.

Two flavors are tested on purpose to cover both timeout variables and both
`JSON` behaviors (MySQL has a real `JSON` type → structured; MariaDB stores
`JSON` as `LONGTEXT` → returned as a string).

**TLS is provided by rustls, not native-tls/OpenSSL.** The sqlx feature is
`tls-rustls-ring-webpki` (chosen over the alternatives per Д8):

- **rustls, not `tls-native-tls`** — native-tls means system OpenSSL (a C
  dependency, per-platform build/audit surface) or SChannel/Secure Transport;
  rustls is memory-safe Rust and self-contained, which suits a static,
  cross-compiled release binary. It also keeps the supply chain off the OpenSSL
  advisory stream.
- **`ring` provider, not `aws-lc-rs`** — `sqlx/tls-rustls` (= `tls-rustls-ring`
  = `tls-rustls-ring-webpki`) uses `ring`, which builds with just a C compiler;
  `aws-lc-rs` additionally wants CMake and bindgen (heavier, more fragile
  cross-compiles) for no benefit we need here.
- **`webpki` roots, not native roots** — the bundled Mozilla CA set
  (`webpki-roots`) gives identical `verify-full` behavior on every platform with
  no dependency on the OS trust store; a private CA is passed per-connection via
  the url (`sslrootcert=`/`ssl-ca=`), so we do not need `rustls-native-certs`.

This still does **not** enable sqlx's `mysql-rsa` feature: that pulls the `rsa`
crate flagged by RUSTSEC-2023-0071 (unpatched timing attack), which
`cargo-deny`/`cargo-audit` reject — the wrong dependency for a
credential-handling tool (Д8). It is unnecessary now: MySQL 8's default
`caching_sha2_password` sends the password over the TLS channel instead of a
client-side RSA exchange. The rustls stack adds five crates to the runtime tree
(`rustls`, `ring`, `rustls-webpki`, `webpki-roots`, `subtle`) and their licenses
to `deny.toml` — `ISC`/`BSD-3-Clause` globally (ubiquitous permissive code
licenses) and `CDLA-Permissive-2.0` scoped to `webpki-roots` (a data license for
the CA bundle, not general code) — no `rsa`, no `openssl` (verified with
`cargo tree -e normal`).

Consequence (now positive, documented in the README): **a password against a
default MySQL 8 server works over TLS** — connect with `ssl-mode=REQUIRED` (or
stricter). The `mysql:8.4` engine timeout/type test still connects as root with
an **empty** password (fast auth, needs neither TLS nor RSA); the dedicated
`mysql8_caching_sha2_password_over_tls` test proves the passworded TLS path.

### The SSH tunnel stand (`tests/ssh.rs`)

`ssh_tunnel_query_end_to_end` is the real proof that the tunnel path works. It
brings up two throwaway containers on a per-test user-defined docker network:

- `postgres:16-alpine`, reachable on the network by its (unique) container name;
- `linuxserver/openssh-server`, a bastion with 2222 published to the host,
  authorized by a **per-test ed25519 keypair** generated by shelling out to
  `ssh-keygen` (no new crate — the same tool nyet users already have; if a
  keypair ever needs generating without a system ssh, revisit).

The binary then runs `nyet query` with an `[ssh]` section pointing at the
bastion; nyet shells out to `ssh`, forwards to `<pg-container>:5432`, and reads
through the tunnel. The image is **pinned by digest** (not floating `latest`) so
a future release cannot silently change the init banner / config path / process
name the stand depends on. Things worth knowing:

- **OpenSSH ignores `$HOME`** for the client config path (it resolves `~` via
  `getpwuid`), so a temp `HOME` cannot inject a test `~/.ssh/config`. Instead the
  test puts a tiny `ssh` shim first on the PATH nyet runs with; the shim execs
  the real ssh with `-F <test config>` (identity file, `StrictHostKeyChecking
  no`, throwaway known-hosts). This is a test-only injection — production nyet
  inherits the user's real `~/.ssh/config`, which is the intended behavior.
- **`linuxserver/openssh-server` ships `AllowTcpForwarding no`** in its live
  `/config/sshd/sshd_config`, which forbids the very forward we need. The test
  flips it to `yes` and reloads sshd (`pkill -HUP sshd.pam` via `container.exec`,
  not `kill -HUP $(pgrep ...)` — a drifted process name then just no-ops instead
  of hard-failing). As reloading the config is not instant, the test **gates on a
  fresh throwaway `-L` forward actually reaching Postgres** (a Postgres
  `SSLRequest` gets a byte back) before the real `nyet` run, and additionally
  retries the `nyet` pass with backoff — so the config-reload window cannot flake
  CI. Gating on forwarding *before* nyet's first run also avoids nyet creating a
  persistent `ControlMaster` under the old (forwarding-denied) policy.
- With the deep temp `HOME`, nyet's `ControlPath` would exceed the unix-socket
  length limit, so the e2e runs in **standalone mode** (`control_path_too_long`).
  That is the cleaner mode to prove the no-leak fix: the forward *is* the child
  process, so the test runs several `nyet query` in a row and asserts
  `pgrep -f <pg>:5432 == 0` after each (the forward is gone once nyet exits). The
  master-mode teardown (`ssh -O cancel` leaves the master, removes the forward)
  is covered by the `cancel_args` unit test and was verified by hand against the
  bastion; `ControlPath` presence is unit-tested in `ssh_args`.

`ssh_tunnel_failure_is_exit_6` needs no Docker: it points `host` at a closed
local port and asserts the `CONNECTION_FAILED` (exit 6) envelope. The pure ssh
command-building, host/remote validation, and the url→localhost override are
covered by unit tests in `src/tunnel.rs` / `src/engine.rs` (no network).

## Module map (PRINCIPLES Д2)

```
cli (src/main.rs) — clap, orchestration, all IO, exit codes, tokio runtime
├─ config    (src/config.rs)    — pure: TOML text -> validated structures; env lookup injected
├─ resolver  (src/resolver.rs)  — pure: (cwd, allowed_dirs) -> allowed?; canonicalize injected
├─ validator (src/validator.rs) — pure: (SQL text, Policy) -> Allow{sql,warnings} |
│                                 Deny{reason,message,hint}; also owns the PII
│                                 policy (PiiRules + PiiMode) and the
│                                 post-execution provenance check
│                                 (Origin/check_origins -> refusal, or the
│                                 columns to mask);
│                                 depends ONLY on sqlparser + unicode-properties
│                                 (+std)
├─ guardrail (src/guardrail.rs) — pure: (config) -> Guardrail; (plan) ->
│                                 CostEstimate; (estimate) -> Check + refusal
│                                 texts. serde_json + output only — the plan
│                                 parsers are unit-tested on fixtures, no db
├─ engine    (src/engine.rs)    — IO adapters behind trait Engine; knows sqlx,
│                                 nothing about clap; fills in output's pure
│                                 schema/estimate models (leaf->leaf edges)
├─ tunnel    (src/tunnel.rs)    — SSH tunnels: pure ssh-command building +
│                                 host parsing; the shell-out to system `ssh`
│                                 is the only IO. std only (net/process), no
│                                 sqlx/config/clap
├─ output    (src/output.rs)    — pure: values -> envelope/table strings;
│                                 also owns the `schema` and `doctor` data
│                                 models (the contract shapes) + their rules
├─ skill     (src/skill.rs)     — pure: (instruction template + the user's
│                                 connections) -> the `agent-setup` SKILL.md
│                                 string; std only, no IO
└─ audit     (src/audit.rs)     — pure record builder ((event, ts) -> jsonl
                                  line, snapshot-tested) + the ONE IO piece
                                  (append: mkdir + create 0600 + advisory lock
                                  + write + flush). serde/serde_json + std only
```

Dependencies flow downward only: the pure modules do no IO and know nothing
about clap or each other; file reading, env access, cwd/realpath, the tokio
runtime and the query timeout live in the cli layer. The edges between "leaf"
modules are `engine -> output`, `engine -> guardrail`, `engine -> validator`
(only for the pure `Origin` type it fills in from the driver's column metadata),
`guardrail -> output`, `config -> guardrail` and `config -> validator` (the guardrail owns the judging and its own config
resolution — `config::guardrail` is the single entry point, called at parse time
to fail loud and again by the cli to get the value; output owns the serialized
shapes; the engines only run the EXPLAIN and hand the result over). The first
one: the `Schema`/`SchemaTable`/`SchemaColumn`
structs are the serialized contract, so they live in the pure module (with
`build_table`, the single owner of the pk/unique presentation rules) and the
engines fill them in. That direction is still downward — `output` depends on
serde alone, `engine` on all of sqlx. The runtime is built
lazily, only when an engine actually executes (Д9: `list`, config errors and
validator refusals never start it). `nyet doctor` reuses this same
`engine -> output` edge: the engine's `diagnose()` fills in `output`'s pure
`Diagnosis` facts, and the pure `output::doctor_checks` turns them into the
verdicts (see the doctor section below).

### SSH tunnels (`src/tunnel.rs`)

For a Postgres connection with an `[ssh]` section, the cli opens a local port
forward *after* the validator (a refused query still exits 5 without paying for
ssh) and *before* the engine connects. The split follows Д1/Д2:

- **Pure core** (unit-tested, no network): `parse_host` (`[user@]hostname[:port]`
  → destination + optional `-p` port, with strict validation), `ssh_args`
  (build the `ssh [-f] -N -L 127.0.0.1:<port>:<remote> ... <dest>` argv, including
  `ControlMaster=auto`/`ControlPersist`/`ExitOnForwardFailure=yes`/`BatchMode=yes`/
  `ConnectTimeout`/`ControlPath`; `-f` only in master mode), and `cancel_args`
  (the `ssh -O cancel -L ...` argv that removes one forward from the master).
- **Forward lifecycle — no accumulation (RESOURCE SAFETY).** `open` returns a
  `Tunnel` guard the cli holds for the query; `Drop` tears the forward down.
  Verified against a real bastion: a `-L` forward opened with `ControlMaster` is
  **owned by the persistent master** and outlives its client, so a plain
  `kill`/`-f`-orphan would leak listeners across a session (the original bug).
  Two modes:
  - **master mode** (a `ControlPath` fits): spawn with `-f` (attaches the forward
    to the reusable master, exits 0 when ready), and on drop run `ssh -O cancel
    -L ...` to remove *just this forward* — the master stays for warm reuse;
  - **standalone mode** (no `ControlPath`): spawn `ssh -N -L` (no `-f`) as a
    foreground child, poll TCP-connect on the local port for readiness (bounded
    by `ConnectTimeout`), and kill the child on drop.
- **Option-injection guard + typed-parse-once (SECURITY).** `host`/`remote`/
  `control_persist` come from the config, where `${VAR}` substitution makes them
  agent-influenced (agent-controlled environment per the threat model). `ssh` has
  no `--` to end options, so a `host` like `-oProxyCommand=...` would run
  arbitrary code. Each is parsed by ONE function — `parse_host` (→ canonical
  destination + `NonZeroU16` port; port 0 rejected), `parse_remote` (→ canonical
  trimmed `host:port`), `parse_control_persist` (real `ControlPersist` grammar:
  `yes`/`no` or an ssh TIME token like `2h30m`) — that both `config.rs` calls at
  parse time (fail-fast, exit 3, `SshInvalid`) and `open` calls to build the
  argv. Building argv only from the canonical parse output removes validate/exec
  drift (e.g. a trailing space or port 0 that a trim-then-validate would let
  through). `valid_label` rejects a leading `-` and anything outside
  `[A-Za-z0-9._-]`.
- **ssh env is sanitized (SECURITY).** nyet holds the DB password (from
  `password_env`) in its own environment; `ssh` must not inherit it (a
  ProxyCommand helper or a local `/proc/PID/environ` reader would see it).
  `ssh_command()` does `env_clear()` + an allowlist (`keep_env_key`: HOME, USER,
  LOGNAME, PATH, SSH_AUTH_SOCK, SSH_CONNECTION, TERM, LANG, LC_*), used for the
  forward spawn and the `-O cancel` teardown alike. Proven both by a unit test
  (`keep_env_key`) and end-to-end (the e2e shim dumps its env; the test asserts
  the password is absent).
- **Imperative shell**: `open` picks a free local port (bind `127.0.0.1:0`, read
  it, release), computes a `ControlPath` under `$XDG_RUNTIME_DIR`/`~/.ssh/nyet`
  (if it would exceed the socket-path limit, ssh_args emits `ControlPath=none` —
  explicit, so a `~/.ssh/config` `Host *` path can't sneak in — and the tunnel
  runs standalone/no-reuse), derives `ConnectTimeout` from the query timeout
  (capped 10s so a blackholed bastion fails fast), spawns the system `ssh`, and
  maps failures to a `TunnelError` the cli turns into `CONNECTION_FAILED`
  (exit 6). No `russh` — the system binary inherits `~/.ssh/config`, keys, agent
  and `ProxyJump` (Д8), and ControlPersist over the ControlPath reuses the master
  between runs (Д9). The `Option<Tunnel>` guard is kept in the cli `Query` arm so
  it drops after the query executes.
- **url → localhost**: rather than string-rewriting the url, `engine.rs`
  overrides `PgConnectOptions.host()/port()` and rewrites `ssl_mode` for the
  tunnel leg (`apply_host_override`) — while user/dbname/params and the password
  stay intact. The rewrite: everything below `require` (`disable`/`allow`/
  `prefer`, the last one being sqlx's default and therefore also "the url said
  nothing") becomes `Disable`, since the ssh hop already encrypts; `require`
  survives, because a managed server behind a pooler refuses plaintext outright
  (Yandex MDB's odyssey answers `SSL is required`, which a forced `Disable` made
  unreachable); `verify-ca` survives too — sqlx sets `accept_invalid_hostnames`
  for everything except `verify-full`, so chain authentication still works
  against `127.0.0.1`; only `verify-full` is downgraded, to `verify-ca`, as the
  cert names the real host. The **direct** leg
  (`host_override == None`) is left untouched, so the `sslmode`/`ssl-mode` from
  the url is honored by the rustls backend (`prefer`/`require`/`verify-ca`/
  `verify-full` all work); a TLS handshake/cert failure there is
  `CONNECTION_FAILED` (exit 6) with a TLS-specific hint (`is_tls_error` →
  `tls_hint`), never a silent plaintext fallback for `require`+.
- **Fail mode**: config validation guarantees `host`/`remote` are present and
  valid, so the cli `expect()`s them (internal invariant) rather than silently
  skipping the tunnel — a skipped tunnel would connect straight to the real host,
  the wrong failure mode for a security step. `sqlite` + `[ssh]` is rejected at
  parse (exit 3).

## Schema introspection (`nyet schema`)

No new dependency: each engine reads its own catalog with the driver it
already has, and the cli path is the query path minus the validator (there is
no agent SQL) — same read-only session, same `timeout_secs`, same SSH tunnel,
same exit codes 6/7/8.

**The `[table]` argument is agent input and never reaches SQL.**

- **SQLite** — `sqlite_master` for the object list (filtered in Rust: the
  argument is compared against catalog names ASCII-case-insensitively, matching
  SQLite's own identifier resolution; `sqlite_%` internals dropped), then
  `pragma_table_xinfo` / `pragma_index_list` / `pragma_index_info` /
  `pragma_foreign_key_list`. The **table-valued** pragma functions are used on
  purpose: unlike the `PRAGMA x(name)` statement form they take a **bind
  parameter**, and the name bound is the one that came *back* from the catalog.
  So `users; DROP TABLE x` / `users'--` are just names that match nothing
  (pinned by `schema_unknown_table_is_exit_7_and_sql_injection_is_just_a_missing_name`).
  `table_xinfo`, not `table_info`: the latter hides GENERATED columns; its
  `hidden` flag distinguishes them (2 VIRTUAL / 3 STORED, both shown) from a
  virtual-table hidden column (1, dropped).
- **PostgreSQL** — four `pg_catalog` queries (objects, columns, constraints,
  indexes) sharing one WHERE tail with the argument bound as `$1`/`$2`
  (name/schema). information_schema cannot do this job: it has **no index
  catalog**. Non-system schemas only (`n.nspname NOT LIKE 'pg\_%'` +
  `<> 'information_schema'`) **and only what the role may read**:
  `has_schema_privilege(n.oid,'USAGE') AND has_any_column_privilege(c.oid,'SELECT')`,
  plus `has_column_privilege(c.oid, a.attnum, 'SELECT')` per column in the
  columns query — pg_catalog is world-readable, so without those clauses
  introspection would hand the agent every table of every schema it cannot
  touch, DEFAULT expressions (literal data — secrets do get parked there)
  included, while MySQL's information_schema filters itself by privilege.
  `has_any_column_privilege`, not `has_table_privilege`: a `GRANT SELECT (col)
  ON t` makes `SELECT col FROM t` legal, so hiding `t` would contradict what
  `nyet query` allows; the per-column check then drops the columns that were
  not granted, and `has_table_privilege(c.oid,'SELECT') AS full_sel` tells the
  key filter below whether the column list is complete. **Known, accepted
  leak:** the constraints query does not filter the *referenced* side, so a
  readable child shows `ref_table: "hidden.parent"` **and the `ref_columns` of
  that parent** even when the role cannot read it — the fk is part of the
  child's own definition (psql's `\d` shows it too) and what is exposed is
  identifiers only, never the parent's data, full column list or defaults.
  Documented in the README. Pinned by
  `postgres_schema_respects_role_privileges`. `public` objects read as bare
  names, others are qualified (`sales.orders`) — the same form `[table]`
  accepts, split on the first `.`; the name also matches its `lower()` form
  since unquoted SQL identifiers fold to lowercase. Index key columns come from
  `unnest(ix.indkey) WITH ORDINALITY` joined to `pg_attribute`
  (`k.ord <= ix.indnkeyatts` drops INCLUDE columns), with `pg_get_indexdef`
  covering expression keys (attnum 0); the index query is restricted to
  `relkind IN ('r','p')` so a **materialized view** (reported as a view) never
  carries indexes, as on the other two engines. The object relkinds are
  `('r','p','f','v','m')` — a **foreign table** (`f`) reads like a table, so a
  role with SELECT on one must find it (covered by a `file_fdw` foreign table
  in the e2e). (`indnkeyatts` is PG11+; older servers are out of scope.)
- **MySQL/MariaDB** — four `information_schema` queries (TABLES, COLUMNS,
  STATISTICS, KEY_COLUMN_USAGE) scoped to `TABLE_SCHEMA = DATABASE()`, the
  argument bound as `?` (twice — MySQL placeholders are positional). A foreign
  key pointing into another database keeps its qualifier
  (`IF(REFERENCED_TABLE_SCHEMA = DATABASE(), ...)`), mirroring the Postgres
  "bare in the default namespace, qualified otherwise" rule. No `EXPRESSION`
  column is selected — MySQL 8 has it, MariaDB does not — so a functional key
  part (NULL `COLUMN_NAME`) becomes the `(expression)` placeholder below.

**Grouping keys are the catalog's, not the display name.** PostgreSQL groups by
`(schema, name)` and applies `pg_display` only on the way out, so
`public."sales.orders"` and `sales.orders` stay two objects; the final list is
sorted by display name (the contract's order). Two consequences of the dotted
form, both pinned by the e2e: (a) `[table]` is split on the FIRST dot, so a
dotted *name* is still reachable by qualifying it (`public.sales.orders` →
schema `public`, name `sales.orders`) — but a bare `sales.orders` always reads
as schema+table; (b) two objects that render to the same display name stay two
entries with indistinguishable `name` values. Living with (b) is deliberate: a
separate `schema` field would cost every agent bytes on every table to
disambiguate a case that needs a quoted dot in an identifier (YAGNI).

**Presentation rules live in `output::build_table`, not in the engines**, so the
three cannot drift: every pk member gets `pk: true` (and `nullable: false` — see
below), a unique index/constraint over exactly one *named* column collapses into
that column's `unique` flag and its index entry is dropped, everything else
stays an index entry with `unique` only when true. Two guards keep that fold
honest, and both are the engines' job because only they can see the catalog
flags:

- a **partial/filtered** unique index (SQLite `pragma_index_list.partial`,
  Postgres `indpred IS NOT NULL`) — and an **invalid** one (Postgres
  `indisvalid = false`, a failed `CREATE INDEX CONCURRENTLY`) — arrives with
  `unique: false`: its uniqueness holds for some rows only, and a `unique` flag
  would promise the agent a key the table does not have;
- an **expression key part** the catalog cannot name is kept as the
  `(expression)` placeholder (Postgres substitutes the real text via
  `pg_get_indexdef`), never dropped — dropping it would make a two-part unique
  index look single-column and fold into a bogus column flag.

The PK-backing index is dropped by the engines too, since only they know its
catalog marker (`origin = 'pk'` / `indisprimary` / the name `PRIMARY`).
Rationale for the whole fold: `pk`/`unique` on the column already carry the
information, and a redundant index entry is pure token cost (UX-4).

**Partial column grants: keys are dropped whole, never shortened.** Neither
`pg_index`/`pg_constraint` nor MySQL's STATISTICS/KEY_COLUMN_USAGE is
privilege-filtered, while the column lists are — so a column-granted role would
otherwise get index/fk entries naming columns it cannot read, and (worse) a
composite PRIMARY KEY reading as a one-column key, which is a *wrong* schema,
not just a chatty one (UX-1). `build_table` therefore takes `full_columns` and,
when it is false, drops the pk if any member is invisible and drops any
index/fk entry with an invisible key part. Two predicates do that, both shared
by every engine so pg and MySQL cannot drift: `names_visible` for plain column
names (the pk and a foreign key's own columns) and `key_parts_visible` for
index keys, which are typed (see below) and need the extra expression rule. Shortening a key list is never
an option: it would both leak "there is more here" and re-open the false fold.
The `full_columns` signal per engine:

- **PostgreSQL** — `has_table_privilege(c.oid,'SELECT')` per object. Table-wide
  SELECT means the columns query withheld nothing, so nothing is filtered (zero
  regression for the ordinary case).
- **MySQL/MariaDB** — always `false`: `information_schema.COLUMNS` is filtered
  by the server but never says whether it filtered, and there is no cheap
  portable way to ask (parsing the privilege tables is not worth it). With full
  privileges every named key part is visible, so the filter drops nothing.
- **SQLite** — always `true`: no privileges exist, the pragma lists everything.

**Key parts are typed, never sniffed by string** (`output::KeyPart`):
`Named(String)` for a column, `Expression(Some(text))` when the catalog hands
over the expression (PostgreSQL `pg_get_indexdef`), `Expression(None)` when it
does not (SQLite's NULL `pragma_index_info.name`, MySQL's NULL `COLUMN_NAME` —
`STATISTICS.EXPRESSION` exists on MySQL 8 only, so no portable text). The
`(expression)` string is a serialization detail of `Expression(None)` and
nothing else; the wire format stays one plain string per part. Two decisions
depend on the type and would be wrong on the text alone:

- **the fold** takes only a `Named` part, so a real column named
  `(expression)` folds like any other column, while an expression whose text
  happens to equal a column name (a quoted `"lower(b)"` column next to an index
  on `lower(b)`) never invents a `unique` flag;
- **the privilege filter** treats `Named` as visible only when the column is,
  `Expression(Some(_))` as invisible (the text can embed identifiers or
  literals from an ungranted column) and `Expression(None)` as harmless (it
  names nothing at all).

**Accepted leak (documented in the README):** because MySQL always runs with
`full_columns = false` and its expression parts are text-free, a functional
index over an ungranted column stays listed there — its NAME may hint at that
column. Dropping every text-free expression entry would blind fully-privileged
accounts to all functional indexes, the worse trade. Pinned by
`mysql8_functional_index_key_part_is_not_dropped`, which also runs the same
table through a `GRANT SELECT (b)` account.

**What that means for SQLite's `sqlite_autoindex_*`** (the indexes SQLite
creates for inline UNIQUE/PK constraints), precisely: the PK one is dropped by
`origin = 'pk'`; a *single-column* `UNIQUE` one disappears in the fold (its
column carries `unique: true`); a *multi-column* `UNIQUE (a, b)` has no column
flag to fold into, so it survives under its generated name
`sqlite_autoindex_<table>_1` with `unique: true` (pinned in
`schema_sqlite_edge_cases_are_not_faked`).

`nullable: false` is forced for pk columns because SQLite's rowid alias
(`id INTEGER PRIMARY KEY`) carries no NOT NULL in the pragma, while Postgres and
MySQL enforce it — reporting it as declared would make the same table read
differently per engine. SQLite's legacy "a non-rowid PK column may hold NULL"
quirk is deliberately not represented.

`DETAIL_LIMIT = 50` (a const in `src/output.rs` — an output policy, so it sits
with the schema model; deliberately not configurable, Д5) is the
adaptive-listing threshold: past it a `nyet schema <alias>` with no table
returns names+kinds only and the cli adds `SCHEMA_TRUNCATED` (the cli asks
`Schema::is_listing()` — derived from the payload, not a second copy of the
state). Naming a table always returns full detail. An argument that matches
nothing comes back as an empty table list, which the **cli** turns into
`DB_ERROR` (exit 7) — the engines do not know the alias the message needs, and
no new error code was introduced for it.

## Auto-guardrail and `nyet explain` (`src/guardrail.rs`)

No new dependency: the plan is JSON (`serde_json`, already there) or ordinary
result rows the engines already decode. The split follows Д1/Д2 — the engines
run the EXPLAIN (IO), `guardrail` parses and judges (pure, fixture-tested), the
cli decides what the verdict means for the envelope.

**Never ANALYZE — the whole feature depends on it.** `EXPLAIN ANALYZE` (and
MariaDB's `ANALYZE`) *executes* the statement, so a guardrail built on it would
run the very query it is supposed to stop. nyet builds its EXPLAIN from a
CONSTANT prefix plus the SQL the validator already accepted (`EXPLAIN (FORMAT
JSON) `, `EXPLAIN `, `EXPLAIN QUERY PLAN `).

**The agent's own `EXPLAIN ANALYZE` is denied (`EXPLAIN_ANALYZE`, owner: the
validator).** It was a real hole: `EXPLAIN ANALYZE SELECT <monster>` is not a
`Statement::Query`, so the cli skipped the guardrail for it, and its plan comes
back as ONE row, so the row limit did not bite either — an unbounded execution
through the one statement kind nobody reads as an execution. There is no
legitimate need for it (that is what `nyet explain` is for), so it fails closed.
Three spellings, in two different places of the AST: the keyword form sets the
`analyze` flag, while PostgreSQL's `EXPLAIN (ANALYZE, FORMAT JSON) ...` puts it
in `options` with the flag left FALSE — reading only the flag left the paren form
wide open — and PostgreSQL **also accepts the British `ANALYSE`**, which a name
match on "analyze" waved through: `EXPLAIN (ANALYSE) SELECT count(*) FROM
generate_series(1, 2e7)` executed in full, 1.74 s, actual times in the output
(verified live). `explain_executes` matches both spellings in both places;
`(analyze false)` is denied too, fail closed. A write *inside* an EXPLAIN ANALYZE keeps the sharper
`WRITE_OPERATION`: the arm only fires for a plain query and the recursion handles
the rest. MariaDB's bare `ANALYZE SELECT ...` does not parse under the MySQL
dialect, so it fails closed as `PARSE_FAILED`. All pinned in the corpus, next to
the `EXPLAIN SELECT ...` allow twins.

**Where the numbers come from, per engine and per flavor:**

- **PostgreSQL** — `EXPLAIN (FORMAT JSON)`; the top plan node's `Total Cost`
  (mode `cost`, the default — a total that already includes its children) and,
  for mode `rows`, the **largest `Plan Rows` anywhere in the tree**
  (`max_plan_rows`, the same pure walk as the recursive-CTE check). Reading the
  top node's rows was a bypass (review finding): the top of
  `SELECT count(*) FROM huge` is an Aggregate with `Plan Rows: 1` over a scan of
  millions, so rows mode waved every aggregate through. The maximum is the
  conservative direction — rows mode is a proxy for work done, and what is
  *returned* is already bounded by the row limit. The column comes
  back as `json`; a text-returning server or an unexpected shape degrades to
  "no estimate" rather than failing (Д3). **A plan containing a `Recursive
  Union` node makes the numbers a LOWER BOUND** (they are kept, and still refuse
  when already over the limit) — see the recursive-CTE section below.
- **MySQL/MariaDB** — the **classic tabular `EXPLAIN`**, deliberately, because
  it is the one form both flavors agree on. `EXPLAIN FORMAT=JSON` exists on
  both but with different trees, and its cost fields are MySQL-only — so nyet
  ships **no `cost` mode here at all** instead of a number that means two
  things (UX-7); `mode = "cost"` on these engines is a config error. Estimate =
  `sum over select ids of (product of that select's rows)`: steps sharing an
  `id` are joined and multiply (that product is what makes a cross join
  enormous), separate ids are separate selects (UNION arms, subqueries) and add.
  `filtered` is ignored — it only lowers the number, and over-estimating is the
  safe direction. Two exceptions to "separate ids add", both from review
  findings: a `DEPENDENT`/`UNCACHEABLE` subquery is re-run per outer row, so its
  group MULTIPLIES the rest — adding it understated a correlated subquery by
  orders of magnitude (5000 + 5000 for real work of 2.5e7) — EXCEPT when its own
  estimate is 1, where multiplying erases it and k such groups would read as a
  single row (a k-fold under-count, third review round), so those are added
  instead. Formally: `(Σ independent, plus every dependent group estimated at 1)
  × (Π dependent groups estimated above 1)`. And a step with a NULL `table` ("No tables used", "Impossible
  WHERE", "Select tables optimized away") counts as ONE row instead of being
  skipped — that is a plan reading nothing, not a plan we failed to read, and
  skipping it made `SELECT 1` warn `GUARDRAIL_SKIPPED` on every call.
  Flavor detail found the hard way and pinned in fixtures:
  **MariaDB 11.4 sends the `rows` column as a STRING** over the binary protocol
  (`"4000"`), so the parser accepts numeric strings as well as numbers.
- **SQLite** — `EXPLAIN QUERY PLAN` gives the plan text and **no numbers at
  all**. So SQLite has no guardrail: `off` is the only accepted mode (anything
  else is a config error) and `nyet explain` answers `verdict: "no_estimate"`
  with the plan. Inventing a pseudo-cost would be exactly the security theatre
  UX-7 forbids.

**Default thresholds (deliberately generous — the guardrail catches monsters,
not analytics; UX-1 says a false refusal is tolerable but a guardrail people
turn off protects nothing):**

- `max_cost = 1_000_000.0` (PostgreSQL cost units). Calibration: a seq scan
  costs roughly `pages + 0.01 * rows`, so ~10^6 rows scanned is only ~15-25k,
  and an aggregate over 10 million rows lands around 200k — comfortably below.
  A cross join or a scan of tens of millions of rows runs into 10^7 and beyond
  (the e2e monster, a 10^6 x 10^6 cross join, plans at ~2.5 * 10^10). One
  million therefore sits an order of magnitude above heavy-but-legitimate work
  and an order of magnitude below the disasters.
- `max_rows = 10_000_000` (estimated rows). A full scan of a 5-million-row
  table passes; a self-join of two 4000-row tables (1.6 * 10^7 rows examined —
  the MySQL e2e monster) does not. It is also above any result an agent could
  usefully read: the row limit truncates at 1000 by default.

Both are per-connection (`[connections.X.guardrail] max_cost / max_rows`);
there are deliberately no `[defaults]` counterparts (YAGNI — a threshold is a
property of one database's size and hardware, not of the tool). Setting the
threshold the ACTIVE mode does not read (`max_rows` under `mode = "cost"`, or
either under `off`) is a config error too: a limit that quietly does nothing is
the same class of lie as a mode the engine cannot honor. And `guardrail.mode` is
literal-only in the config (no `${VAR}`), like `allowed_dirs` and the validator
lists — the environment belongs to the agent, and it must not be able to switch
its own guardrail off.

**Row comparison is integer, cost comparison is float.** `rows` is compared as
`u64` against a `u64` threshold: past 2^53 two different row counts round to the
same `f64`, so a float comparison could tie a monster with its limit (the `value`
in the refusal message is still an f64 — display only). Cost is genuinely
fractional and stays `f64`.

**The backstops have ceilings of their own.** The guardrail's fallbacks —
`timeout_secs` and the row limit — are raisable by the agent through `--timeout`
/ `--limit`, which makes "the timeout is the backstop" only as true as the
config owner allows. `max_timeout_secs` / `max_row_limit` (`[defaults]` or
per-connection, the latter overriding) cap the effective value: `config::capped`
applies them to the flag, to the configured value and to the built-in alike, and
clamps SILENTLY (the effective number is already visible as `TRUNCATED` /
`TIMEOUT`; a warning per call would be pure token cost). Absent = the historical
behavior, byte for byte. Resolution lives in `Config::row_limit` /
`Config::timeout_secs` (pure, unit-tested) — the cli no longer spells the
precedence chain out itself.

**A recursive CTE makes the estimate a LOWER BOUND (two review rounds, both
verified live).** PostgreSQL does not estimate the iteration of a
`Recursive Union`, so
`WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 1e11)`
plans at a `Total Cost` of about **3.35** while the backend burns CPU for the
whole timeout — and `nyet explain` cheerfully reported "ok". The first fix
(drop both numbers, verdict `no_estimate`) traded that for a WORSE hole: gluing a
two-iteration CTE onto a monster erased the monster's own estimate, so
`WITH RECURSIVE z(n) AS (... n < 2) SELECT count(*) FROM <cross join> WHERE ...`
executed where the bare monster was refused in 0.05s. The shipped rule keeps the
numbers and flags them (`CostEstimate::lower_bound`, set by the same pure
`contains_node_type` walk):

- **above the threshold → refuse** as usual: the unestimated part only ADDS, so a
  lower bound over the limit is already proof;
- **below it → `Check::NoEstimate`**: we cannot promise "ok", so `nyet query`
  runs the statement with `GUARDRAIL_SKIPPED` and the timeout as the backstop,
  and `nyet explain` shows the numbers with `verdict: "no_estimate"` and NO
  threshold (nothing was compared).

Refusing every recursive CTE was rejected: hierarchy walks are ordinary,
legitimate SQL. Pinned by
`a_recursive_union_lowers_the_verdict_but_never_hides_a_monster` and by the
disguised-monster case in the Postgres e2e.

**A plan we cannot read is a warning, not a refusal.** If the EXPLAIN succeeds
but carries no usable number, the query RUNS and the envelope gets
`GUARDRAIL_SKIPPED`. The alternative (fail closed, refuse) was rejected on
purpose: the guardrail is an availability guard, not a security boundary — the
security layers (validator, read-only session, read-only role) are unaffected by
a missing cost number, while refusing every plan nyet cannot parse would break
legitimate queries on every server version whose plan shape we did not foresee.
The real backstops (`timeout_secs`, `row_limit`) still apply. A **failing**
EXPLAIN is different: it maps to the ordinary 6/7/8 codes, because the query
itself would have failed the same way.

**Known gaps, documented rather than papered over:**

- Statements that are not a plain query (`SHOW`, `DESCRIBE`, and an `EXPLAIN`
  the agent sends itself) are not estimated — there is nothing to plan. The
  validator reports this (`Verdict::Allow { is_query }`, straight off the AST,
  no keyword sniffing), and the cli passes `Guardrail::OFF` for those. For
  `nyet explain` the same flag short-circuits the database trip entirely:
  wrapping a `SHOW` in another EXPLAIN would only earn a syntax error whose hint
  points at the wrong thing, so it answers `no_estimate` + `NO_PLAN` locally.
- `nyet explain` runs the guarded plan path too — same budget, same server cap
  (`Engine::estimate` returns `Ok(None)` when planning outruns it, which the cli
  renders as `verdict: no_estimate` over an empty plan plus a `GUARDRAIL_SKIPPED`
  warning naming the budget). Before that it ground for the full `timeout_secs`
  and answered "ok, cost 0.01" for the very statement `nyet query` refuses —
  which is precisely the promise "explain answers what query would decide"
  breaking. A database ERROR still surfaces there (exit 7): the plan is the
  answer, there is no query to fall back on. SQLite is the exception (no server
  cap to lend, no numbers to bound anyway).
- A recursive CTE (above), and any plan shape nyet cannot read, run unguarded
  with a warning.
- The estimate is the planner's guess. A wrong statistic (stale ANALYZE) makes
  it wrong in both directions, which is another reason the thresholds are
  generous and the refusal hands back the plan.
- **The view-grant fail-open is a residual vector, and its width was measured.**
  Where a `SELECT`-granted view exists that the role may not `EXPLAIN` (MySQL
  without `SHOW VIEW`), *mentioning that view* is enough: a monster joined
  against it runs with `GUARDRAIL_SKIPPED` even at `max_rows = 1` — one such view
  is a repeatable guardrail off switch for that connection. Accepted anyway: the
  alternative (refusing) breaks legitimate view-only accounts outright, which is
  the far more common case. Mitigations: the warning is in the envelope
  (forensics — the human can see it happened), the timeout and the row limit
  still bound the query, and the README tells config owners the one-line fix
  (grant `SHOW VIEW` alongside `SELECT` on views).
- **pg rows mode takes the MAXIMUM node, it does not add siblings.** Two 6e6
  branches read as 6e6, not 12e6 — the estimate can under-count a wide plan by
  the number of branches. `cost` does not have this problem (the top node's total
  includes everything), which is one more reason it is the PostgreSQL default.
- **MySQL multiplies every dependent group by every other.** Two sibling
  correlated subqueries multiply as if nested, which OVER-counts (a false
  refusal — the safe direction, though it can annoy on wide statements). Its
  under-counting twin — k dependent groups of one row each collapsing into `x1` —
  is fixed in the formula above (they add), not merely documented.
- **Plan numbers arrive through f64.** `serde_json` values are read as `f64`
  before being clamped into `u64`, so a row estimate past 2^53 keeps only
  f64 precision. The comparison itself is exact `u64` — this is an ingest limit,
  and at those magnitudes everything is over every sane threshold anyway.
- **A plan discloses more than a result does.** It names the base tables,
  indexes and predicates behind a view, and shows the qualifiers RLS adds — so an
  account restricted *by a view* still learns the shape underneath. Documented in
  the README: restrict agents with grants, not with views.
- **Planning is not perfectly free of execution.** PostgreSQL evaluates
  constant-foldable `IMMUTABLE` expressions at plan time, so `nyet explain` of
  `SELECT slow_pure_fn(1)` can consume real time (bounded by the same read-only
  session and `timeout_secs`). "Never executes" means the statement is not run —
  not that the work is zero.

**One connection, and its own budget.** The guardrail EXPLAIN runs inside the
engine's existing read-only transaction, right after `BEGIN READ ONLY` /
`START TRANSACTION READ ONLY`, so it costs no extra connect and no extra ssh
tunnel. It does share the query's `timeout_secs` and counts inside
`meta.duration_ms` (that field is the whole database phase — documented in the
README), which is why it also gets a budget of its own: `EXPLAIN_BUDGET_MS`
(5 s, or the query timeout when that is smaller). Two review findings drove this,
both verified live:

- a MySQL EXPLAIN over an `information_schema` cross join took **17.9 s**,
  turning what should have been a refusal into a `TIMEOUT` — while doubling the
  server-side work;
- a role that may `SELECT` a view but lacks `SHOW VIEW` cannot EXPLAIN it
  (MySQL ER 1345), which made `nyet query` fail with `DB_ERROR` where the plain
  SELECT would have worked — a regression caused purely by the guard.

**The two empty-handed outcomes are NOT the same (the core rule).** Fail open
only for causes an agent cannot summon on an ARBITRARY query — an important
qualifier: `Failed` IS reachable on purpose where a suitable object exists (see
the SHOW VIEW gap below), it just cannot be produced for any statement at will,
which is what makes fail-open the right default there:

- `Plan::Failed` — the database would not plan the statement (ER 1345 and
  friends). Fail OPEN: the query runs, `GUARDRAIL_SKIPPED` warns, and the query
  reports its own error if it has one (error parity).
- `Plan::TooSlow` — planning outran the budget. Fail CLOSED: `QueryOutcome::
  PlanTooSlow` -> `NYET`/`EXPENSIVE_QUERY` (exit 5, no plan in the envelope,
  texts from `guardrail::planning_too_slow`). Planning time IS agent-controlled:
  PostgreSQL const-folds `IMMUTABLE` expressions at plan time (measured: three
  `md5(repeat('x', 6e7))` terms = 583 ms of pure planning; eight of them blow a
  1-second budget), and a MySQL EXPLAIN over `information_schema` was seen taking
  24 s. With the old fail-open rule, "make planning slow" was a guardrail off
  switch. A server-side statement timeout during the EXPLAIN (57014 / 3024 /
  1969 -> `EngineError::Timeout`) counts as TooSlow, not Failed. Same catch-all
  as on the query path (where 57014 is documented as TIMEOUT): a manual
  `pg_cancel_backend` aimed at the guardrail's EXPLAIN therefore reads as
  "planning was too slow" and refuses — rare, and a refusal is the safe
  direction.

**The server is capped too, and the session is repaired.** Abandoning the EXPLAIN
client-side is not enough — the backend keeps planning, and on MySQL the late
error of a dropped EXPLAIN surfaced as the failure of the NEXT statement. So:

- **PostgreSQL** (`Postgres::begin_read_only` + `pg_guarded_plan`):
  `SAVEPOINT nyet_guardrail` + `SET LOCAL statement_timeout = <budget>` before the
  EXPLAIN, and `ROLLBACK TO SAVEPOINT` after it — on every path that keeps the
  connection. Each of those two groups travels as ONE message (see "Round trips"
  below): the arming rides in the `BEGIN READ ONLY`, the repair carries its own
  restore.
  `TooSlow` and `Broken` skip it (there the socket is dropped, and the savepoint
  dies with it; awaiting a rollback on a busy or broken session is the very hang
  this design avoids). The savepoint is what makes the
  fail-open path work at all: a failing EXPLAIN aborts the transaction, and
  before this fix `nyet query pg "SELECT * FROM nope_x"` answered *"current
  transaction is aborted, commands ignored until end of transaction block"*
  instead of naming the missing relation (verified live, now pinned in the e2e).
  Rolling back to the savepoint also restores `statement_timeout` (SET LOCAL is
  savepoint-scoped), and an explicit restore follows as belt and suspenders.
  **That second half is provably redundant, and deliberately kept**: measured on
  postgres:16 (`SET LOCAL statement_timeout = 5000` inside the savepoint reads
  `5s`, and after `ROLLBACK TO SAVEPOINT` alone it reads `30s` again), and an
  ablation that deletes ONLY the explicit restore leaves the whole suite green —
  not a coverage hole, an unobservable duplicate. It costs zero round trips (it
  shares the repair message) and covers a rollback that ever stops restoring
  GUCs. The invariant underneath it IS pinned: deleting the whole repair, or
  restoring the wrong value, turns
  `pg_collapsed_guardrail_arming_keeps_its_invariants` red (`5s` / `300ms`
  instead of `30s`).
- **MySQL/MariaDB** (`Mysql::guarded_plan`): `set_statement_timeout(budget)`
  before, `set_statement_timeout(query timeout)` after — the same (now single)
  variable `begin_read_only` uses. Here the restore is NOT redundant (there is no
  savepoint to undo it), and it is pinned twice: an e2e reads
  `@@max_statement_time` back inside the query (10 s with `--timeout 10`, not the
  5 s budget), and `mysql_layer2_types_and_timeout` asserts it as the agent would
  feel it — with `query_timeout_ms = 1000` the EXPLAIN's cap is 300 ms while the
  query's own stays 30 s, so `SELECT sleep(0.5)` must come back `0`; a leaked
  budget makes MySQL interrupt the sleep and return `1`. Both go red under an
  ablation that drops the restore.

**Plumbing errors are their own verdict (`Plan::Broken`).** A failure of the
guardrail's own scaffolding — the savepoint, the timeout it lends the EXPLAIN,
the rollback, the restore — is NOT "we could not plan it": the session state is
then unknown (an aborted transaction, or the query about to run under a 5s
EXPLAIN budget it never asked for). Those paths surface the error instead of
running the query on an undefined session, and a verdict already reached is never
downgraded by them (`TooSlow` stays `TooSlow` — the downgrade is exactly how the
race below used to end in a meaningless `DB_ERROR`). If arming fails halfway, no rollback is
attempted either: `Broken` means the connection is dropped, so the savepoint dies
with the socket — and awaiting a rollback there is exactly the hang this design
avoids.

**Three deadlines, strictly nested: server cap < guardrail deadline < query
deadline.** `explain_budget_ms` = `min(cap + grace, timeout_secs - 200ms)` minus
the 500 ms grace, and `explain_deadline_ms` is **derived from that budget**
(`budget + grace`), so the ordering holds for EVERY timeout the CLI accepts (at
the 1 s minimum: 300 / 800 / 1000 ms; from 10 s up the flat 5 s cap applies).
The derivation direction matters now that the cap is armed at one call site (it
rides in the `BEGIN`) and the deadline is awaited at another: computing both from
`query_timeout_ms` would leave "the server cuts a grace period first" true only
as long as two places agree on the arithmetic, and a silent divergence brings
back exactly the flake below. Passing the budget through
(`pg_guarded_plan(.., budget_ms, ..)`) makes it one physical value.
Both earlier shapes were wrong in the same way:
equal deadlines let the race be decided by luck (the e2e flaked one run in
three), and `budget + grace` alone exceeded the query's own deadline below 3.5 s,
so the outer timer answered `TIMEOUT` before the guardrail could refuse. Pinned
by the loop over timeouts in
`a_failing_explain_falls_open_but_a_slow_one_refuses`.

**`TooSlow` is terminal, and a dirty connection is dropped, never chatted with.**
Once planning has outrun the deadline nothing further is attempted on that
connection — no rollback, no restore, no graceful close — because the backend may
still be planning and each of those would queue behind it until the query's
deadline fired and turned the refusal into a bare `TIMEOUT` (the same root as the
earlier flake, on a different path). Two direct consequences: a plumbing error
can no longer overwrite the verdict (there is no plumbing left to fail), and
`Plan::Broken` drops the socket too — a graceful goodbye can hang on exactly what
broke. `Plan::discard()` is the ONE predicate every call site uses — the two
guarded query paths and the two `nyet explain` paths alike; the remaining polite
closes (`pg_close_read_only` / `mysql_close_read_only`) sit only on connections
the guardrail left clean: the threshold refusal, the executed query, and the
`schema` path that never plans anything. That claim was false for one review
round — the query paths still closed politely on `TooSlow`, which is exactly the
race this section exists to close.

**And even a polite close is bounded, and happens after the deadline.** The
goodbye on a clean connection is not fire-and-forget: on a TLS connection sqlx's
rustls socket runs `complete_io` during shutdown, which READS, waiting for the
peer's `close_notify` — and a pooler may never send one (Yandex MDB's odyssey
neither answers nor closes the socket), so `close()` hangs forever. The
`ROLLBACK` before it waits on the server too. Hence two rules, both in
`pg_close_read_only` / `mysql_close_read_only` and their `*_finish` callers:
the whole goodbye runs under `CLOSE_GRACE`, and it runs **outside** the query
deadline — the query phase hands the connection back (`Option<Conn>`; `None` for
one it deliberately dropped) and the close happens after. A bound alone would not
be enough: inside the deadline the grace is only `min(remaining, CLOSE_GRACE)`,
so a `timeout_secs` of 1-2 would still let the outer timer discard an answer
already in hand. This was a real bug against a Yandex MDB PostgreSQL behind
odyssey: the rows arrived in 1.4 s and the caller still got `TIMEOUT` at 60 s.

Two more things worth knowing:

- **PostgreSQL does not interrupt plan-time const-folding on
  `statement_timeout`** (measured — `md5(repeat(...))` chains run to completion),
  so for that particular attack the CLIENT deadline is what fires. The server cap
  still matters for ordinary slow planning, where interrupts do get checked.
- On `TooSlow` the connection is **dropped, not closed politely**: a graceful
  `ROLLBACK`/`COM_QUIT` would wait for the planning we just abandoned. The
  backend notices when it tries to answer. That is the accepted cost of refusing
  on time.

Cost over an unguarded query: three extra round trips on Postgres (the EXPLAIN's
two, plus the repair message) and four on MySQL (the EXPLAIN's two, plus lending
and returning the cap). The ARMING is free on both — it rides in a message that
was being sent anyway (see "Round trips" below). That is the price of a guardrail
that cannot be disabled by making planning slow.
*Residual, documented:* MariaDB's `max_statement_time` has SECOND granularity,
rounded UP (rounding down turned a 1600 ms budget into a 1 s cap and refused
queries that were inside it). So on short timeouts the server cap lands LATER
than nyet's own deadline — 300 ms of budget becomes a 1 s cap at `--timeout 1`,
1300 ms becomes 2 s at `--timeout 2` — and the real limiter there is the client
deadline plus the drop. That costs a connection, not a verdict: a client-elapsed
`TooSlow` is terminal, survives untouched (no plumbing runs after it) and is
answered from the dropped socket.
Classification is pinned by `a_failing_explain_falls_open_but_a_slow_one_refuses`
(no Docker, stubbed plan future) and end to end by the const-folding case in
`tests/postgres.rs`.

When the estimate blocks, the engine returns `QueryOutcome::Refused { estimate,
value }` (and `PlanTooSlow { budget_ms }` for the budget case) — the engines never decide policy, they only call `Guardrail::refuses`
(and `plans()`, so they never even see the mode); the comparison, the texts and
the envelope shape live in the pure module.

**No cache, on purpose (Д5).** Plans are not memoized between runs: a plan
depends on statistics, parameters and server settings, and a stale cached
estimate would be a guardrail that lies. Reconsider only if a connection daemon
(ROADMAP v0.5) ever gives it a natural home.

## Round trips (the control statements, per engine)

On a LAN the control statements around a query are invisible; over a WAN they are
the bill. Measured against a Yandex-MDB-shaped setup (RTT ≈ 27.5 ms), one
`nyet query` cost 542 ms of which 278 ms was the query phase — and the query
phase was **ten** round trips on Postgres and **twelve** on MySQL/MariaDB, i.e.
more than the connect handshake itself (4–6). Through an SSH bastion each round
trip roughly doubles in price (measured: 431 ms warm through the tunnel vs 229 ms
direct at the same RTT), so the count is what to cut, not the per-hop cost.

**What was collapsed.** Both wire protocols run a `;`-separated string of
statements in ONE round trip, in order, stopping at the first error (Postgres:
the simple-query `Query` message, which sqlx uses for any `execute(&str)` with no
bind parameters; MySQL: COM_QUERY with the CLIENT_MULTI_STATEMENTS capability
sqlx already negotiates). Groups that are always sent together are therefore sent
as one message:

| Group | Before | After |
|---|---|---|
| pg: `BEGIN READ ONLY` + `SAVEPOINT` + `SET LOCAL statement_timeout = <budget>` | 3 | 1 |
| pg: `ROLLBACK TO SAVEPOINT` + `SET LOCAL statement_timeout = <restore>` | 2 | 1 |
| mysql: `START TRANSACTION READ ONLY` + the timeout SET | 3 | 1 |
| mysql: the two SETs the guardrail lends and returns | 4 | 2 |

Per guarded `SELECT`, query phase only (connect excluded), counted on the wire:

| Path | Before | After |
|---|---|---|
| `query`, PostgreSQL | 10 | **7** |
| `query`, MySQL / MariaDB (label correct) | 12 | **8** |
| `query`, MySQL / MariaDB (label wrong) | 12 | **9** |
| `explain`, PostgreSQL | 8 | **5** |
| `explain`, MySQL / MariaDB | 10 | **6** |
| `schema`, MySQL / MariaDB | 12 | **10** |
| `query` with `guardrail.mode = "off"`, PostgreSQL | 4 | 4 (unchanged — nothing is armed) |
| `query` with `guardrail.mode = "off"`, MySQL / MariaDB | 6 | **4** |
| `schema`, PostgreSQL | 10 | 10 (unchanged) |

At RTT 27.5 ms that is ≈ 82 ms saved per Postgres query and ≈ 110 ms per
MySQL/MariaDB query; through an SSH tunnel (where the per-hop price doubles),
≈ 165 / 220 ms.

**How it was measured (reproducible).** A counting TCP proxy in front of the
container: it forwards every client→server flush after a fixed delay and logs it
(one flush = one round trip, because both drivers flush and then read). The log
is the statement-by-statement trace, and the wall clock is the second, independent
witness — `meta.duration_ms` moves by exactly `Δround-trips × delay`:

| delay per round trip | pg before → after | mysql before → after |
|---|---|---|
| 27 ms | 446 → 359 ms | 422 → 293 ms |
| 55 ms (tunnel-shaped) | 853 → 676 ms | 810 → 585 ms |

(medians of 3–5 runs, `postgres:16-alpine` / `mysql:8.4` / `mariadb:11.4` on
colima; the numbers include the connect handshake, which did not change.)

**Why none of the guardrail's invariants moved.** Collapsing is only safe where
every statement in a group fails the SAME WAY to the caller, and where nothing
can slip between them:

- **The server-side timeout is never absent.** On Postgres the query's
  `statement_timeout` is a CONNECT option (libpq `-c`), so it is in force before
  the first byte of SQL; the `SET LOCAL` only NARROWS it for the EXPLAIN and is
  restored in the same message as the savepoint rollback. On MySQL the cap now
  shares its round trip with `START TRANSACTION READ ONLY`, which comes first —
  and still lands before any agent statement.
- **Read-only cannot be bypassed.** `BEGIN READ ONLY` /
  `START TRANSACTION READ ONLY` is the FIRST statement of its group and the
  server stops the group at the first error, so nothing can execute ahead of it
  (Postgres also carries `default_transaction_read_only=on` from connect).
  Verified live: after the collapsed batch, `transaction_read_only` reads `on`
  and an `INSERT` is refused.
- **The guardrail still cannot be switched off by slow planning.** The
  `Plan::Failed` / `Plan::TooSlow` / `Plan::Broken` classification, the three
  nested deadlines and `Plan::discard()` are untouched; the collapse only changes
  how many messages carry the same statements. `TooSlow` still returns before any
  repair is attempted.
- **The restore still happens on every path that keeps the connection**,
  including the fail-open one: it is the second half of the repair message that
  the `Failed` path sends too. A failure of that message is still `Plan::Broken`
  (the session is unusable either way — which is exactly why the two halves may
  share a message).
- **Arming failure is treated like `Plan::Broken`.** Since the savepoint and the
  budget now travel with the `BEGIN`, a half-applied arming is indistinguishable
  from a failed `BEGIN` — so the armed paths (`query`, `explain`) DROP the socket
  instead of closing it politely, which is what `Plan::Broken` already did for
  the same failure. The unarmed `schema` path still closes politely: nothing was
  armed, so its state is known.

**Diagnostics: what is lost.** When a collapsed group fails, the server names the
error but not which statement of the group tripped on it. That is acceptable
precisely because the groups were chosen so any member's failure means the same
thing to the agent and to the human: arming → "the session could not be set up"
(DB_ERROR, exit 7, the server's own message); repair → `Plan::Broken` → the same
DB_ERROR the un-collapsed code produced. No `error.code`, `reason`, hint or exit
code changed, and none of the statements in a collapsed group contains agent
text — the agent's SQL still travels ALONE, as a prepared statement, which is
also why the collapse adds no injection surface (multi-statement text queries
carry nyet's own constants plus integers).

Not collapsed on purpose: the EXPLAIN and the query itself (prepared statements —
Parse/Describe then Bind/Execute on Postgres, COM_STMT_PREPARE then
COM_STMT_EXECUTE on MySQL: 2 round trips each, and the protocol has no way to
batch them through sqlx), and the final `ROLLBACK`/close (it already runs outside
the query deadline). Connection reuse, a daemon and query batching stay out of
scope (ROADMAP v0.5).

## `nyet agent-setup` (`src/skill.rs` generator)

A local generator (UX-3: an agent must be able to learn nyet by itself) that
emits a **Claude Code skill** — a `SKILL.md` with YAML frontmatter
(`name`/`description`) and a Markdown body. No new dependency; no database, no
network, no runtime (Д9 — it short-circuits at the top of `run()`, before the
config read). The split follows Д1/Д2: `skill::skill` is a **pure function**
(instruction template + the already-read connections -> String, unit-tested with
no IO), and the cli does the best-effort config load and the stream write.

**Skill format — verified, not guessed (a hard requirement).** The frontmatter
shape was checked against the current Claude Code skills docs
(`code.claude.com/docs/en/skills` frontmatter reference) via the
`claude-code-guide` subagent. What that established: for a **directory** skill
(`.claude/skills/<name>/SKILL.md`) no frontmatter field is strictly required and
the command name comes from the directory, not `name`; `description` is the
recommended field and is what Claude uses to decide when to load the skill
(truncated at ~1536 chars in listings). nyet still writes both `name: nyet`
(kebab-safe single token) and a `description` phrased as *when* to use nyet
(reading a database, inspecting schema, safe read-only queries), so the file is
valid whether dropped in as a directory skill or a plugin skill. The generator
writes the YAML by hand (no yaml crate — Д8): the frontmatter is trivial and we
generate it, we do not parse it. A `frontmatter_is_valid_and_names_the_skill`
unit test parses it manually and asserts `name`/`description` are present and
non-empty, and that exactly two bare `---` fences exist (no stray fence in the
body).

**Hybrid content.** A stable instruction (commands with examples; how to read
the `ok`/`rows`/`meta`/`warnings` envelope and `error.code`/`reason`/`hint`;
the exit-code table; how to fix a `NYET` refusal from `reason`+`hint`; that the
agent operates on aliases, never credentials) plus a dynamic "Your connections"
section listing the real aliases and engines. **Scope decision: connections
reachable from the current directory**, the same scope as `nyet list` (not the
whole config) — the skill is generated from the project directory where it will
live, so cwd scope is exactly the connections relevant there, the concrete
`nyet query <alias>` example then uses an alias that actually works from there,
and it keeps one mental model with `nyet list`. Determinism: connections are
sorted by alias (the cli passes them from a `BTreeMap`, and `skill::skill` sorts
again so the pure function does not depend on the caller) for a stable snapshot.

**Degradation, not failure.** A missing / unreadable / unparseable config, or an
unresolvable cwd, degrades the dynamic section to a hint (`Connections::
Unavailable`) — `agent-setup` still emits the full instruction and exits 0. It
is never an exit-3 config error: the command's value is teaching the agent
*before* setup. Empty-but-reachable (config fine, nothing scoped here) is a
distinct hint pointing at `allowed_dirs` / `nyet list`.

**Output / envelope.** Default is the raw `SKILL.md` on stdout with the success
envelope one JSON line on stderr — markdown is treated as a data format, routed
through the same `emit()` as table/csv/jsonl (DESIGN §1: the envelope's place is
decided by the format). `--format json` puts the whole `SKILL.md` in a **new
append-only envelope field `skill` (string)** on stdout via
`output::skill_json`; serde escapes the markdown (newlines, quotes) into a valid
JSON string. `agent-setup` has its own two-value format enum (`markdown` | `json`
— the row formats are meaningless for a single document) and does not honor
`[defaults].format`. It adds no error/warning code and does not extend the exit
table: exit 0 (a bad config degrades, never exit 3; a closed reader / broken
pipe is exit 0 too), and — like every command — only a non-broken-pipe stdout
write failure (a full disk -> `INTERNAL`, exit 1) errors.

## `nyet doctor` (`src/output.rs` verdicts, `engine::diagnose` facts)

Honest setup diagnostics for a **human** (UX-7). No new dependency. The split
follows Д1/Д2: the engine gathers FACTS (`Engine::diagnose -> output::Diagnosis`,
an IO call), the pure `output::doctor_checks` compares them with the expectation
and builds the verdicts (fixture-free, unit-tested), and the cli orchestrates and
formats. The envelope carries a new append-only field `checks: [{name, status,
message, hint?}]`; `status` is a **closed list** (`ok` | `warn` | `fail` | `na`),
and doctor is always `ok: true` (it ran — the verdicts are per-check).

**Exit codes: doctor lives in 0/3 only.** It exits 0 whenever it *ran*, even when
checks find problems — a failed *connection* is a `fail` check, NOT exit 6:
diagnosing a broken connection is the whole point. The only non-zero exits are
the config-level ones every command shares (config unreadable / unknown alias ->
3, unsupported engine -> 1). The exit table is NOT extended.

**Default format is `table`** (the one human-facing command). Unlike list/schema/
explain it ignores `[defaults].format` (set for agent query workflows) — only an
explicit `--format json|table` changes it. Stream convention is the usual one:
`table` puts the readable checks on stdout and the (checks-less) envelope on
stderr; `json` puts the whole envelope on stdout.

**No directory scoping for a named alias.** `nyet doctor <alias>` diagnoses
regardless of `allowed_dirs` — the human owns the config and is often testing it
before `cd`-ing into the project. `nyet doctor` with no alias lists the
connections reachable from cwd (scoping applies to that listing only).

The six checks (order = presentation order): `connectivity`,
`transport_encrypted`, `read_only_role`, `not_superuser`, `pii_columns`,
`config_permissions`.
`transport_encrypted` reuses the same static rule as the `INSECURE_TRANSPORT`
warning (`engine::transport_below_require`, ssh vs. sslmode >= require);
`config_permissions` reuses `config::permissions_warning`; `pii_columns` is
described in the PII section below. SQLite reports
`transport_encrypted` / `read_only_role` / `not_superuser` / `pii_columns` as
`na` (no server, roles or network) — an honest non-answer, never a faked pass.

### The layer-3 write probe — the ONE place layer 2 is removed

`read_only_role` is a **hybrid**: metadata explains *why* a write is (or is not)
refused, and a **probe write proves the fact**. Layer 2 (nyet's read-only
session) would refuse ANY write and prove nothing about the role, so `diagnose`
connects on a dedicated path (`connect_plain`) that does **not** apply layer 2
(no `default_transaction_read_only`, no `BEGIN READ ONLY` / `START TRANSACTION
READ ONLY`) and runs a write the SERVER would refuse for a read-only role /
replica. This is the only code path in all of nyet where layer 2 is deliberately
off, and it is reached only by `doctor` — `query`/`explain`/`schema` never call
`diagnose`.

The probe object is uniquely named (`nyet_doctor_probe_<pid>_<nanos>_<seq>`, a
reserved prefix that cannot hit a real table; the process-local `seq` hardens the
name when the clock reads at the epoch) and the write is a `CREATE TABLE` — a
write **not tied to any existing object**.

**Classification is the honesty crux (UX-1/UX-7): unknown ≠ ok.** A false pass is
the worst outcome for a security tool (UX-1: a false pass destroys the human's
trust, worse than a false warn), so ONLY a KNOWN server read-only error reads as
`ok`. The three outcomes:

- **the write succeeded** → `ProbeFact::Wrote` → `fail`: the role can write.
- **a KNOWN read-only error** → `ProbeFact::Blocked { ddl_only }` → `ok`: the
  server refused the write. The `ddl_only` flag splits the `ok` HEADLINE so it
  does not over-promise (UX-7): a real read-only refusal (`ddl_only = false`) says
  "a direct write would be rejected"; an access-denied on CREATE
  (`ddl_only = true`) says only DDL was proven refused and DML was not probed. The
  status is `ok` either way. Exact codes (`pg_readonly_refusal` /
  `mysql_readonly_refusal` return `Some(ddl_only)`):
  - **PostgreSQL** — SQLSTATE `25006` (`read_only_sql_transaction`: a hot standby,
    or a role/db that defaults to read-only) and `42501` (`insufficient_privilege`:
    the role lacks CREATE).
  - **MySQL/MariaDB** — errno `1290` (ER_OPTION_PREVENTS_STATEMENT:
    `read_only`/`super_read_only`), `1836` (ER_READ_ONLY_MODE), and the
    access-denied codes for the write `1142` (ER_TABLEACCESS_DENIED_ERROR), `1044`
    (ER_DBACCESS_DENIED_ERROR), `1227` (ER_SPECIFIC_ACCESS_DENIED_ERROR).
- **any OTHER error** (connection loss, timeout, a name collision like PG `42P07`
  / MySQL `1050`, a lock-wait timeout, no database selected, disk full, …) →
  `ProbeFact::Unknown` → **`warn`** ("could not verify the server rejects
  writes"), NOT a false `ok`. Before this rule every CREATE error mapped to
  `Blocked`/`ok` — a lost MySQL ACK (server created the table, client saw the
  error) even read as `ok` while orphaning a table.

**Known limitation — the probe proves DDL-write capability, NOT DML.** A `CREATE
TABLE` refused with `42501` / `1142` proves the role cannot CREATE, which for the
**recommended SELECT-only layer-3 role is genuinely read-only** — but a role with
`INSERT`/`UPDATE`/`DELETE` grants and no `CREATE` also lands on that code and
therefore reads as `read_only_role: ok` even though it can write data. The
compromise is accepted because the recommended layer-3 role is SELECT-only (no
DDL, no DML); a DDL-write probe would be far messier to make DML-general. Pinned
by the `writer` role in `postgres_doctor_end_to_end` so a change is a conscious
one. (Treating `42501`/`1142` as `warn` instead was rejected: it would report the
correct SELECT-only setup as "could not verify", training the human to ignore the
tool — the opposite UX-1 damage.)

**No stray object in the normal case — a possible orphan is always NAMED, never
lost:**

- **PostgreSQL** — DDL is transactional, so the probe runs inside an explicit
  transaction that is only ever **ROLLED BACK, never committed**. The rollback
  runs on every path, and because nyet never issues `COMMIT`, even a panic, an
  early return or the cancellable deadline firing drops the socket and the backend
  discards the uncommitted transaction. Nothing can persist — no orphan is
  possible. The connection is **dropped, not gracefully closed** after diagnose
  (`close().await` on a deadline-abandoned socket would itself be an un-cancelled
  await).
- **MySQL/MariaDB** — DDL **auto-commits** (a transaction cannot roll it back), so
  the probe is a **create-then-drop**: it leaves nothing in the normal case, but a
  refused DROP / a dead socket / a timed-out probe can leave a table, which is why
  a possible orphan is always NAMED for manual cleanup. The safety rules:
  1. **DROP only after a CONFIRMED CREATE, and only our exact name** — never
     `IF EXISTS`, so a CREATE that failed on a name collision cannot delete a
     pre-existing table, and a failed CREATE (read-only / collision / lock-wait)
     touches nothing.
  2. **NO un-cancelled await anywhere.** The invariant is not "the CREATE is the
     only un-cancelled step" — every await is time-bounded:
     - the **metadata** queries run under a client deadline; a timeout POISONS the
       MySQL connection (a dropped op leaves it busy), so the connection is NOT
       reused — the probe is **skipped** and the socket **dropped** (never a
       graceful close, which could hang on the abandoned op). Here BOTH `superuser`
       and `read_only_role` become `warn` (the metadata never answered).
     - **cap-arming** (`arm_probe_bounds`, only `SET`s — which create nothing, so a
       client deadline here does NOT re-open the orphan risk) also runs under a
       client deadline; a timeout → skip + drop.
     - the **probe itself** (CREATE + DROP) is bounded BOTH server-side (primary —
       `arm_probe_bounds` sets `max_statement_time` / `lock_wait_timeout`; the
       usual way a stuck statement is cancelled) AND by a generous CLIENT backstop
       (`probe_backstop_ms` = **2 × the server cap + grace** — the probe runs TWO
       statements, CREATE and DROP, each of which can independently wait a full cap
       on a metadata lock, so the worst-case live duration is `2 × cap`; a single-cap
       backstop would fire during a slow-but-legitimate DROP and cry a false orphan):
       on a **dead socket** the server cap cannot reach the client, so the `.await`
       would hang forever — the backstop fires, the outcome is unknown, and the
       possible orphan is NAMED (`probe_backstop_expired`). The connection is
       **dropped, not closed** (a `close().await` on a dead socket is itself an
       un-cancelled await).
     - the server-side bound is **fail-safe (gate `mysql_probe_bounded`)**: a DDL
       statement is capped by `lock_wait_timeout` (both flavors — the metadata-lock
       wait that actually hangs a CREATE) OR MariaDB's `max_statement_time`; MySQL's
       `max_execution_time` is SELECT-only and does NOT count. If neither can be
       armed → skip.

     Every skip is a `warn` with an honest reason (`PROBE_SKIP_METADATA_TIMEOUT` /
     `PROBE_SKIP_ARM_TIMEOUT` / `PROBE_SKIP_NO_BOUND`, the branch chosen by the pure
     `probe_after_arming`), never an un-bounded CREATE on a sick connection (a
     self-DoS). For the cap-arming / no-bound skips the metadata verdict
     (`superuser`) is kept and only `read_only_role` warns; the metadata-timeout
     skip warns on both.
  3. **a DROP that is not acknowledged reports the possible orphan NAME**
     (`Wrote { orphan: Some(name) }`) instead of swallowing it. The message says
     the table **may remain** (a transport loss after a successful server-side DROP
     is "unknown", not "definitely there"). The check stays `fail` (the role
     writes). Pinned by the `nodrop` account (CREATE but not DROP) in
     `mysql_doctor_end_to_end`, which asserts the orphan is real *and* reported.
  4. **a CREATE whose outcome is unknown NAMES the possible orphan too.** A failed
     CREATE is classified (`classify_mysql_create_failure`, pure) by its error
     number: a read-only errno → `Blocked` (nothing created); another SERVER error
     (`1050` collision, `1205` lock-wait — the server replied) → `Unknown`, no
     orphan (the CREATE did not commit); but a **transport failure with no error
     number** (a connection drop / IO error where the auto-committed CREATE may
     already have committed) → `Unknown` whose message NAMES the possible orphan
     ("if the connection dropped after the CREATE, a table named
     `nyet_doctor_probe_…` may remain — check and DROP it manually"), symmetric
     with rule 3. So no lost-ACK orphan is ever left unnamed.

     *Residual (documented, not over-engineered):* the transport-loss discriminator
     is `mysql_err_number().is_none()` — a reasonable heuristic, not a proof of how
     sqlx 0.9 represents a mid-statement transport loss. If a future sqlx ever
     surfaced transport loss as a *numbered* error, that case would fall into
     `ServerRejected` and the possible orphan would go unnamed — conservatively
     accepted; revisit on an sqlx upgrade.

  Making the guarding role SELECT-only (the recommendation) removes the whole
  question: a read-only role's CREATE is refused before any write, so nothing is
  ever created.

The normal-case no-orphan behavior is proven by tests that run `nyet doctor`
against a writable role and assert, on a separate connection, that no
`nyet_doctor_probe_%` table survives and the seed data is intact
(`postgres_doctor_end_to_end`, `mysql_doctor_end_to_end`) — direct factual
assertions, not timing ones. The orphan-NAMING paths (a refused DROP, and the
client backstop firing on a dead socket) are pinned by `mysql_doctor_end_to_end`'s
`nodrop` account and the pure `probe_backstop_cuts_off_a_dead_socket_and_names_the_orphan`.

### Per-engine metadata and superuser facts

Honesty-first again: a metadata failure is `SuperuserFact::Unknown` → `warn`
("could not determine superuser status"), NEVER a false "not a superuser".

- **PostgreSQL** — `current_setting('is_superuser')` (`Yes`/`No`, or `Unknown` on
  a query error), `pg_is_in_recovery()` (hot standby), and
  `current_setting('default_transaction_read_only')` (a read-only role/db
  default). The replica / read-only-default note is folded into the
  `read_only_role` ok message (the *why*). The replica/default queries are the
  only ones read leniently (they merely color the message).
- **MySQL/MariaDB** — `@@global.read_only` / `@@global.super_read_only` (the latter
  is a MariaDB-unknown variable, so its error yields `None`), and `SHOW GRANTS`.
  The grant scan is deliberately narrow: `ALL PRIVILEGES` / `SUPER` on `*.*` →
  `Yes` (a universal `USAGE ON *.*` and a db-scoped `SELECT ON app.*` do not trip
  it); a `SHOW GRANTS` failure or empty result → `Unknown`; **role or PROXY grants
  nyet does not resolve → `Unresolved` → `warn`** ("nyet checks direct grants
  only — verify elevated privileges by hand"), never a false "not a superuser" (no
  role resolver, Д5 — just an honest gap). The raw grant line is never echoed
  (MariaDB embeds `IDENTIFIED BY PASSWORD '*hash'`): only the privilege type is
  named. The probe remains the authoritative writability check; the grant scan
  only feeds `not_superuser`.

### Tests

- **Pure (`src/output.rs`)** — `doctor_checks` over hand-built facts: all four
  statuses with hints (Д10), the probe-blocked ok path (both `ddl_only` headlines)
  with a replica note, the **unknown-is-warn-never-a-false-ok** path (a
  non-read-only probe error and an undetermined superuser status both `warn`), the
  **orphan reporting** (a `Wrote { orphan }` surfaces the leftover name) and
  `Unresolved` grants `warn`, the connect-failure shape, the SQLite `na` honesty,
  the config-level (no-alias) checks, and a compact envelope + table snapshot (Д7).
- **Pure (`src/engine.rs`)** — `classify_mysql_create_failure` over error numbers
  (read-only errnos → `Blocked`; another server error → no orphan; `None` /
  transport failure → `MaybeOrphan`, the lost-ACK case that must name the table),
  `mysql_probe_bounded` (the fail-safe gate: EITHER cap bounds it, and it must NOT
  require both — MySQL never has `max_statement_time`), `probe_after_arming` (the
  probe runs only on a bounded, healthy connection; a cap-arming timeout `None` — a
  poisoned connection — skips it, never runs un-bounded), and
  `probe_backstop_cuts_off_a_dead_socket_and_names_the_orphan` (a stubbed hung
  future is cut off by the client backstop, which names the possible orphan — no
  un-cancelled await, no lost orphan).
- **SQLite (`tests/cli.rs`, no Docker)** — the honest `na` output in table and
  json with the stream convention, loose vs. 0600 config permissions, a connect
  failure that is a `fail` check with exit 0 (not exit 6), the no-alias listing,
  and unknown-alias -> exit 3.
- **PostgreSQL / MariaDB (testcontainers)** — `postgres_doctor_end_to_end` /
  `mysql_doctor_end_to_end`: a writable/superuser account fails read_only_role +
  not_superuser, a SELECT-only role passes both, the probe leaves nothing behind
  (no probe table survives, data intact), the documented DDL-vs-DML false ok is
  pinned (a PG `writer` role with INSERT but no CREATE reads `ok`), the MySQL
  orphan is reported when DROP is denied (`nodrop` — CREATE but not DROP —
  produces a `fail` naming a table that really remains), and (Postgres) a
  `require`-mode url reads `transport_encrypted: ok` even when the connect then
  fails on the no-TLS container. All exit 0.

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
- `sqlx` (runtime-tokio; `tls-rustls-ring-webpki`, `sqlite-bundled`, `postgres`,
  `mysql`, `bigdecimal`, `uuid`, `chrono`, `json`) — the SQLite, PostgreSQL and
  MySQL/MariaDB drivers.
  `sqlite-bundled` (not the `sqlite` meta-feature) keeps `load-extension` and friends
  out of a security tool. `postgres` and `mysql` are built-in drivers — one shared
  driver crate for MySQL and MariaDB, no new top-level dependency. The four type
  features are the price of reading a real table: `bigdecimal` decodes
  `numeric`/`DECIMAL` losslessly to a string (f64 would round money/ids), `uuid`,
  `chrono` (timestamp/date/time) and `json` (jsonb / MySQL `JSON` straight into the
  envelope) cover the types prod tables are full of; without them a normal `SELECT`
  would DB_ERROR on decode. **TLS via `tls-rustls-ring-webpki`** (rustls + `ring`
  + bundled webpki roots — rationale and the deliberate absence of the
  `mysql-rsa` feature / `rsa` crate are in the MySQL/TLS note above). Postgres
  layer 2 is server-enforced (connect options
  `-c default_transaction_read_only=on -c statement_timeout=<ms>` plus an explicit
  `BEGIN READ ONLY`); MySQL/MariaDB layer 2 is an explicit `START TRANSACTION READ
  ONLY` plus a `SET SESSION max_execution_time`/`max_statement_time`.
- `tokio` (rt, time, net) — sqlx requires an async runtime; `time` gives the query
  timeout, `net` the Postgres TCP connection. The per-query runtime uses
  `enable_all` (io + time). Single-threaded, built per query.
- `futures-util` (no default features) — `try_next()` on sqlx's row stream, to fetch
  limit+1 rows instead of the whole result. Already in sqlx's own tree.

Dev:

- `tempfile` — per-test isolated dirs with cleanup; symlink/permission fixtures
  without touching the real `~/.config`.
- `testcontainers-modules` (`postgres`, `mysql`, `mariadb` features) — the
  server-engine integration and e2e tests need a real server; this spins a
  throwaway container per test (`postgres:16-alpine`, `mysql:8.4`, `mariadb:11.4`)
  and tears it down. Chosen over a hand-rolled `docker run` wrapper (Д8): it owns
  image pull, readiness wait and cleanup (the ryuk reaper), and each module ships
  the ready image config. Dev-only — it never reaches a release binary. Its (large) transitive tree passes `cargo deny`
  (licenses/advisories/bans/sources) as of this step. The SSH tunnel stand
  (`tests/ssh.rs`) reuses this crate's re-exported `testcontainers` (`GenericImage`,
  networks, `container.exec`) for the `linuxserver/openssh-server` bastion — no
  new dependency.

## Tests

- Unit tests live next to the code (`src/*.rs`, `#[cfg(test)]`): config
  parsing/substitution/permissions, resolver path logic, envelope snapshots,
  validator corpus, engine read-only/decoding (on temp SQLite files).
- `tests/cli.rs` runs the real binary via `CARGO_BIN_EXE_nyet` with
  `env_clear()` + a temp `HOME`, pinning exit codes and envelope structure
  (Д7: the output is an API — changing codes/structure must break tests).
  Query tests build a fixture SQLite database with sqlx.
- `nyet schema` is covered at three levels. Unit snapshots of the envelope and
  the pk/unique folding (`src/output.rs`). SQLite e2e in `tests/cli.rs`: the
  full shape (composite pk/fk, unique column vs multi-column unique index, a
  view), the adaptive listing at 51 objects, table-not-found, SQL-injection
  arguments that stay a plain "not found", case-insensitive `[table]`, and
  `schema_sqlite_edge_cases_are_not_faked` — the cases where a naive catalog
  read would invent a key: expression key parts, a partial unique index, a
  STORED generated column, an inline composite UNIQUE autoindex, an
  unresolvable FK parent. Container e2e per server engine:
  `postgres_schema_end_to_end` (non-public schema, qualified names, `serial`
  default, composite fk, matview without indexes, a `file_fdw` foreign table,
  partial unique index, colliding display names,
  qualified/unqualified/case-folded `[table]`),
  `postgres_schema_respects_role_privileges` (the SECURITY one: a `lowpriv`
  role sees only its granted tables — table-wide and column-level — with the
  ungranted columns, schemas, DEFAULT literals and every key touching an
  ungranted column absent, while the table-wide grant keeps its pk),
  `mysql_schema_end_to_end` (AUTO_INCREMENT, composite pk/fk, view, a
  cross-database FK keeping its qualifier, and the same server seen through a
  `GRANT SELECT (a)` account: composite pk and the index over `b` gone, the
  index over `a` kept) and
  `mysql8_functional_index_key_part_is_not_dropped` (`mysql:8.4` — MariaDB has
  no functional indexes).
- The guardrail is covered at three levels. Pure unit tests in
  `src/guardrail.rs` (fixture plans: a PostgreSQL `FORMAT JSON` tree, both MySQL
  and MariaDB classic EXPLAIN shapes including the string-typed `rows`, a
  SQLite plan; the surprising-plan cases that must degrade to "no estimate"
  instead of panicking; threshold comparison; config resolution per engine).
  Envelope snapshots in `src/output.rs` (explain success / expensive /
  no-estimate, and the `EXPENSIVE_QUERY` refusal with its attached plan).
  End to end: `explain_on_sqlite_is_honest_about_having_no_estimate`,
  `explain_of_a_metadata_statement_says_there_is_no_plan` and
  `a_guardrail_mode_sqlite_cannot_honor_is_a_config_error` in `tests/cli.rs`
  (no Docker), `postgres_guardrail_and_explain_end_to_end` (the default
  threshold stops a real 10^12-row cross join, a configured threshold decides
  deterministically, `off` is off, metadata statements stay unguarded, and a
  recursive CTE runs with `GUARDRAIL_SKIPPED` while explaining as `no_estimate`)
  and `mysql_guardrail_and_explain_end_to_end` (rows mode on MariaDB, a tableless
  `SELECT 1` with no spurious warning, a view-only role whose query must keep
  working, the borrowed-and-returned server cap, `mode = "cost"` as exit 3).
  Thresholds in tests come from the config, never from timing — the one
  deliberately time-based case (planning that outruns its budget) is driven by
  const-folding work an order of magnitude past the budget, not by a race.
- The `max_row_limit` / `max_timeout_secs` ceilings: `Config::row_limit` /
  `Config::timeout_secs` resolution in `src/config.rs`
  (`ceilings_clamp_the_flag_the_config_and_the_built_in`: flag above/below the
  ceiling, a `[defaults]`-only ceiling, a stricter per-connection one, a
  configured value above its own ceiling, zero ceilings rejected) and
  `config_ceilings_clamp_the_flags` in `tests/cli.rs` (a `--limit 999999` that
  comes back TRUNCATED at 2 rows, a `--timeout 999999` that still stops at the
  1-second ceiling, and both flags unclamped when no ceiling is configured).
- `tests/postgres.rs` is the same for PostgreSQL against a testcontainers
  Postgres: success (json/table), row-limit truncation, DB_ERROR (exit 7),
  server-timeout (exit 8), CONNECTION_FAILED (exit 6, closed port), and a
  password-leak guard (a distinctive password must never appear in stdout/stderr).
  The container runs inside `block_on` so its async `Drop` (which removes the
  container) always has a runtime — even when an assertion unwinds.
- `tests/mysql.rs` is the same for MySQL/MariaDB against a testcontainers
  `mariadb:11.4` (a passworded `mysql_native_password` user over plaintext
  loopback, covering the password path and leak guard; the passworded-over-TLS
  path is proven separately by the `src/engine.rs` MySQL-8 TLS test): success
  (json/table),
  row-limit truncation, DB_ERROR (exit 7), timeout (exit 8), CONNECTION_FAILED
  (exit 6). The `engine = "mariadb"` path (`max_statement_time`) is exercised
  here; the MySQL `max_execution_time` path is in the `src/engine.rs` engine test.
- `src/engine.rs` holds the layer-2 proof for Postgres and MySQL: a write issued
  *directly* to the engine (bypassing the validator) is refused by the read-only
  transaction (`EngineError::Db`), the table stays intact, common types decode as
  documented, and a server timeout maps to `EngineError::Timeout` (not `Db`, so
  exit 8 is deterministic). The MySQL test (`mysql_layer2_types_and_timeout`,
  `mysql:8.4`) additionally covers `BIGINT UNSIGNED` at the u64 ceiling, structured
  `JSON`, `BIT`, full-range `TIME` (`-838:59:59`..`838:59:59` via `MySqlTime`), and
  `max_execution_time` → SQLSTATE 3024 → Timeout. `mariadb_server_timeout_maps_to_timeout`
  (`mariadb:11.4`) proves the sibling `max_statement_time` → SQLSTATE 1969 → Timeout
  directly, with no outer tokio timeout in play. **TLS is proven on both server
  engines:** `mysql8_caching_sha2_password_over_tls` (`mysql:8.4`) connects a
  passworded `caching_sha2_password` user over `ssl-mode=REQUIRED` and reads a
  row (the plaintext-only "MySQL 8 password needs TLS" limitation is gone); the
  Postgres test additionally asserts that `sslmode=require` against the (ssl=off)
  `postgres:16-alpine` container fails with a TLS-hinted `CONNECTION_FAILED` —
  proof that `require` is enforced by the rustls backend, not silently
  downgraded to plaintext.

## PII columns (`[connections.X.pii]`, steps PII-1 / PII-2)

The config owner marks `table.column` pairs as personal data. `mode = "deny"`
(the default, step PII-1) refuses any query that could expose them
(`NYET`/`PII_COLUMN`, exit 5); `mode = "mask"` (step PII-2) additionally lets a
plain projection through with every value replaced by `[REDACTED]`. The mode
lives in `PiiRules` itself, so both nets read the same single source.

### Two nets, both fail-closed

**Net A — names, before execution** (`src/validator.rs`, pure). Everything below
is the rule in BOTH modes; `mode = "mask"` carves out exactly one shape (a bare
unaliased projection of the column, in a statement that does not sort, group or
dedupe) — see "Masking" below. A pre-pass
(`TableScan::push_factor`) classifies EVERY table factor. From it `PiiScope`
builds the protected column names of the protected relations in scope, the
handles that stand for them, and the full relation-name set. The main `Checker`
walk then refuses:

- any `Expr::Identifier` / `Expr::CompoundIdentifier` whose terminal component
  is a protected column name — which covers projection, WHERE, JOIN ON, GROUP
  BY, HAVING, ORDER BY, subqueries and CTE bodies at once, because the visitor
  passes every expression in the tree through the same hook. Function calls,
  casts and operators need no special case: they are reached through their own
  sub-expressions, so `substr(email,1,3)` is caught by the inner `email`;
- `JOIN ... USING (col)` and `NATURAL JOIN`. `JoinConstraint::Using` holds
  `ObjectName`s **outside** the `Expr` tree and `Natural` holds nothing at all,
  so neither is reachable from `pre_visit_expr`. Both are a working equality
  oracle over the protected value — the agent brings its own dictionary
  (`FROM (users NATURAL JOIN (SELECT '<guess>' AS email) d)` answers 1 or 0).
  `Checker::check_joins` is applied from TWO hooks, which between them see every
  `TableWithJoins` in the statement exactly once: `pre_visit_select` for
  `select.from`, and the `TableFactor::NestedJoin` arm of
  `pre_visit_table_factor` for a parenthesised join, whose own `joins` live a
  level deeper and produce no `Select` of their own. Checking only the first was
  a bypass (`FROM (users JOIN dict USING (email))`). The local wildcard scope
  recurses into the same nested joins (`SELECT * FROM (users JOIN dict ON true)`
  expands `users` too);
- `TABLE t` — a whole-relation read whose name sqlparser keeps as a plain
  `String` inside `SetExpr::Table`, not as a `TableFactor` or even an
  `ObjectName`. No visitor hook reaches it, so it is walked explicitly from
  `query.body` (`set_expr_tables`, recursing through `SetOperation`) in
  `Checker::pre_visit_query`. `TableScan` walks it too, but that hook is
  REDUNDANT rather than load-bearing: the `Checker` refuses a protected
  `TABLE t` unconditionally and earlier, so the scan's only effect is adding
  unprotected names to `relations` — a widening of allow, with no deny case that
  discriminates it. It is only reachable as an operand of a set operation
  (`SELECT NULL UNION ALL TABLE users`), and left unhandled it switched net A
  off ENTIRELY — columns, wildcard, composite, alias-columns and the catalog
  denylist at once — while the server returned every column. `SetExpr` has no
  other variant carrying a relation outside a `TableFactor` (`Insert`/`Update`/
  `Delete`/`Merge` are already `WRITE_OPERATION`);
- a wildcard, judged against **the source it expands**, not the whole statement:
  `SelectItem::Wildcard` needs that select's own FROM to be rule-free, and
  `prefix.*` is safe when `prefix` provably names a relation with no rules. An
  unresolvable prefix inside a scope holding a protected relation fails closed.
  `count(*)` is a `FunctionArgExpr::Wildcard`, a different enum the visitor never
  surfaces as an `Expr` — which is why `SELECT count(*) FROM users` stays
  allowed, while `f(t.*)` (a `FunctionArgExpr::QualifiedWildcard`) does not:
  `json_agg(u.*)` really returns `{"id":1,"email":"..."}` — verified live on
  postgres:16-alpine. `Checker::check_function_args` is called from BOTH sides of
  the AST where a function can appear — the `Expr::Function` arm and the
  table-source arms of `pre_visit_table_factor` (`TableFactor::Table` with
  `args`, and `TableFactor::Function`, i.e. `FROM f(u.*)` /
  `FROM LATERAL f(u.*)`), which carry their `FunctionArg`s in a different field;
- a bare table name or alias used as a VALUE (PostgreSQL's whole-row composite
  `SELECT u FROM users u`);
- an alias COLUMN list on a protected relation (`users AS u (a, b, c)`), which
  renames columns positionally — nyet does not know the real column order, so
  which alias hides the protected column is unprovable;
- any table in this engine's `*_VALUE_SAMPLING_CATALOGS` whenever the connection
  has ANY rule. The list is **per dialect**, like `denied_prefixes`: a user table
  named `column_stats` on SQLite is a table, not MariaDB's histogram catalog.

**The root rule: classification is exhaustive, and "unknown" is not "absent".**
Three review rounds produced five separate bypasses — `FROM ONLY t`,
`FROM ONLY (t)`, `SetExpr::Table`, a parenthesised join, `f(t.*)` in table-source
position — and every one of them was the SAME defect: `push_factor` silently
ignored a shape it did not understand, `PiiScope` came out empty, and an empty
scope reads as "no protected relation here", which switches net A off wholesale
(columns, wildcards, USING/NATURAL, whole-row and the catalog denylist at once).
Two changes close the class rather than the instances:

1. `push_factor` matches `TableFactor` **exhaustively — no `_` arm**. A new
   variant in a future sqlparser breaks the BUILD instead of quietly reopening
   the hole. Each variant lands in exactly one of three buckets:
   - **named relation** (`Table`, once `relation_name` has resolved it) ->
     a `ScannedRelation`, whose columns net A can judge;
   - **wrapper** (`NestedJoin`, `Pivot`, `Unpivot`, `MatchRecognize`) -> recurse
     into the factor it wraps; the alias is remembered as a prefix only;
   - **opaque row source** (`Derived`, `Table` with `args` — i.e. a table
     function, `TableFunction`, `Function`, `UNNEST`, `JsonTable`,
     `OpenJsonTable`, `XmlTable`, `SemanticView`) -> only the alias is
     remembered, as a resolvable prefix, NEVER as a protected handle. Their
     columns come from their own body or arguments, which the rest of net A
     judges; what a *server-side* opaque source returns is the documented view
     limitation. Denying them outright would refuse `generate_series`,
     `unnest`, `json_table` on every PII connection for no proven gain.
2. `PiiScope` carries `unresolved` separately from an empty scope, and
   `active()` is true for either. A factor nyet could not identify refuses the
   statement (`PII_UNPROVABLE`) instead of reading as "nothing to protect".
   **Honest note:** with sqlparser 0.62 and the three dialects nyet ships,
   `unresolved` is currently unreachable — the only way `terminal_ident` fails
   is `ObjectNamePart::Function`, which only the Snowflake dialect produces. It
   is a guard for the next parser version, so no corpus case discriminates it
   (unlike the eleven rules that do); the exhaustive match is what actually
   holds the line today.

**A qualified wildcard is judged GLOBALLY.** `SelectItem::Wildcard` (bare `*`)
is judged against its own select's FROM, because that is what it expands. A
QUALIFIED wildcard names its source itself, so it does not need the local scope
— and using it was a bypass: a correlated sub-select has an EMPTY FROM, so
`SELECT count(*) FROM users u, LATERAL (SELECT u.*) s WHERE s.email LIKE 'a%'`
saw a local scope with nothing to protect while `u.*` copied every protected
column of the OUTER `users u` into a derived table whose alias is (correctly)
unprotected. The count form cleared BOTH nets — net B saw an `Expression` — and
was a working character-by-character oracle, exactly the channel net A refuses
`WHERE email LIKE` for. `check_function_args` already judged `f(t.*)` globally;
the two are consistent now.

**`relation_name` — one resolver, two disguises.** PostgreSQL's `FROM ONLY tbl`
(do not descend into inheritance children) has no representation in sqlparser
and arrives in two shapes, both of which the server runs as a plain read of
`tbl`: `ONLY tbl` becomes a table called `ONLY` **aliased** `tbl`, and
`ONLY (tbl)` becomes a **table function** called `ONLY` with `tbl` as its
argument. The second one was a complete exfiltration on PostgreSQL — verified
live, `SELECT most_common_vals FROM ONLY (pg_stats)` handed over the sampled
values of the protected column. Both are undone in `relation_name`, the single
function the scan AND the catalog denylist call, so the two can never again
agree on different names.

**Physical name vs alias.** A `ScannedRelation` stores the PHYSICAL table name
separately from the alias; the alias becomes a handle only once the physical name
is known to be protected. `FROM orders AS users` is therefore `orders`, whatever
it is called locally. PostgreSQL's `FROM ONLY tbl` — which sqlparser lands as a
table literally named `ONLY` with `tbl` as its alias, and which left the scope
empty and net A off while the server ran the real query — is undone explicitly in
`TableScan::push_factor` instead. The earlier "match on any of the names" fix
closed `ONLY` too, but cost a false refusal on every alias that happened to spell
a protected table name.

**What over-denial is still deliberate.** A relation whose own name is a
protected table's name is treated as that table, so a CTE or temp table called
`users` is refused on a connection with `users.*` rules. The AST *does*
distinguish them — `Query.with` carries every CTE's `alias.name` — so this is a
cost decision, not an impossibility: dropping those names correctly needs
LEXICAL scoping, and `PiiScope` is one flat scope for the whole statement. Both
naive versions are fail-OPEN:

- drop every CTE name -> `WITH users AS (SELECT * FROM users) SELECT * FROM users`
  loses the real table too;
- drop only CTE names whose body is clean ->
  `SELECT email FROM users WHERE id IN (WITH users AS (SELECT 1 AS x) SELECT x FROM users)`
  declares the CTE in a nested scope, so the name falls out of `handles`,
  `active()` goes false and the OUTER read of the real `users` sails through.

Real scoping costs more than this false refusal is worth. Documented in the
README instead, with the working way out (rename the CTE — qualifying does not
help, because the name is what the match keys on).

**Scopes are flat for COLUMN names, local for wildcards.** An *unqualified*
`email` is refused wherever it appears in a statement that reads a protected
table: without the schema nyet cannot prove ownership, and `WHERE email LIKE
'a%'` + `row_count` is a character-by-character oracle (over-denial is the only
safe direction, UX-1). A *qualified* `o.email` is different — `PiiScope::
prefix_is_safe` proves `o` names an unruled source, the same proof `o.*` already
relied on. Keeping the strict rule there forbade a strict subset of what the
wildcard rule allowed, while the data came back through `o.*` anyway. A wildcard
likewise expands exactly one source, so it is judged against that select's own
FROM — and `PiiScope::of_from` collects **only** the FROM's own sources (plus,
recursively, the ones inside wrapping factors), never descending into derived
bodies or the subqueries inside ON conditions: a visitor walk there refused
`SELECT * FROM (SELECT id FROM users) t` with a message that was simply untrue.

The same proof reaches derived tables: the alias of ANY source — including a
subquery, a VALUES list or a table function — goes into `relations`, so
`SELECT s.email FROM users u JOIN (SELECT contact AS email FROM signups) s ...`
is allowed. A derived table's columns can only come from its own body, which
net A judges separately, so the qualifier settles ownership exactly as it does
for a real table. Aliases never enter `handles`, so an alias that shadows a
protected table's name stays refused.

**Net B — provenance, after execution and before output** (`validator::Origin` /
`check_origins`). The engines translate the driver's `sqlx::ColumnOrigin` into
the pure `Origin` enum on the same `ResultSet` that carries the columns; the cli
judges. A `Table(t, c)` matching a rule is `PII_COLUMN`; an `Unknown` — or a
column with no origin entry at all — is `PII_UNPROVABLE`; `Expression` passes.

**Where net B lives, and why there.** In `main::Db::execute` — the ONE wrapper
all three engines and every command go through to get rows. It used to be a call
in the `query` branch, which is discipline, not a waist: `explain` never got it.
A refusal now becomes `QueryOutcome::PiiRefused`, so the enum's exhaustive match
forces every present and future caller to handle it. `explain` returns a plan
and no `ResultSet`, so net A alone applies there (its plan names relations, which
is schema-level — `nyet schema` exposes the same — never cell values).

**What net B is honestly worth.** It is a wire-level cross-check: it sees what
the server actually returned, which is how a divergence between nyet's parse and
the server's becomes visible. On PostgreSQL and MySQL/MariaDB the driver reports
a *view* as a view column's origin, so there it keys on the same names net A
checks; on SQLite it additionally resolves a *bare* view column to its base
table.

`Expression` is accepted, and that is a documented LIMIT, not a proof. A
computed column carries no provenance at all, so `contact || ''` over an
unlisted view slips past net B even on SQLite, where the bare `contact` is
caught — and, before net A learned about `SetExpr::Table`, so did every column
of `SELECT NULL,... UNION ALL TABLE users` (a base table with rules, no view
involved). Closing `Expression` WOULD have caught both. It was rejected on
**cost**: it refuses every aggregate, every computed column and every set
operation on every PII connection (UX-1), and it is not the root fix for either
bypass — both live in net A and are fixed there. The boundary that holds for
renaming layers is: list the view's own columns, and use column-level GRANTs.
`tests/cli.rs::pii_view_limitation_is_pinned_in_both_directions` pins both sides
so this cannot drift silently.

### What the drivers actually report (measured, sqlx 0.9, July 2026)

| engine | on the FETCH path | table naming | sees through a view? |
|---|---|---|---|
| SQLite (bundled) | full `Table(table, column)`, free | bare (`users`) | **yes** — `SELECT mail FROM v` reports `users.email` |
| MySQL 8.4 / MariaDB 11.4 | full `Table(db.table, column)`, free; the table ALIAS is resolved to the real name | `db.table` (`test.users`) | **no** — reports the view (`test.v_users`, `contact`) |
| PostgreSQL 16 | `Unknown` for real table columns, `Expression` for computed ones | — | — |

PostgreSQL is the odd one: sqlx calls `resolve_statement_metadata` with
`resolve_column_origin = false` on the `run`/fetch path, so the names are never
looked up (`PgColumn::relation_id()`/`relation_attribute_no()` — the wire
`RowDescription` oid+attnum — are always there, but the catalog lookup that turns
them into names is skipped). **Fix taken:** when the connection has a PII policy,
`Postgres::execute` calls `conn.prepare(sql)` once before the fetch. That path
DOES resolve origins, and it caches both the origin names and the prepared
statement on the connection, so the following fetch reuses the same PARSE and
reports `Table(table, column)` — verified against postgres:16-alpine
(`postgres_pii_policy_end_to_end` fails with `PII_UNPROVABLE` on
`SELECT id FROM users` if the prepare is removed). Cost: one extra DESCRIBE round
trip, paid ONLY by connections with a PII policy (`Postgres::resolve_column_origins`,
set in `open_session`). The alternative — reading oid+attnum and querying
`pg_attribute` ourselves — costs the same round trip and more code (Д5).
PostgreSQL names the table search_path-relative (`users`, `s.t`, `v`), which is
why matching ignores the schema qualifier.

Because two of the three engines report a VIEW as the origin, **views are a
documented limitation, not a bug**: a rule on `users.email` does not cover
`v_users.contact`. Both container tests pin the current behavior in both
directions (the view leaks under a base-table rule; listing the view closes it),
so a driver change that starts resolving through views turns the test red rather
than silently changing the guarantee.

**Testing net B.** A deny-only e2e exists on SQLite
(`pii_net_b_catches_a_renaming_view`). On PostgreSQL and MySQL none is known
*today* — but "net A refuses everything net B would" is an observation about the
current parser coverage, and it has been false twice. `FROM ONLY (users)` is the
clean example: sqlparser read it as a table function, net A saw no relation at
all, and on PostgreSQL the bare projection `SELECT email FROM ONLY (users)` was
refused by **net B alone** — the driver reported the origin as `users.email`
whatever the parser thought. That is exactly the divergence net B exists for
(and exactly why an expression wrapper, which carries no origin, got through it
until net A was fixed). What the container
tests pin there is net B **liveness**: `SELECT id FROM users` must exit 0 on a
PII connection, and if sqlx ever stops resolving origins the columns arrive as
`Unknown` and that line turns into an exit-5 `PII_UNPROVABLE`. The judging logic
itself is unit-tested (`net_b_judges_the_reported_provenance`).

### Masking (`mode = "mask"`, step PII-2)

**A cell is redacted only where BOTH nets agree — that is the whole design.**
Net A says which projection may be masked (`pii_exempt`: result-column indexes)
and net B proves from the driver's PROVENANCE that the result column really is
that protected column. `check_origins` returns the intersection, and
`Db::execute` replaces those cells — the one place rows leave the engine layer,
so the formatters, `meta`, the audit `response` and every future rows-returning
command see the masked `ResultSet` and nothing else can serialize a raw value.
Any disagreement REFUSES:

- promised but not proven -> `PII_UNPROVABLE` (the promise check below);
- proven but not promised -> refused exactly as under `deny`;
- `Unknown` -> refused in BOTH modes: a column nyet cannot identify could be the
  protected one, and there is no masking what you cannot name.

**Why net B does not mask on its own** (review round 6; this deliberately narrows
the original PII-2 sketch, where net B was to be "the source of truth" and mask
any protected origin). Net B knows MORE than net A — SQLite resolves a view
column to its base table — and a column net A never saw is one it could not judge
the `ORDER BY` / `DISTINCT` over: with `columns = ["users.email"]`, `SELECT id,
contact FROM v_users ORDER BY contact` came back fully redacted and perfectly
SORTED by the hidden value, and `SELECT DISTINCT contact FROM v_users` gave its
exact cardinality. `deny` refuses both. Masking only what net A sanctioned makes
the ordering guard complete BY CONSTRUCTION (it judges exactly the set that can
be masked), makes the three engines agree (PostgreSQL and MySQL never reported
through a view anyway), and turns "mask ⊆ deny" into a structural property rather
than a claim. The cost: `columns = ["users.email"]` no longer silently covers
`v_users.contact` on SQLite — and the fix is the one every engine already needed,
list the view's own columns.

**What net A relaxes, and why exactly that** (`validator::maskable_projection`).
Net A must not allow anything net B cannot then prove, so the relaxation is the
narrowest shape all three drivers resolve to a real `table.column`: a **bare,
unaliased column reference in the ROOT select's projection**. Each condition
closes a concrete channel:

- **bare** — `upper(email)` carries no provenance at all (net B sees an
  `Expression` and passes it through), so allowing it would return the real value
  transformed;
- **unaliased** — an alias is a second name for the value, and **SQLite accepts
  an output alias in `WHERE`** (`SELECT email AS e FROM users WHERE e LIKE 'a%'`),
  where net A can no longer recognise it. That is the character-by-character
  oracle the mask exists to prevent, so `ExprWithAlias` is not exempt;
- **root select only** — a derived table, a CTE or a UNION arm hands its column
  to another layer, and what a driver reports THROUGH that layer is precisely the
  documented view limitation. `SELECT x FROM (SELECT email AS x FROM users) t`
  must not become a laundering path;
- **no WILDCARD anywhere in that projection** (review round 6). `*` and `t.*`
  expand into as many result columns as the source has, so every item to their
  right sits at an index net A cannot compute — and the promise net B checks by
  index is then kept by the WRONG column while the exempted one goes out RAW.
  Measured: with two renaming views, `SELECT v_contacts.*, c.work_mail FROM
  v_contacts, v_crm c` masked the wildcard's `email` and returned `work_mail` in
  plaintext, exit 0, where `deny` refused the same statement. A qualified `t.*`
  is NOT caught by the wildcard rule when `t` provably carries no rules (that is
  the PII-1 false-refusal fix), so it had to be handled here. Refusing the
  combination is what makes "the n-th projection item is the n-th result column"
  TRUE — the invariant the whole promise rests on — and it gets its own refusal
  (`pii_mask_wildcard_deny`), because the fix is "list the columns", which no
  other PII message says. **`SelectItem` has FIVE variants in sqlparser 0.62**,
  not four: besides the two wildcards and the two scalar forms there is
  `ExprWithAliases` (`expr AS (a, b)`), which is ALSO a multi-column expansion.
  It is parsed only by dialects whose `supports_select_item_multi_column_alias()`
  is true (Spark/Databricks/Generic) — none of the three nyet ships, and
  `GenericDialect` is not used anywhere in the crate — so it cannot reach the
  projection today; adding a dialect means adding it to that match.

Sorting, grouping and dedup are a property of the STATEMENT, not of the node, so
they are judged separately (`mask_ordering_conflict`, below) and refuse with
their own text.

Everything else — the wildcards in every spelling, the composite whole row,
`TABLE t`, `USING`/`NATURAL`, the alias column list, the value-sampling catalogs,
the unresolved source — keeps its `deny`-mode refusal in mask mode, and the
corpus re-pins all nine PII-1 holes under `pii_mode: mask`
(`tests/corpus/*_pii_mask.yaml`) precisely so relaxing the projection cannot
reopen one.

**The relaxation is per OCCURRENCE, not per name**, and that is why the exempt
set is a set of node ADDRESSES (`std::ptr::from_ref(expr).addr()`), collected
from the root projection before the walk and consulted in `check_pii_expr`. The
same `email` is masked in the projection and refused in the `WHERE` of one
statement, so the rule cannot key on the name — and it cannot key on the value
either: `WHERE email = 'x'` holds an `Expr::Identifier` structurally EQUAL to the
projected one. The AST is borrowed immutably for the whole validation, so a
node's address identifies it exactly.

**Whole-row reads stay refused under mask, deliberately.** Net B *could* mask the
protected columns of a `SELECT * FROM users` (it knows every column's origin), so
this is a choice, not a limit: `*`, `t.*`, the PostgreSQL composite `SELECT u
FROM users u` and `TABLE users` are one family in the agent's head, and only the
first of them has provable per-column provenance — the composite arrives as a
single `Expression`-origin value with every column inside it, and `TABLE t` is a
whole-relation read nyet judges before it ever sees columns. Masking one spelling
while refusing three would be a rule an agent cannot learn from a refusal. The
refusal hint says to name the columns, `nyet schema` marks which ones are
protected, and naming them is exactly the shape the mask supports.

**Generated columns are a renaming layer inside the protected table itself**
(measured on PostgreSQL, both modes, and a PII-1 behaviour rather than a
regression): `gen GENERATED ALWAYS AS (upper(email)) STORED` carries its own
provenance (`users.gen`), which no rule names, so `SELECT gen FROM users` returns
the derived value and `WHERE gen LIKE 'A%'` is a working character oracle. Nastier
than a view because it lives in the very table the owner believes is protected —
listed in the README limits with the fix (name the derived column in `columns`
too).

**A masked NULL is `[REDACTED]`, not `null`.** Keeping NULL would answer "is this
person's phone on file?" for every row — a one-bit oracle per cell, over the very
column being protected, available without any filter. So `output::redact`
replaces the whole cell for every type, and the direct consequence is documented
rather than hidden: **the JSON type of a masked column becomes `string`**
whatever the column's real type is (number, date, JSON). The `PII_MASKED` warning
is what makes that legible to the agent — it names the columns (never values,
never a count, since every row of the column is replaced anyway) and says the
type and length are gone too. `output::REDACTED` is a const, not a config key
(Д5): a configurable mask string is another way to leak (a per-column string
would fingerprint the column) and buys nothing.

**The exemption is a PROMISE, and net B enforces it (review round 5).** Net A
relaxes a projection *on the understanding that net B will redact it*, so
`Verdict::Allow` carries `pii_exempt` — the RESULT-column indexes it let through
— and `check_origins` refuses (`PII_UNPROVABLE`) any exempted index it did not
mask. Without that the promise was silently breakable, and two agent-reachable
ways to break it were found in review, one of them critical:

- **the README's own view recipe, on SQLite.** With `columns =
  ["v_users.contact"]`, net A protects the VIEW's column while SQLite resolves
  the origin to the BASE table (`users.email`), which no rule names — so nothing
  matched, nothing was masked, and `SELECT contact FROM v_users` returned the
  plaintext value, NULLs included, with no warning. The same config under `deny`
  refuses that query: turning `mode = "mask"` on was *removing* protection, the
  one defect class UX-1 forbids outright;
- **a CTE shadowing the protected table's name.** `WITH users AS (SELECT
  'secret' AS email) SELECT email FROM users` keeps the scope active (the name
  is what net A matches on), so the projection was exempted while the value is a
  computed expression with no provenance at all. Harmless in itself — the value
  is the agent's own literal — but it is the mechanism the first case exploits,
  which is exactly why "only a driver regression could produce this" was wrong.

**"mask ⊆ deny" is a structural property, not a claim in prose.** Net A's mask
branch fires only where the deny branch would have refused (it lives inside the
`columns.contains` arm), net B masks nothing net A did not sanction, and the
extra refusals (unkept promise, wildcard conflict, ordering conflict) fire only
on statements `deny` refuses too. Therefore: every cell `mask` redacts belongs to
a query `deny` refuses outright, every query BOTH modes allow returns
byte-identical rows, and `mask` never returns a value `deny` would have withheld.
Anything that breaks that reads as a leak — which is how both review rounds found
their bugs.

The rule is the STRICT one ("an exempted column must come back masked"), not the
narrower "refuse only an `Expression` or a foreign relation": it costs nothing
against `deny`, because net A only ever exempts an occurrence it would otherwise
have REFUSED. The earlier objection (`SELECT email FROM orders o JOIN users u
...`, where the origin says `orders.email` and nothing is protected) does not
apply for the same reason — that statement is refused under `deny` too, as the
documented unqualified-name over-denial. Pinned by
`net_b_refuses_an_exempted_column_it_did_not_mask`,
`pii_mask_refuses_when_it_cannot_keep_its_promise` and, on live drivers, in both
container tests (PostgreSQL reports the VIEW, so there the same recipe masks
correctly — the test pins both sides).

**What sorting/grouping costs, and why the check is a DENYLIST.** A statement
that SORTS, GROUPS or DEDUPES while a maskable column is projected is refused by
`mask_ordering_conflict`, with its own message and hint (Д10: the fix is "use a
column name", which the generic "do not name this column" text never says). The
rule: while anything is maskable, an `ORDER BY`/`GROUP BY` key is accepted ONLY
when it is a plain `Expr::Identifier`/`CompoundIdentifier` — a NAME, which
`check_pii_expr` judges like every other name, in both modes, so a protected one
is refused there. `DISTINCT` conflicts unconditionally (it dedupes on the values
themselves).

The first two shipped versions were ALLOWLISTS ("refuse a key that is a
position"), and both were wrong — not by an oversight but in principle: deciding
which expressions a planner folds into an ordinal is a per-engine, per-VERSION
question the AST cannot answer. A fuzz of 47 spellings against live servers found
twelve holes in the second version alone: `0x1`/`0x2` are ordinals on SQLite AND
on PostgreSQL 16 (which added non-decimal integer literals), `0_1` is one on
PostgreSQL (digit separators), `-(-2)` on both, and `2 COLLATE NOCASE` /
`(2) COLLATE BINARY` on SQLite — while `1+0`, `2.0`, `'2'`, `2e0`, `abs(2)` and
`CAST(2 AS INT)` are ordinals nowhere. Each miss sorted the result by the real
value of a redacted column (`ORDER BY 0x2 DESC LIMIT 1` = "the row with the
largest email") or handed over its exact distinct count. The denylist needs none
of that knowledge and cannot go stale with the next server release.

Cost, deliberate: under `mode = "mask"`, and only in a statement that plainly
projects a protected column, sorting and grouping take column names only —
`ORDER BY id`, `ORDER BY u.created_at DESC`, `GROUP BY id` all work (that is the
case this guard was narrowed for), while `ORDER BY 1` and `ORDER BY lower(name)`
are refused. An output ALIAS would be a third route into the masked column on
SQLite/MySQL, and it cannot occur: an aliased projection item is never maskable.

**The row ORDER is a residual channel nyet cannot close** (measured, README's
honest limits): with an index on the protected column the engine may return rows
in ITS order for free — `SELECT id, email FROM users` came back ordered by
`email` off a covering index on SQLite and MySQL 8.4. No `ORDER BY` is involved,
so there is nothing to refuse short of forbidding the projection entirely, which
is the feature. The values stay hidden; their relative ORDER can leak.

### `nyet schema` marking and the `pii_columns` doctor check

Both are cli-layer wiring over pure functions, because the policy is CONFIG and
the engines only report what the catalog holds:

- `output::mark_pii(&mut Schema, mode, protects)` takes a predicate rather than
  `PiiRules`, so `output` keeps its single dependency (serde) and no
  `output -> validator` edge appears. It runs after the engine's
  privilege filter, so a column the role cannot read is never marked — it is not
  in the payload at all. The field is `pii: Option<&'static str>`, omitted when
  absent (UX-4: every byte is the user's money).
- The doctor check is `Engine::diagnose(pii)` -> `Vec<PiiAccess>` (a FACT per
  rule: readable yes/no/unknown) -> the pure `output::pii_columns_check`, and it
  is emitted ONLY when the connection has a policy (an `na` line on every
  ordinary connection is noise, UX-4). PostgreSQL asks
  `has_column_privilege($1, $2, 'SELECT')` with the names BOUND (a name is data,
  not SQL — the same rule as `nyet schema`); a rule naming something that does
  not exist raises, which is `None` = "could not verify", not `false`.
  MySQL/MariaDB has no such function: `information_schema.COLUMNS` is
  privilege-filtered BY the server, so a VISIBLE column answers "readable"
  outright — but an INVISIBLE one is ambiguous ("not granted" vs "no such
  column"), and reading a typo as "the database enforces it" turns a rule that
  protects NOTHING into a green check. So the ambiguous case asks the server
  directly with `SELECT \`col\` FROM \`tbl\` WHERE 0` and reads the ERROR
  NUMBER: 1143/1142 (SELECT denied for the column/table) = the grant is doing its
  job -> `false`; 1054/1146 (unknown column/table) or anything else -> `None`,
  the same verdict PostgreSQL produces. **Residual, documented in the README:**
  MySQL answers "denied" BEFORE it checks existence, so for an account that
  already lacks the grant — the recommended least-privilege one — a misspelled
  rule still reads `ok` rather than "could not verify"; every metadata path is
  privilege-filtered, so there is no cheap way to ask "does this column exist?"
  as an account that may not see it, and saying so is better than implying a
  check nyet cannot make. That statement is the ONE place a config
  name reaches SQL text (MySQL cannot bind an identifier): it is backtick-quoted
  with the backtick doubled, the key is literal-only so the agent cannot
  influence it, and it reads no rows. SQLite is `na`: no roles, and the check
  says plainly that nyet is then the only thing enforcing the policy. A readable
  column is a `warn`, never a `fail`: the policy still holds for everything going
  through nyet, which is what the config owner asked for — the warn's job is to
  say the boundary is nyet ALONE, with the column-grant recipe (UX-7).

### Database errors are withheld

`main::db_error_withheld`. PostgreSQL and MySQL quote the offending CELL VALUE in
their messages (`invalid input syntax for type integer: "alice@example.com"`,
`Incorrect string value: 'a@b.c' for function uuid_to_bin`) — an exfiltration
channel of one cell per query that no filter on the RESULT can see, and one that
does not need to name a protected column (route it through a view). On a
connection with any PII rule, `EngineError::Db` is replaced wholesale before it
reaches the envelope; `Connect` and `Timeout` messages are curated constants and
are left alone. **No regex filtering** — that would be theatre (UX-7) and would
fail the first time a driver phrases a message differently. The SQLSTATE class is
not surfaced either: on its own it is not actionable enough to be worth a new
envelope field (`nyet schema` answers the questions the message would have).
Connections without a PII policy are byte-for-byte unchanged, verbatim error
included (pinned by `without_a_pii_section_nothing_changes`).

`nyet doctor` never goes through `run_db`/`engine_failure`, so
`main::redact_diagnosis` applies the same rule to the facts it collected: the
write PROBE runs a statement against real data, so its `detail` is replaced,
while the VERDICTS stay intact (which check failed and whether the role is
read-only is diagnosis, not data). `ConnectFact::Failed` is deliberately left
verbatim — symmetric with `engine_failure`, which also passes
`EngineError::Connect` through: a refused handshake happens before any row
exists and cannot quote a cell, and telling the human why the connection is
broken is doctor's entire job. The four independently derived
`redact_db_errors` locals that let doctor slip through are now one accessor,
`Session::redact_db_errors`.

Measured while choosing the leak-guard fixtures: PostgreSQL echoes the value on
any failed input conversion; MySQL 8.4 echoes it from `UUID_TO_BIN` (error 1411);
MariaDB 11.4 in its default `sql_mode` downgrades most cast failures to warnings,
so its e2e asserts the redaction itself (the raw text must not appear) rather
than a value echo.

### Audit and the pipeline point

`Event.sql` keeps the RAW agent text even under a PII policy: the log is
forensics for the HUMAN, the file is 0600, and the point of the record is showing
what the agent TRIED — including the query that was refused for naming a
protected column. `Event.response` (only under `[audit] log_responses`) is built
from the `ResultSet` AFTER both nets have passed — and after the mask has been
applied, since the redaction happens inside `Db::execute` — so it can only ever
hold what the agent also received, `[REDACTED]` included
(`pii_mask_is_audited_without_the_data`, plus the leak guard in both container
tests: the real value appears in neither stream nor the log). A refusal logs
`verdict: "refused"`, `reason: "PII_COLUMN"` and no response at all
(`pii_refusals_are_audited_without_the_data`).

### Module edges

`PiiRules` holds two pieces of state and nothing else: the `(table, column)` pair
set and the `mode`. "Which tables are protected" and "is this scope active" are
derived on the fly, because a cached copy is exactly what a later edit
desynchronizes into a fail-OPEN net A. The mode lives HERE rather than in
`Policy` so both nets and every refusal hint read one source (a hint that
described the wrong sanction would be worse than no hint).
`PiiRules::parse` rejects anything that could never match an identifier (a
comma-separated list crammed into one entry, a stray quote): a rule that is
accepted but can never fire leaves the config owner believing a column is
protected while every query returns it — silently worse than a rejected rule. A
fully double-quoted part is taken verbatim (`"users"."e-mail"`), so a name that
cannot be written bare is protectable at all; matching stays case-insensitive
there too (over-matching, the safe direction).

`PiiRules`, `Origin`, `Refusal` and `check_origins` live in `validator.rs` — still pure,
still sqlparser + std only. `engine.rs` imports `validator::Origin` to translate
`sqlx::ColumnOrigin`; that is one more leaf→leaf edge of the same kind as
`engine -> guardrail` and `engine -> output` (the stable pure type is defined
once, the IO adapter fills it in). `config.rs` calls `validator::PiiRules::parse`
from `config::pii` — the same single-entry-point pattern as `config::guardrail`:
called at parse time so a malformed rule is a loud exit 3, and again by the cli
to get the value. No new dependency (Д8).

### PostgreSQL `*_to_xml` — a function-denylist hole, wider than PII

Found while reviewing PII-1, but **not a PII defect**: it predates this step and
applies to every connection, policy or not. Fourteen `pg_catalog` functions —
`query_to_xml`, `table_to_xml`, `schema_to_xml`, `database_to_xml`,
`cursor_to_xml` plus their `*_to_xmlschema` / `*_to_xml_and_xmlschema` variants
— are built in, need no extension, and are callable by a plain `GRANT SELECT`
role. Two separate powers:

- `query_to_xml('<sql>', ...)` **executes a SQL string sqlparser never sees**,
  which re-enables the entire function denylist: measured,
  `query_to_xml('select pg_sleep(3)', ...)` slept 2985 ms and exited 0 while
  `pg_sleep` itself is denied. (Layer 2 still holds — `nextval` inside the
  string is refused by the read-only transaction.) Same class as `dblink`.
- `table_/schema_/database_/cursor_to_xml` dump a whole relation, schema or
  database **without naming a column**, so net A has nothing to match and net B
  sees an `Expression`.

Fixed by ENUMERATING all fourteen in `POSTGRES_DENIED_FUNCTIONS` rather than by
a substring match on `_to_xml`: it reuses the existing mechanism (the family
shares a SUFFIX, and `denied_prefixes` cannot express that), the family has been
closed since PostgreSQL 8.3, and enumeration keeps `validator.allow_functions`
as the documented escape hatch — the same trade already made for `pg_sleep`. A
substring matcher would be a second, non-tunable mechanism for one family.

**Are there other built-ins that execute a SQL string?** Reviewed: no. `dblink*`
(prefix-denied) and this family are the only ones. `pg_get_viewdef` /
`pg_get_functiondef` / `pg_get_expr` return DDL TEXT without executing it;
`xpath`/`xmltable` take XML, not SQL; `format()` cannot execute; `EXECUTE`,
`DO` and `CALL` are statements, refused by the top-level allowlist. MySQL's
`PREPARE`/`EXECUTE` are likewise statements, and SQLite has no equivalent — so
the fix is PostgreSQL-only.

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
`WRITE_OPERATION`, `TXN_CONTROL`, `LOCKING_CLAUSE`, `DENIED_FUNCTION`,
`EXECUTABLE_COMMENT`, `EXPLAIN_ANALYZE`, `PII_COLUMN`, `PII_UNPROVABLE`);
optional `warnings` on an allow case is the comma-joined list of expected
warning codes (currently only `UNICODE_STRIPPED`) — allow cases without it
must produce none, deny cases never carry warnings; optional `dialect`
defaults from the **filename prefix** — `postgres_*.yaml` runs the PostgreSQL
dialect + `Policy::postgres`, `mysql_*.yaml` the MySQL dialect + `Policy::mysql`
(MariaDB is dialect-identical), everything else SQLite + `Policy::sqlite` — and a
per-case `dialect: postgres|mysql|sqlite` still overrides. A `pii:` line placed
BEFORE the first `- query:` sets the file-wide PII policy (comma-separated
`table.column` rules, exactly what `[connections.X.pii] columns` holds), and a
per-case `pii:` overrides it — `pii: none` turns it off for one case, so a file
can pin both sides of the same query. Absent everywhere = no PII policy.
`pii_mode: deny|mask` works the same way (file-wide line, per-case override);
absent = `deny`, so every pre-PII-2 file keeps its meaning. The `*_pii_mask.yaml`
files are the mask twins of the `*_pii.yaml` ones — same statements, one mode
apart.
Unknown lines fail the run loudly. The runner (`validator::tests::golden_corpus`) reads every `*.yaml` in
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
- **the advisory-lock family, all 11 `pg_catalog` names** — `pg_advisory_lock`,
  `pg_advisory_lock_shared`, `pg_advisory_unlock`, `pg_advisory_unlock_shared`,
  `pg_advisory_unlock_all`, `pg_advisory_xact_lock`, `pg_advisory_xact_lock_shared`,
  `pg_try_advisory_lock`, `pg_try_advisory_lock_shared`, `pg_try_advisory_xact_lock`,
  `pg_try_advisory_xact_lock_shared` (the list is exactly what `pg_proc` holds —
  read off the catalog, not from memory, and identical on **16.14 and 18.4**).
  Taking a lock is not a read, and no legitimate agent task needs one. Two reasons,
  both measured:
  - **a SESSION advisory lock survives `ROLLBACK`.** Measured on `postgres:16-alpine`:
    `pg_try_advisory_lock(77)` inside `BEGIN TRANSACTION READ ONLY` left
    `count(*) FROM pg_locks WHERE locktype='advisory'` at **1** after the abort, in
    the next transaction — layer 2 does not touch it, only the backend dying frees
    it. Today nyet opens one connection per invocation, so the lock dies with the
    process; the day connections are reused (connection TTL / daemon), an agent
    would accumulate session locks and could block other applications on the same
    database — a write-shaped effect from a read-only tool.
  - **the blocking forms hang until `statement_timeout`.** Measured on the same
    server: with key 4242 held by another session, `pg_advisory_lock(4242)` under
    `statement_timeout = '2s'` waited the full two seconds and died with *"canceling
    statement due to statement timeout"* (1.96 s wall). It ties up the connection for
    as long as the server allows — the `pg_sleep` DoS class, already denied.
- **transactional variants (`*_xact_*`) are denied too**, deliberately. They *are*
  released at COMMIT/ROLLBACK, so they survive no reuse; but the blocking ones hang
  exactly like the session ones, the `pg_try_` ones still hold a lock other
  applications wait on for the life of nyet's transaction, and one rule ("nyet never
  takes a lock") is a rule the agent can learn — "advisory locks are denied except
  the transactional non-blocking ones" is not. The false-refusal cost (UX-1) is zero:
  no read needs any of them.
- `pg_advisory_unlock*` are harmless on their own (nyet can no longer hold a lock, so
  they are a no-op returning false), and denied for the same reason MySQL's
  `release_lock` is: the whole family is one rule, and an agent read never calls one.

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

The advisory family is **enumerated**, following the `*_to_xml` precedent rather
than adding `pg_advisory` + `pg_try_advisory` prefixes: the 11 names were read off
the live catalog on two majors (16.14 and 18.4 — byte-identical sets), so the
enumeration is provably complete on every version nyet is likely to meet, and the
family has been stable for many releases (the `_xact_` variants arrived in 9.1 —
that date is from the release notes, not measured here); it reuses the existing
mechanism; and `allow_functions` stays reachable for a config owner who
really does want one of them on one connection. The cost of that choice is pinned
in the corpus — `SELECT pg_advisory_lock_report()` (a user function that merely
starts the same way) is an **allow** case, and switching to a prefix would break
it on purpose.

Deliberately *not* denied: reading lock STATE. `SELECT … FROM pg_locks` takes
nothing and stays allowed (allow case in `postgres_allow.yaml`) — the rule is
about acquiring locks, not about observing them.

Other ways to grab a lock, all closed elsewhere and pinned in the corpus:
`SELECT … FOR UPDATE`/`FOR SHARE` → `LOCKING_CLAUSE` (`FOR NO KEY UPDATE` /
`FOR KEY SHARE` are not parsed by sqlparser at all → `PARSE_FAILED`, fail closed);
`LOCK TABLE` (PostgreSQL) and `LOCK TABLES` / `FLUSH TABLES WITH READ LOCK` (MySQL)
are not reads → `WRITE_OPERATION`; `EXPLAIN ANALYZE` executes and is refused;
`query_to_xml('select pg_advisory_lock(1)', …)` is denied with the rest of the
`*_to_xml` family. SQLite has no advisory-lock function at all (its locking is
file-level and driven by transactions/`PRAGMA locking_mode`, and every `PRAGMA` is
already refused), so there is nothing to add there.

## Function denylist rationale (MySQL/MariaDB)

Like Postgres, these act *outside* the read-only transaction (filesystem, a
tied-up connection, or process execution via a UDF), so layer 2 does not stop
them — the validator (layer 1) is the only guard. All enumerated by exact name
(no clean shared prefix), all `DENIED_FUNCTION`, all config-tunable via
`allow_functions` / `deny_functions`:

- `load_file` — reads any server file into a string (needs the FILE privilege
  and `secure_file_priv`, but denied regardless: defense in depth, the
  MySQL analogue of `pg_read_file`).
- `sleep` — `SLEEP(seconds)`: silent DoS that ties up a pooled connection
  (the `pg_sleep` analogue).
- `benchmark` — `BENCHMARK(count, expr)`: a CPU busy-loop, DoS.
- `sys_exec` / `sys_eval` — the `lib_mysqludf_sys` UDFs: run a shell command
  (RCE) if that extension is installed. Non-standard, but denied so a
  compromised/legacy server with the UDF present is not a foothold.
- `get_lock` / `release_lock` / `release_all_locks` — the named-lock family.
  `GET_LOCK(name, -1)` blocks the connection **forever** waiting for a lock: a
  silent DoS, the same class as `SLEEP`. `release_*` are non-blocking but denied
  for completeness (an agent read never needs any of them). Same rule as the
  PostgreSQL advisory family above: nyet never takes a lock, in any engine.
  (`is_used_lock` / `is_free_lock` are pure non-blocking reads — they inspect lock
  state without taking or waiting for anything — and stay **allowed**, pinned as
  allow cases in `mysql_allow.yaml`. Measured on `mysql:8.4`: both return in
  microseconds and take nothing — `is_free_lock('x')` = 1 and `is_used_lock('x')` =
  NULL while the name is free, 0 / the holder's connection id after a `GET_LOCK`. MySQL's named-lock family is exactly these
  five functions; there is nothing else to add.)
- `master_pos_wait` / `source_pos_wait` / `master_gtid_wait` /
  `wait_for_executed_gtid_set` / `wait_until_sql_thread_after_gtids` — the
  replication-wait family: each blocks until a replica reaches a binlog/GTID
  position (unbounded DoS). `master_gtid_wait` is MariaDB-specific.

`INTO OUTFILE` / `INTO DUMPFILE` (writing a server file from a `SELECT` — the
sharpest MySQL vector, and the validator is the only guard) is not a function —
it is caught structurally: sqlparser's `MySqlDialect` fails to parse them under
the read allowlist, so they fail closed as `PARSE_FAILED` (pinned in the corpus).

**Executable comments are the sharpest MySQL bypass** and are handled *before*
parsing, not by the denylist. MySQL runs the body of `/*! ... */`, `/*M! ... */`
(MariaDB) and optimizer-hint `/*+ ... */` comments, but sqlparser discards them
as ordinary comments — so `SELECT 1 /*! SLEEP(10) */` reaches the AST as
`SELECT 1` while the server runs `SLEEP`, and `/*! ... INTO OUTFILE ... */` writes
a file: the entire layer-1 policy (denylist, INTO OUTFILE, locking) is bypassed.
`has_mysql_executable_comment` (pure, string-aware — a `/*!` inside a `'…'`/`"…"`
string or a `` `…` `` identifier is data, not a comment) flags these openers
outside literals and the validator denies with `EXECUTABLE_COMMENT`. MySQL-only:
Postgres/SQLite do not execute comment bodies.

**Why two scan passes.** The validator runs before connecting, so it does not
know the server's `sql_mode`, which changes where a string *ends*: under
`NO_BACKSLASH_ESCAPES` a `\` is literal (`'x\'` closes the string), and under
`ANSI_QUOTES` `"` is an identifier with no `\` escape (`"x\"` closes). A single
default-mode pass **under-denies** — it thinks the string runs past a `/*!` the
server actually executes (e.g. `… name='x\' AND 1=1 /*! OR SLEEP(5) */ …`). So
`scan_executable_comment` is parameterized by `backslash_escapes` and run twice
(`true` and `false`); the validator denies if EITHER pass finds an opener outside
a literal. The real server matches exactly one pass on the backslash question
(and the escape-free pass also models `ANSI_QUOTES` `"`-identifiers), so any
executed opener is caught by at least one pass — fail closed under every
`sql_mode`. Doubling (`''`/`""`/`` `` ``) is mode-independent and applied in both.
The acceptable cost is over-denial of a benign string that contains a backslash
right before a `/*!` (both corpus attack cases are pinned in `mysql_deny.yaml`).

Deliberately *not* included: `is_used_lock` / `is_free_lock` (pure reads).
`SLEEP`/`BENCHMARK`/`GET_LOCK` being denied means the timeout integration tests
use a heavy `information_schema` cross join instead. Add a new entry with a
failing corpus case first (Д6).

**Known representation choices (documented, not bugs):** `TIMESTAMP` decodes to
the value in the connection's session time zone rendered as a naive string
(no offset) — nyet does not pin a session `time_zone`, so a `TIMESTAMP` reads
back in the server default; use `DATETIME` or `CONVERT_TZ`/`UNIX_TIMESTAMP` if
you need an unambiguous value. `TIME` decodes via `sqlx::mysql::types::MySqlTime`
(not `chrono::NaiveTime`) and stringifies as `[-]H:MM:SS[.ffffff]`, covering
MySQL's full duration range (`-838:59:59`..`838:59:59`, negative / over 24h) that
`NaiveTime` cannot hold — a normal such column would otherwise DB_ERROR. `BIT`
decodes to a lossless integer (sqlx reads it big-endian into a `u64`); a hex
string would need the raw bytes (sqlx keeps them `pub(crate)`) and the bit-width
(dropped from the type name).

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
  a working Docker daemon, so the testcontainers Postgres/MySQL/MariaDB tests run
  for real (they pull `postgres:16-alpine`, `mysql:8.4`, `mariadb:11.4` and the
  SSH bastion image over the runner's network). Nothing is weakened — the same
  suite CI runs is the one you run locally with Docker up.
- **deny** — `EmbarkStudios/cargo-deny-action` with `deny.toml`
  (advisories, license allowlist, bans, sources).
- **audit** — `cargo audit` against the RustSec advisory DB
  (installed via `taiki-e/install-action`).

## Release process (`dist` + `.github/workflows/release.yml`)

Releases are built by [`dist`](https://github.com/astral-sh/cargo-dist) (the
Astral fork of cargo-dist). Config lives in `dist-workspace.toml` (`[dist]`
table) and the generated pipeline in `.github/workflows/release.yml`.

- **Crate `nyetdb`, binary `nyet`** (`[[bin]] name = "nyet"`).
- **Trigger: a `v*` version tag only** (`pr-run-mode = "skip"` — no PR/branch
  runs, so the release workflow never interferes with the main CI or publishes
  before a tag). Pattern: `**[0-9]+.[0-9]+.[0-9]+*`, e.g. `v0.1.0`.
- **Artifacts** (`dist plan` to preview): per-target `.tar.xz` for
  `{aarch64,x86_64}-{apple-darwin,unknown-linux-gnu}` (each with the `nyet`
  binary + `LICENSE-*` + `README.md` + a checksum), a shell installer
  (`nyetdb-installer.sh`, `curl | sh`), and a Homebrew formula (`nyetdb.rb`).
  Windows is intentionally not released (SSH tunnels / some tests are unix-only).
- **Homebrew tap:** `tap = "stasmarkin/homebrew-tap"`, `publish-jobs = ["homebrew"]`.
  The tap repo is **not** created or pushed by this step (a release act); the
  publish job needs a `HOMEBREW_TAP_TOKEN` repo secret with write access to the tap.
- **npm wrapper:** placeholders live in `packaging/npm/` but are **not** wired
  into `dist` yet (backlog; ROADMAP v0.3 item 12) — connecting dist's npm
  installer would generate its own package and needs an npm scope/token.

Regenerate the workflow after editing `[dist]` config: `dist init --yes` (writes
config + `[profile.dist]`) then `dist generate` (rewrites `release.yml`).

> **`dist generate` overwrites `release.yml` — re-apply three hardenings after it
> (Д8), dist does not emit them:** (1) pin every `uses:` to a full commit SHA
> (dist writes floating `@v4` tags); (2) drop the workflow-level `permissions`
> to `contents: read` and give only the `host` job `contents: write` (dist writes
> `contents: write` at the workflow level, so every job — including the
> unprivileged build jobs — would get write); (3) tighten the tag trigger to
> `v[0-9]+.[0-9]+.[0-9]+*` (dist's default `**[0-9]+.[0-9]+.[0-9]+*` also matches
> bare `0.0.1` / `releases/0.0.1` tags — require the `v` prefix). The release job
> is privileged (`contents: write` + `HOMEBREW_TAP_TOKEN`), so the current
> `release.yml` already carries all three; a regenerate reverts them. dist 0.28
> has no option to emit SHA pins, per-job permissions or a custom tag regex, so
> this is a manual post-step. Because the hand-edits make `release.yml` differ
> from dist's own output, `[dist] allow-dirty = ["ci"]` is set in
> `dist-workspace.toml` — otherwise the release pipeline's own `dist plan` job
> would fail its "CI out of date" check and abort every release.
>
> One thing NOT to add: keep `persist-credentials: false` off the
> `publish-homebrew-formula` checkout (it `git push`es to the tap and needs its
> credentials); it belongs only on the read-only build/host/announce checkouts.
>
> **Accepted risk (dist bootstrap):** the release jobs install the `dist` binary
> with `curl … | sh` over HTTPS from dist's GitHub releases, without an
> independent SHA-256 of the installer. dist 0.28 offers no installer checksum
> verification; the mitigation is the pinned `cargo-dist-version = "0.28.7"` (the
> version, hence the artifact set, is fixed) plus HTTPS/TLS transport. Revisit if
> dist adds installer attestation, or vendor a pinned `dist` binary. Flagged for
> the maintainer to accept vs. harden.

**What a human does to cut a release (not automated, on purpose):**

1. **Bump `version` in `Cargo.toml` to the release version (e.g. `0.1.0`)
   *before* tagging** and update `Cargo.lock`; commit. dist requires the package
   version to equal the tag version — a tag `v0.1.0` on a `0.0.1` `Cargo.toml`
   fails the `plan` job. *(nyet ships at `0.0.1`; the `0.1.0` bump is the release
   act — do not bump it ahead of time.)*
2. `git tag v0.1.0 && git push origin v0.1.0`.
3. The `release.yml` pipeline builds the artifacts, creates the GitHub Release,
   and (with `HOMEBREW_TAP_TOKEN` set) opens/updates the formula in the tap.
4. First release only: create the `stasmarkin/homebrew-tap` repo and add the
   `HOMEBREW_TAP_TOKEN` secret; publish crates.io / npm separately if desired.

## Error codes (closed list, part of the contract)

| code | exit | when |
|---|---|---|
| `CONFIG_INVALID` | 3 | config not found / unreadable / bad TOML / unknown key / missing `${VAR}` / unknown alias / sqlite without `path` / unsupported `[defaults].format` / zero `row_limit`/`timeout_secs`. One code for the whole class — deliberate; details live in `message`. |
| `DIR_NOT_ALLOWED` | 4 | alias exists but cwd is outside its `allowed_dirs` |
| `NYET` | 5 | query refused by the validator; `error.reason` from the closed list `PARSE_FAILED` / `MULTI_STATEMENT` / `WRITE_OPERATION` / `TXN_CONTROL` / `LOCKING_CLAUSE` / `DENIED_FUNCTION` / `EXECUTABLE_COMMENT` / `EXPLAIN_ANALYZE` / `PII_COLUMN` / `PII_UNPROVABLE` (owner: `src/validator.rs`; the two PII reasons are produced by both the pre-execution AST walk and the post-execution provenance check `validator::check_origins`, which the cli calls — see the PII section) — **plus `EXPENSIVE_QUERY`, whose owner is NOT the validator** but the guardrail (`src/guardrail.rs` decides, `src/main.rs` builds the failure): the plan estimate was over the connection's threshold — or planning itself outran the guardrail's budget — so nothing ran. The threshold case is the only envelope with a top-level `estimate` object (append-only field); the budget case has no plan to attach |
| `CONNECTION_FAILED` | 6 | database unreachable (sqlite: file missing / unreadable / a directory; postgres/mysql: refused, auth failure, or a hung TCP handshake that exceeds the connect deadline — bounded separately inside each engine so a blackholed connect is 6, not 8) |
| `DB_ERROR` | 7 | the database accepted the connection but rejected the query |
| `TIMEOUT` | 8 | query did not finish within the per-query timeout (the future is dropped; a stuck sqlite worker may run until process exit). Postgres: the server `statement_timeout` (SQLSTATE 57014) maps here too, so the exit code is deterministic whichever timer fires; 57014 is `query_canceled` generally, so a manual `pg_cancel_backend` from another session also lands as TIMEOUT (rare, acceptable). MySQL/MariaDB: the server `max_execution_time`/`max_statement_time` (error 3024 / 1969) maps here too |
| `NOT_IMPLEMENTED` | 1 | resolved connection uses an engine this version does not ship |
| `INTERNAL` | 1 | nyet's own failure (e.g. cwd cannot be resolved) |

Warning codes (`warnings[].code`, also closed and append-only): `TRUNCATED`,
`DUPLICATE_COLUMNS`, `UNICODE_STRIPPED`, `INSECURE_TRANSPORT` (direct server
connection with url `sslmode`/`ssl-mode` below `require` and no ssh tunnel —
transport not guaranteed encrypted/verified; static from config+url, so it
over-warns against a server that happens to negotiate TLS — we report the
guarantee, not the runtime outcome), `SCHEMA_TRUNCATED` (`nyet schema` past
`DETAIL_LIMIT` objects: names and kinds only; the message names the
`nyet schema <alias> <table>` way out), `GUARDRAIL_SKIPPED` (the guardrail got no
number it could judge — an unreadable plan, a recursive CTE under the limit, or
an EXPLAIN the database refused — so the query ran unguarded. An EXPLAIN that
outran its BUDGET is NOT in this list: that refuses the query, exit 5. On
`nyet explain`, where there is no query to run, the same code also carries the
budget case — the verdict is `no_estimate` either way),
`NO_PLAN` (`nyet explain` was handed a metadata statement, which has no plan —
answered without touching the database),
`PII_MASKED` (`[connections.X.pii] mode = "mask"`: the named result columns came
back as `[REDACTED]` — every value in them, whatever its type, NULL included. The
agent MUST see this, or it reads the mask as data; the warning names columns
only, never values, and never a count).

Codes are append-only; renaming/removing one is a breaking change (bump `v`).
Every error must carry an actionable `hint` (Д10) — tests enforce it.

`nyet doctor` adds no error/warning code — it exits 0/3 only (see the doctor
section above). It introduces one append-only envelope field, `checks:
[{name, status, message, hint?}]`, whose `status` is a **closed list**
(`ok` | `warn` | `fail` | `na`); the check `name`s and the status list follow the
same append-only rule as the codes above (renaming/removing = bump `v`).

`nyet agent-setup` adds no error/warning code either — it exits 0 (a bad config
degrades rather than errors, and a closed reader / broken pipe is exit 0 too);
like every command, only a non-broken-pipe stdout write failure (a full disk ->
`INTERNAL`, exit 1) can error. It introduces one append-only envelope field, `skill`
(string), carried only by `--format json`; the default markdown output puts the
`SKILL.md` on stdout and a bare `{"v":1,"ok":true}` envelope on stderr.

`nyet query` pipeline order is pinned by tests: format (right after config
parse — it routes every later envelope) -> alias -> directory scoping ->
engine support / connection config -> validator -> **guardrail (EXPLAIN)** ->
execution. The guardrail sits after the validator (a refused query never pays
for a connection, and only validated SQL is ever appended to an EXPLAIN prefix)
and inside the engine's own read-only session (see below).
`nyet explain` runs the same order and stops at the guardrail step: it produces
the plan and the verdict, and never executes anything. Scoping and
engine support answer before the validator so the agent gets the real
blocker, not a SQL lecture. `nyet schema` runs the same order minus the
validator (no agent SQL), sharing the very same code: `lookup_alias`,
`check_scope`, `build_engine`, `open_tunnel`, `runtime`, `engine_failure` in
`src/main.rs` — pinned by `schema_pipeline_order_matches_query`. `nyet doctor`
shares `lookup_alias` (unknown alias -> exit 3) and `build_engine` but
deliberately **skips `check_scope`** (a named alias is diagnosed from any
directory) and never calls `engine_failure` (a connect failure becomes a `fail`
check via `diagnose_connection`, not an exit-6 envelope).

## Audit log (`src/audit.rs`)

The forensic log the human relies on (UX-8): one jsonl line per
database-touching command. The split follows Д1/Д2 — `audit.rs` is a pure record
builder plus the single IO primitive, the cli owns the orchestration.

**Record schema, versioned independently.** `audit_v` (a `const` in `audit.rs`)
is the record-schema version, deliberately separate from the JSON-envelope `v`:
the log can gain fields on its own cadence without touching the agent contract.
Fields: `audit_v`, `ts` (ISO 8601 UTC ms), `command`, `alias`, `engine`, `cwd`,
`sql` (query/explain — the RAW agent text, before Unicode normalization, so a
zero-width injection is visible) or `table` (schema), `verdict`
(`ok`/`refused`/`error`), `reason` (the NYET reason on a refusal, the
`error.code` on an error), `exit_code`, `row_count`+`truncated` (query),
`duration_ms`, `warnings` (codes only), and — under `log_responses` — `response`
(the rows the agent saw, in column order via the same ordered-object serializer
as `output`; other commands log their structured payload as a `Value`). All
optional fields are `skip_serializing_if`, so each line stays minimal (UX-4).
Snapshot-tested with an injected timestamp (`ts` is never compared byte-for-byte
in the e2e — only its shape).

**Privacy — what is excluded.** The `Event` struct has nowhere to put a
password or a url: only `alias`+`engine` identify the connection. A url can
carry an inline password, so it is never logged. Pinned by
`warning_codes_are_listed_but_never_the_url_or_password` and by the e2e reading
the raw file back and asserting it holds no `password`/`://`.

**Where it is logged (the pipeline point).** `main::audit_finish` is the single
seam. Each DB command (`query`/`schema`/`explain`/`doctor <alias>`) runs its
body as one `Result<Emitted, Failure>` — so **every** outcome, success or a
refusal/DB-error `Failure`, flows through the same place — and then
`audit_finish` writes the record **before** `emit` (success) or before `main`
prints the error envelope (failure). The audit point is *after* the session is
open (engine resolved) but does not require a connect: a validator refusal is
logged though nothing reached the database ("what the agent tried"). Config
errors *before* the session (unknown alias, directory denied, unsupported
engine, missing `password_env`) are **not** logged — there is no engine to name
and no database interaction; behavior there is byte-for-byte as before.
`list`, `agent-setup` and `doctor` with no alias never contact a database and
are not logged (Д9 — nothing extra on the cold-start path).

**Fail-closed ordering (UX-8/UX-1).** The record is written and flushed before
the result is released. If the append fails, `audit_finish` returns
`AUDIT_FAILED` (a new `error.code`, exit 1 / INTERNAL class — it is nyet's own
infrastructure failing, not the request) and the result is **never emitted** —
`stdout` carries the error envelope (json) or stays empty (data formats), so the
agent gets no rows. The human cannot miss an event the agent acted on. A refusal
or DB error is logged too and, if THAT write fails, `AUDIT_FAILED` overrides even
the original error.

**Concurrency — no interleaving.** Several `nyet` processes (parallel agents)
append to one file. A jsonl line with `log_responses` can exceed 4 KiB, so a
single `write()` is not guaranteed atomic; `audit::append` therefore holds an
advisory exclusive lock (`std::fs::File::lock`, stable since Rust 1.89 —
`flock(2)` on unix, no new crate, no `unsafe`) across the write+flush, and opens
with `O_APPEND`. Two concurrent large writes each land whole. Proven by
`concurrent_large_appends_never_interleave` (4 threads × 50 × 8 KiB) and by the
cross-process e2e `audit_is_safe_across_concurrent_processes` (two `nyet query`
processes, big-blob rows).

**Durability trade-off (Д9).** The line is `write`+`flush`ed (in the OS cache,
visible to readers, survives a process crash) but NOT `fsync`ed: a per-query
fsync would tax every request, and a full power loss dropping only the last line
is acceptable for a cooperative-agent log. The load-bearing guarantee is the
cli's ORDERING (record committed before the agent gets its result), not fsync.

**No new dependency (Д8).** The timestamp comes from `chrono`, already in the
tree via sqlx (`sqlx::types::chrono`); the lock is `std`. `audit.rs` depends on
serde/serde_json + std only.

**Path resolution.** `main::audit_path`: explicit literal `[audit] path` →
`$XDG_DATA_HOME/nyet/audit.jsonl` → `~/.local/share/nyet/audit.jsonl`. `${VAR}`
in an explicit `path` is a config error (`AuditPathEnvVar`, exit 3) via the same
`reject_env_vars_in_policy` as the other policy values, so a config owner's
pinned path cannot be rewritten through the environment. **Honest limit:** the
*default* path still resolves from `XDG_DATA_HOME`/`HOME`, which are
agent-controlled — an agent can redirect the DEFAULT log by setting
`XDG_DATA_HOME` (the same threat-model boundary as cwd spoofing, DESIGN §4; the
defense is an explicit literal `path` plus a read-only role, not the log alone).
literal-only therefore hardens the explicit pin, not the default. If neither
HOME nor XDG_DATA_HOME is set and no explicit path is given, auditing cannot
proceed and fails closed (`AUDIT_FAILED`), never a panic (Д3).

**Existing-file permission warning.** `main::warn_loose_permissions` (shared
with the config file) stat-warns to stderr if an EXISTING log has group/other
bits — it holds the agent's SQL (and rows under `log_responses`). Like the
config, nyet warns and does not chmod; a file nyet creates is 0600 from birth.

**Partial-write rollback.** `audit::write_flush` records the file length before
the write and, on a `write_all`/`flush` error (a full disk mid record),
`set_len`s back to it under the still-held flock — so a committed prefix cannot
corrupt every jsonl line below it — then returns the error (`AUDIT_FAILED`,
fail-closed). Fault-injected by `a_partial_write_is_rolled_back_and_leaves_valid_jsonl`.
