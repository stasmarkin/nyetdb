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
ER_UNKNOWN_SYSTEM_VARIABLE, 1193): MySQL uses `max_execution_time` (ms), MariaDB
`max_statement_time` (seconds). The engine picks by the config `engine` value
(`mariadb` → the seconds form) and **swallows a 1193** if the label is wrong —
the cli's outer tokio timeout is the backstop, so a mislabelled server degrades
to timeout-only rather than a broken query. Both timeout SQLSTATEs (3024 / 1969)
map to `EngineError::Timeout` so the exit code is deterministic (like Postgres
57014).

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
│                                 Deny{reason,message,hint}; depends ONLY on
│                                 sqlparser + unicode-properties (+std)
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
└─ output    (src/output.rs)    — pure: values -> envelope/table strings;
                                  also owns the `schema` data model (the
                                  contract shape) and its pk/unique rules
```

Dependencies flow downward only: the pure modules do no IO and know nothing
about clap or each other; file reading, env access, cwd/realpath, the tokio
runtime and the query timeout live in the cli layer. The edges between "leaf"
modules are `engine -> output`, `engine -> guardrail`, `guardrail -> output` and
`config -> guardrail` (the guardrail owns the judging and its own config
resolution — `config::guardrail` is the single entry point, called at parse time
to fail loud and again by the cli to get the value; output owns the serialized
shapes; the engines only run the EXPLAIN and hand the result over). The first
one: the `Schema`/`SchemaTable`/`SchemaColumn`
structs are the serialized contract, so they live in the pure module (with
`build_table`, the single owner of the pk/unique presentation rules) and the
engines fill them in. That direction is still downward — `output` depends on
serde alone, `engine` on all of sqlx. The runtime is built
lazily, only when an engine actually executes (Д9: `list`, config errors and
validator refusals never start it).

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
  overrides `PgConnectOptions.host()/port()` and forces `ssl_mode(Disable)` on
  the tunnel leg (`apply_host_override`) — the ssh hop already encrypts, and TLS
  verification against `127.0.0.1` would fail against a cert naming the real host
  — while user/dbname/params and the password stay intact. The **direct** leg
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

- **PostgreSQL** (`pg_guarded_plan`): `SAVEPOINT nyet_guardrail` +
  `SET LOCAL statement_timeout = <budget>` before the EXPLAIN, and
  `ROLLBACK TO SAVEPOINT` after it — on every path that keeps the connection.
  `TooSlow` and `Broken` skip it (there the socket is dropped, and the savepoint
  dies with it; awaiting a rollback on a busy or broken session is the very hang
  this design avoids). The savepoint is what makes the
  fail-open path work at all: a failing EXPLAIN aborts the transaction, and
  before this fix `nyet query pg "SELECT * FROM nope_x"` answered *"current
  transaction is aborted, commands ignored until end of transaction block"*
  instead of naming the missing relation (verified live, now pinned in the e2e).
  Rolling back to the savepoint also restores `statement_timeout` (SET LOCAL is
  savepoint-scoped), and an explicit restore follows as belt and suspenders.
- **MySQL/MariaDB** (`Mysql::guarded_plan`): `set_statement_timeout(budget)`
  before, `set_statement_timeout(query timeout)` after — the same pair of
  variables `begin_read_only` uses. Pinned by an e2e that reads
  `@@max_statement_time` back inside the query (10 s with `--timeout 10`, not the
  5 s budget) — proof that the cap was lent and returned.

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
deadline.** `explain_deadline_ms` = `min(cap + grace, timeout_secs - 200ms)`, and
`explain_budget_ms` is that minus the 500 ms grace, so the ordering holds for
EVERY timeout the CLI accepts (at the 1 s minimum: 300 / 800 / 1000 ms; from 10 s
up the flat 5 s cap applies). Both earlier shapes were wrong in the same way:
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

Two more things worth knowing:

- **PostgreSQL does not interrupt plan-time const-folding on
  `statement_timeout`** (measured — `md5(repeat(...))` chains run to completion),
  so for that particular attack the CLIENT deadline is what fires. The server cap
  still matters for ordinary slow planning, where interrupts do get checked.
- On `TooSlow` the connection is **dropped, not closed politely**: a graceful
  `ROLLBACK`/`COM_QUIT` would wait for the planning we just abandoned. The
  backend notices when it tries to answer. That is the accepted cost of refusing
  on time.

Cost: three extra round trips on a guarded Postgres query, two on MySQL. That is
the price of a guardrail that cannot be disabled by making planning slow.
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
`EXECUTABLE_COMMENT`, `EXPLAIN_ANALYZE`);
optional `warnings` on an allow case is the comma-joined list of expected
warning codes (currently only `UNICODE_STRIPPED`) — allow cases without it
must produce none, deny cases never carry warnings; optional `dialect`
defaults from the **filename prefix** — `postgres_*.yaml` runs the PostgreSQL
dialect + `Policy::postgres`, `mysql_*.yaml` the MySQL dialect + `Policy::mysql`
(MariaDB is dialect-identical), everything else SQLite + `Policy::sqlite` — and a
per-case `dialect: postgres|mysql|sqlite` still overrides. Unknown lines fail the run
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
  for completeness (an agent read never needs any of them). Note this differs
  from the Postgres `pg_advisory_*` decision — there the wait variants aren't the
  default and the family is noisier to enumerate; MySQL's blocking form is the
  common one and the family is tiny. (`is_used_lock` / `is_free_lock` are pure
  non-blocking reads and stay **allowed**.)
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
| `NYET` | 5 | query refused by the validator; `error.reason` from the closed list `PARSE_FAILED` / `MULTI_STATEMENT` / `WRITE_OPERATION` / `TXN_CONTROL` / `LOCKING_CLAUSE` / `DENIED_FUNCTION` / `EXECUTABLE_COMMENT` / `EXPLAIN_ANALYZE` (owner: `src/validator.rs`) — **plus `EXPENSIVE_QUERY`, whose owner is NOT the validator** but the guardrail (`src/guardrail.rs` decides, `src/main.rs` builds the failure): the plan estimate was over the connection's threshold — or planning itself outran the guardrail's budget — so nothing ran. The threshold case is the only envelope with a top-level `estimate` object (append-only field); the budget case has no plan to attach |
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
answered without touching the database).

Codes are append-only; renaming/removing one is a breaking change (bump `v`).
Every error must carry an actionable `hint` (Д10) — tests enforce it.

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
`src/main.rs` — pinned by `schema_pipeline_order_matches_query`.
