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
├─ engine    (src/engine.rs)    — IO adapters behind trait Engine; knows sqlx,
│                                 nothing about clap; fills in output's pure
│                                 schema model (the one leaf->leaf edge)
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
runtime and the query timeout live in the cli layer. The one edge between two
"leaf" modules is `engine -> output`: the `Schema`/`SchemaTable`/`SchemaColumn`
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
`EXECUTABLE_COMMENT`);
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
| `NYET` | 5 | query refused by the validator; `error.reason` from the closed list `PARSE_FAILED` / `MULTI_STATEMENT` / `WRITE_OPERATION` / `TXN_CONTROL` / `LOCKING_CLAUSE` / `DENIED_FUNCTION` / `EXECUTABLE_COMMENT` (owner: `src/validator.rs`) |
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
`nyet schema <alias> <table>` way out).

Codes are append-only; renaming/removing one is a breaking change (bump `v`).
Every error must carry an actionable `hint` (Д10) — tests enforce it.

`nyet query` pipeline order is pinned by tests: format (right after config
parse — it routes every later envelope) -> alias -> directory scoping ->
engine support / connection config -> validator -> execution. Scoping and
engine support answer before the validator so the agent gets the real
blocker, not a SQL lecture. `nyet schema` runs the same order minus the
validator (no agent SQL), sharing the very same code: `lookup_alias`,
`check_scope`, `build_engine`, `open_tunnel`, `runtime`, `engine_failure` in
`src/main.rs` — pinned by `schema_pipeline_order_matches_query`.
