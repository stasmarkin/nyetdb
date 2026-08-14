# Security Policy

## Reporting a vulnerability

Report privately through **GitHub Private Vulnerability Reporting**: open the
repository's [**Security** tab](https://github.com/stasmarkin/nyetdb/security),
click **Report a vulnerability**, and file a draft advisory. There is
deliberately no security mailbox — a mailbox has to be created and guarded, the
advisory flow does not.

Please do not open a public issue for a suspected vulnerability. If a report
turns out to be a validator bypass, its resolution is a regression test in the
public golden corpus (`tests/corpus/*_deny.yaml`) — the fix is a green test, not
a private patch.

## Supported versions

`nyet` is pre-1.0. Only the **latest released version** receives security fixes;
there are no backports to older tags. Track the latest release.

## What `nyet` does NOT guarantee (out of scope)

`nyet` is a read-only layer for a **cooperative but fallible** agent, not a
sandbox around a hostile one (see the threat model in
[docs/DESIGN.md](docs/DESIGN.md)). The list below is deliberate: an unwritten
boundary gets found anyway, and honesty beats obscurity. The *categories* below
are accepted limits, not bugs — directory scoping as a UX barrier, prompt
injection, the PII oracle as a class. But a **concrete, first-of-its-kind
bypass** — a specific input that defeats the function denylist or a parser-vs-
server divergence that slips a write past the validator — *is* a reportable bug:
file it privately as above.

- **An agent with shell access can walk around `nyet`.** It can read the config
  and connect to the database directly (`psql`, `nc`, a driver). The durable
  boundary is therefore *in the database*: a read-only role, column-level
  `GRANT`s, views and row-level security enforce the line for **every** client,
  including one that never goes through `nyet`. `nyet doctor` checks for this and
  nags. The `nyet` layers (validator, session read-only, `[pii]`) are the fast,
  local, reviewable layer on top — not a replacement.

- **The credentials can be kept out of the agent's reach; the config file
  cannot.** `password = { keychain = "..." }` (macOS) stores the secret behind
  an ACL the OS checks against the *caller's* code signature, so an agent that
  finds the config still cannot read the password: `security`, a driver or its
  own shell all get a keychain prompt only a human can answer. `{ env = ... }`
  and `{ command = ... }` do **not** do this — any process of the same uid
  reads the variable or runs the command — and `nyet doctor` says which of the
  two a connection uses. What remains open is the file itself: it belongs to
  the same user, so an agent can *rewrite* it — point `url` at a database it
  controls, or add an `[ssh] remote` — and `nyet` will then hand the real
  password to that endpoint. Closing this would mean binding each secret to its
  target and protecting the config from writes; it is a **known and accepted**
  limit of the current design, which assumes a cooperative-but-fallible agent
  rather than one actively phishing for credentials.

- **Directory scoping is a UX barrier, not a security boundary.** `allowed_dirs`
  guards against pointing an agent at the wrong database by accident. The current
  directory comes from the process and is controlled by the calling agent, so it
  can be spoofed — this is not a sandbox.

- **Prompt injection is not solved at `nyet`'s layer.** No complete defense
  exists. `nyet` validates the *query*, not the *intent*: an agent can be talked
  into composing a query that is a perfectly valid read yet serves an attacker's
  goal, and `nyet` will run it. Read-only enforcement limits the blast radius and
  the audit log gives you forensics; the rest is the harness's responsibility.

- **A protected (PII) column is still an oracle through `WHERE`.** A comparison
  on the *marked* column (`WHERE email LIKE 'a%'`, an equality, a join predicate)
  does not *return* the value, but it would leak **one bit** of information per
  query through the row count — which is exactly why `nyet` refuses filters and
  joins on marked columns. The residual channel it *cannot* close is the same
  oracle on inputs it does not control: counting over *unmarked* columns that
  correlate with a protected one, query timing, and row order under
  `mode = "mask"`. Closing those would mean refusing nearly every query, so they
  are a **known and deliberately accepted** limitation. The real confidentiality boundary is the
  database (column-level grants, views, RLS); see "PII columns" in the README.

- **MongoDB's PII policy leans on a closed list of "movers".** With no schema
  and no column provenance, the MongoDB nets hold on one invariant: a value
  cannot leave without its field name (net A refuses every mention, net B scans
  the result documents for protected keys). The operators that break the
  invariant — converting field names to values or reaching fields through
  computed names (`$objectToArray`, `$getField`, ...) — are refused wholesale,
  but the completeness of *that list* is **not proven**, and MongoDB adds
  operators every release (the allowlist refuses new ones by default, which is
  the real backstop). Two residual channels are the same **accepted class** as
  the SQL `WHERE` oracle above and cannot be closed without a schema: a
  parent-path count (`countDocuments({profile: {$exists: true}})`) leaks the
  *presence* of a subdocument, and sorting/skip/limit on an unprotected PARENT
  of a protected field (`sort({profile: 1})`) leaks the protected value's
  *order* — neither returns the value, both leak a bit per query. The policy is
  also keyed on the **collection name**: a view or copy collection over the
  protected data under a different name is not covered unless it is named too
  (as on the SQL side). And MongoDB has no field-level privileges, so unlike
  SQL there is **no server-side twin** of the policy: the honest boundary is a
  view that `$unset`s the protected fields with a role scoped to it, and `nyet
  doctor` says so.

- **On SQLite a query can exhaust the machine's memory, and nothing in `nyet`
  stops it.** SQLite is *in-process*, so the allocation happens inside `nyet`
  itself rather than on a server someone else operates — and SQLite publishes
  no plan estimate, so this is the one engine with no guardrail to refuse an
  expensive query. Measured (August 2026): `SELECT length(randomblob(1e9))`
  reached 994 MB RSS in 6.9 s, and a recursive CTE that doubles a string —
  `WITH RECURSIVE c(x) AS (SELECT 'aaaaaaaa' UNION ALL SELECT x||x FROM c WHERE
  length(x) < 4e8) SELECT max(length(x)) FROM c` — reached **4.35 GB in 4 s**
  using nothing but ordinary SQL. `row_limit` does not help (it is one row) and
  the default timeout is far too generous to matter. Denylisting `randomblob` /
  `zeroblob` would be theatre: the CTE form is both cheaper to write and
  bigger. SQLite's own heap limits were tried and do not close it either —
  `PRAGMA hard_heap_limit` is not compiled into this build (it reads back 0) and
  `soft_heap_limit` bounds the page cache, not string and blob allocations (set
  to 256 MB, the same query still reached 4.13 GB). The honest containment is
  outside `nyet`: run the agent under a memory limit (`ulimit -v`, a cgroup, a
  container). Server engines do not share this: there the memory is the
  database server's problem, and the guardrail refuses the plan first.

- **A read that causes a side effect is only as complete as the denylist.** A
  `SELECT` can call a function that writes or reaches outside the database
  (`setval`, `lo_export`, `pg_read_file`, `dblink`, `query_to_xml`, a volatile
  user function). `nyet` maintains a per-engine function denylist, but the
  completeness of that list is **not proven**. Report a bypass and it becomes a
  denylist entry plus a corpus test.

- **The parser is not the server.** `sqlparser` classifies query text; the
  database executes it. Where the two diverge (nested comments, dollar-quoting,
  escape syntax, Unicode homoglyphs, identifier folding, a `;` inside a literal,
  multi-statement smuggling, a `SET`/`RESET` the validator did not recognise as
  transaction control) is the root class of validator bypasses.
  Differential testing against a live read-only server and fuzzing are built
  **specifically** to hunt this down — but there is no 100% guarantee, which is
  why layer 3 (the read-only database role) matters.

  An audit in August 2026 found one real divergence and one unadvertised
  barrier. The divergence: with `sql_mode=NO_BACKSLASH_ESCAPES`, MySQL does not
  treat `\'` as an escape, so `SELECT '\';SELECT 2;--'` is **two** statements to
  the server and one string literal to the validator. The barrier: it does not
  get through anyway, because queries are sent as *prepared statements*, and
  neither MySQL nor PostgreSQL will accept a second statement in one — measured,
  the server rejected the whole string with a syntax error. So multi-statement
  smuggling has to beat the parser **and** the wire protocol, not just the
  parser. This is worth knowing about rather than relying on: it is a property
  of how the driver sends queries today, not a promise, and anything that ever
  switches to the simple query protocol (or adds a code path building SQL as
  text for the server to split) loses it silently.

  Checked in the same pass and found to agree with the server: nested block
  comments (Postgres nests, MySQL does not — the validator is dialect-aware and
  refuses on MySQL what it accepts on Postgres), dollar-quoted strings, `E''`
  escapes, a `;` inside a literal, and Unicode — a homoglyph in a keyword fails
  to parse rather than being folded, and a zero-width character is stripped by
  normalization, with the *normalized* text being what actually runs.

- **The audit log and SSH tunnel have agent-reachable edges.** A trail that
  cannot be written is refused (the query's result is withheld, exit 1), and
  since August 2026 a path that *accepts writes without keeping them* —
  `/dev/null`, a device, a fifo, reached directly or through a symlink an agent
  dropped in place — is refused the same way rather than silently swallowing
  the record. The forward registry is worth the same caution as the audit path:
  it lives under the user's own runtime dir, so it proves ownership against
  accident, not against a process of this uid that sets out to forge an entry.
  The default audit
  path resolves from agent-controlled `XDG_DATA_HOME`/`HOME`, so an
  agent-resistant trail needs an explicit literal `[audit] path` plus the
  read-only role — and even then the log file's own path, permissions and
  symlinks are only as trustworthy as the directory it lives in. A reused SSH
  forward (`reuse_forward`) is a loopback listener
  to your database that outlives the `nyet` process; any local process can reach
  the database through it while it lives (it does not hand out your password).
  See the "Audit log" and "SSH tunnels" sections of the README.
