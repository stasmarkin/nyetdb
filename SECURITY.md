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
  the real backstop). A parent-path count (`countDocuments({profile: {$exists:
  true}})`) still leaks the *presence* of a subdocument, one bit per query —
  same accepted class as the SQL `WHERE` oracle above. MongoDB has no
  field-level privileges, so unlike SQL there is **no server-side twin** of the
  policy: the honest boundary is a view minus the protected fields with a role
  scoped to it, and `nyet doctor` says so.

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

- **The audit log and SSH tunnel have agent-reachable edges.** The default audit
  path resolves from agent-controlled `XDG_DATA_HOME`/`HOME`, so an
  agent-resistant trail needs an explicit literal `[audit] path` plus the
  read-only role — and even then the log file's own path, permissions and
  symlinks are only as trustworthy as the directory it lives in. A reused SSH
  forward (`reuse_forward`) is a loopback listener
  to your database that outlives the `nyet` process; any local process can reach
  the database through it while it lives (it does not hand out your password).
  See the "Audit log" and "SSH tunnels" sections of the README.
