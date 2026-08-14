# nyetdb — Principles

Agreed in July 2026. Every product and technical decision is checked against
this document; if a decision contradicts a principle, either the decision
changes or the principle does — deliberately and explicitly.

## The frame: two users

- **The human** — installs it, writes the config, grants access to their own
  databases. What they buy is **peace of mind**: "I let an agent near prod and
  I am not afraid."
- **The agent** — the actual daily user of the CLI (99% of invocations). What
  it needs is **clarity and learnability**: to find its way without the human,
  to correct itself after a refusal, to not burn context.

Almost every UX decision is a choice about which of the two to please, so the
principles are ordered: on conflict, the lower number wins.

## UX principles

**1. The human's trust is the one currency you cannot get back.**
The human must never once regret installing nyet. No surprises: writes are
impossible by default, behavior is predictable, doubt is resolved against the
request (fail closed). A false refusal annoys the agent — tolerable; a false
pass destroys the human's trust — unacceptable.

**2. A refusal is part of the product.**
Every "nyet" must explain *why* and *what to do instead*: `reason` + `hint`
are mechanism, not decoration. The agent corrects itself without going to the
human. Dead-end errors do not exist. A teaching refusal outranks token
thrift: refusals are rare, and an agent's guessing loops cost more than a
hint.

**3. An agent must be able to learn the tool on its own.**
Zero assumptions that nyet is in the training data. Everything needed to pick
it up is available to the agent programmatically: `nyet agent-setup`
generates the instructions for AGENTS.md or a skill, `--help` is written for
an LLM (examples, not just flags), `nyet list` shows what is reachable from
here, refusals teach (principle 2). The test: an agent seeing nyet for the
first time reaches a successful query without a human.

**4. The agent's tokens are the human's money.**
Every extra byte of output is read and paid for by the agent. Compact JSON
without decoration, explicit truncation markers, schema output designed for an
LLM context window. Verbosity is not "thoroughness", it is a tax. (It is also
the marketing edge over MCP servers.)

**5. Write the config once, and it keeps working.**
Backward compatibility of the config and of the agent-facing contract (JSON
fields, error codes, exit codes) is a promise, not a detail. A new version of
nyet must understand an old config: keys are never dropped, they are
deprecated with a warning and a hint (or migrated automatically). Breaking
the contract happens only through a bump of the `v` field, with a transition
period.

**6. Five minutes to the first query, and the human forgets the tool exists.**
One binary, one config, no daemons, no migrations: install → example config →
`nyet query`. The human sets it up once and nyet leaves their head — that is
the ideal outcome, not a sign of being unimportant.

**7. No security theater.**
We do not promise protection we do not have: directory scoping is a UX barrier
(and we say so), prompt injection is not solved (and we write that down),
`doctor` names the weak spots of a setup honestly. Overpromising in a security
tool is a scandal on a delay.

**8. The human sees everything the agent did.**
The audit log is part of the deal, not an option: letting an agent near a
database is acceptable only if you can look at what it did there.

## Explicit conflict resolutions

| Conflict | Winner |
|---|---|
| Safety vs the agent's convenience | safety |
| Teaching refusal vs token thrift | teaching refusal (refusals are rare) |
| Token thrift vs pretty output for humans | tokens; the table format exists but is secondary |
| Simple start vs configurability | simplicity: sane defaults, everything except credentials optional |
| Feature completeness vs predictability | predictability |
| A nicer new config schema vs compatibility | compatibility; the new lands next to the old, the old is deprecated with a warning |

## Anti-values (deliberately NOT priorities)

- **Breadth of database support** — nyet differentiates in the depth of the
  safety layer, not in the number of engines (see ROADMAP: positioning).
- **Interactive human UX** (REPL, completion, pagers) — humans have pgcli and
  usql; nyet is an agent's tool.
- **Speed as a product value** — performance matters (see the dev principles),
  but nyet does not compete on speed benchmarks; it competes on trust and
  token efficiency.

---

# Dev principles

How decisions get made in the code. The architectural principles set the
shape, the operational ones set the discipline; each serves one of the UX
principles above.

## Architectural

**D1. Pure core, imperative shell.**
Domains stay pure for as long as possible: the validator, the resolver, the
formatters are pure functions (input → output, zero IO, zero global state).
All the "business noodles" — orchestration, config from disk, connections,
ssh, output — live as high up as possible, in a thin imperative cli layer.
Direct consequence: the validator's golden corpus runs without live databases,
instantly, in any CI.

**D2. Dependencies flow downward only, and they shrink on the way.**
The lower the module, the fewer dependencies it has: `validator` knows only
sqlparser's AST types (not tokio, not sqlx, not clap); `engines` know their
drivers; `cli` knows everything. The direction of dependencies is the
direction of stability: the bottom changes rarely and tests cleanly, the top
changes cheaply and often.

Target module map for v0.1:

```
cli        — clap, orchestration, exit codes (the "noodles" live here and only here)
├─ config    — serde → pure structures (Config, Policy); validated on the way in
├─ resolver  — pure: (cwd, Config) → Connection | Denied
├─ validator — pure: (AST, Policy) → Verdict; depends on sqlparser alone
├─ engines   — IO adapters behind trait Engine (sqlx, mongodb, redis, scylla)
└─ output    — pure: (ResultSet, Format) → String
```

**D3. Fail fast inward, fail closed outward.**
Two different reflexes, not to be confused: an internal invariant is violated
or the config is invalid → abort immediately with a clear error, do not carry
broken state further; a user's or agent's request is doubtful → deny with a
reason and a hint. No `unwrap()` or panics on paths reachable from external
input — errors are typed and mapped onto contract codes.

**D4. One responsibility, closed scopes.**
A method reads locally: its signature and body make it perfectly clear what it
does and how it behaves, with no global context needed. The ideal is a pure
function; hidden side effects in "innocent" methods are a review bug. Every
type and module is responsible for one thing, and its name says which.

**D5. Simple beats easy; boring beats clever.**
If a feature needs "just one more if" inside someone else's responsibility, or
a refactor of responsibilities, we take the refactor whenever it keeps the
abstractions clean: the extra if is a loan at a steep rate. The code itself
stays boring: no magic, no generalizations "for later" (trait `Engine` is the
only planned abstraction; a second one appears when a third concrete case
proves the need). A contributor of average skill reads the code without a
tour guide.

## Operational

**D6. A validator rule does not exist without a test.** *(UX-1, UX-7)*
Every rule gets at least a positive and a negative case in the golden corpus.
A known bypass → the failing test first, the fix second. The corpus is public
— "no theater" in checkable form.

**D7. Output is an API.** *(UX-5)*
The JSON envelope, error codes and exit codes are covered by snapshot tests;
CI fails when they change. A deliberate change means a `v` bump, a deprecation
period and a changelog entry. The `message`/`hint` texts are free to change;
the structure and the codes are not.

**D8. Every dependency is attack surface.** *(UX-1, UX-7)*
A security tool holding production credentials: the supply chain is our own
biggest risk. A new dependency is justified in the PR (what it buys, and why
30 lines of our own would not do); `cargo-deny` and `cargo-audit` run in CI
from day one; `#![forbid(unsafe_code)]` covers all of our own code.

**D9. Cold start is a budgeted resource.** *(UX-4, UX-6)*
The CLI pays startup on every single agent call. Target: < 50 ms from launch
to the start of the connection (with no failing CI gate — timing in CI flaps,
but a regression against the target is worth a conversation in the PR).
Initialization is lazy; startup does no network and no telemetry.

**D10. Error texts are code.** *(UX-2, UX-3)*
`reason` and `hint` get reviewed like code, against the template "what
happened → why it was refused → what to do instead". An error without an
actionable hint does not get merged. This is the cheapest part of the product
and the most visible one to the agent.

## Hygiene

- clippy with deny-warnings in CI from day one (a bar is easier to lower than
  to raise).
- Test coverage as a percentage is not a metric: what matters is the corpus
  (D6) and the contract (D7), not the number.
- We keep no performance benchmarks for query execution — execution speed
  belongs to the database, nyet answers only for its own overhead (D9).
