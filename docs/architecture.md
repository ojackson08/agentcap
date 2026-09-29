# Architecture

Why AgentCap is built the way it is. Each decision below exists because the
obvious alternative fails in a specific, demonstrable way.

---

## The enforcement point sits outside the agent

An agent that can modify its own enforcement has no enforcement. The mediator is
a separate process, a sidecar, or a Lambda — never a library the agent imports
and can monkey-patch, and never a tool the agent can reconfigure.

This is also why the conformance suite includes C14. The honest consequence of
"enforcement outside the agent" is that a call which never reaches the mediator
is not mediated. That path is declared, measured, and disclosed rather than
papered over.

## Defaults are deny, and every failure mode fails closed

| Condition | Result | Why not the alternative |
|---|---|---|
| Tool not in contract | deny | an allowlist that defaults open is not an allowlist |
| Pinned tool, no digest supplied | deny | an unpinned invocation is a different artifact from the approved one |
| Digest mismatch | deny | the tool changed; approval was for the old definition |
| Predicate raised | deny | a predicate that failed to run is not a predicate that passed |
| Contract expired | deny | expiry that is advisory is not expiry |
| Signature invalid | deny | a tampered contract is not a contract |
| Ledger unavailable | deny | a decision that is not recorded cannot be defended later |
| Budget exceeded | deny | and nothing is consumed on the rejection path |

The last one matters more than it looks. A budget check that consumes on failure
turns a retry loop into a slow-motion overspend.

## Policy is compiled, not interpreted from prose

The contract is declarative data. `compile.py` turns it into a decision function
with a stable hash, and that hash is written into every ledger record.

Two consequences:

1. **Decisions are reproducible.** Given the contract and the call, the decision
   is determined. There is no model in the loop.
2. **Decisions are attributable.** `policyHash` in the record proves which rules
   were in force. "We blocked it" is meaningless if you cannot say under which
   policy.

## Predicates are a restricted expression language

Contract predicates are parsed with `ast`, vetted against a node allowlist, and
evaluated with `__builtins__` removed. Permitted: comparisons, boolean operators,
membership, and eight vetted functions (`startswith`, `endswith`, `contains`,
`lower`, `len`, `matches`, `any_of`).

Not permitted: imports, dunder access, arbitrary attribute traversal, lambdas,
comprehensions, or assignments.

The reason is not paranoia about contract authors. It is that contracts are
*data*, and data can be influenced by whoever can write a contract — including,
in a compromised workflow, an agent. A policy language with surprising semantics
is a policy language that will authorize something unexpected. C16 tests four
code-execution payloads.

Method-call syntax (`args["path"].endswith(".md")`) is supported because it is
what a Python author reaches for, but it resolves to the same vetted allowlist
through a `str` subclass whose `__getattr__` refuses anything unlisted.

## The budget is a critical section, not a counter

The failure mode: two parallel agent branches both read "budget remaining: $10",
both conclude they may spend $10, and both spend it.

`LeaseStore.check_and_commit` performs the read, the ceiling comparison, and the
write inside one exclusive `flock`. The AWS deployment replaces this with a
DynamoDB conditional write, which is the same guarantee expressed as a storage
primitive. C12 races 50 concurrent threads against a $10 ceiling and asserts
exactly 10 grants.

## Cost scales with what is provisioned

A flat per-call fee cannot bound a provisioning call. `ec2:RunInstances` is
charged at the instance's hourly rate × count × a 24-hour commitment horizon.

Two deliberate choices:

- **Unknown instance types cost the most expensive known rate.** An unrecognised
  class must be treated as maximally risky, not free. A cost table that silently
  misses on a naming convention reports $0.00 consumed while the agent spends
  real money — which is the exact failure the module exists to prevent.
- **The horizon is a commitment, not a session.** An agent that launches
  instances has committed to paying for them. Charging the first hour would let
  it commit to a week of spend against an hourly budget.

## The ledger is evidence, so it must survive a hostile host

Three properties, each defeating a specific attack:

| Property | Defeats |
|---|---|
| `prevHash` chains each record to its predecessor | deletion, reordering, retroactive editing |
| `policyHash` binds decision to rules | "we blocked it" with no verifiable ruleset |
| `toolDigest` binds decision to artifact | a tool mutated after approval |

Signatures are Ed25519 over the canonical record body. `agentcap verify` walks
the chain and reports the first break. C10 and C11 tamper and delete records
respectively and assert detection.

Redaction is by allowlist: investigation-relevant fields are retained, secret-shaped
keys are never stored, and everything else becomes a truncated hash — so the
record still proves *what* was passed without retaining it.

## Approvals are out-of-band and cannot be self-satisfied

`Mediator.resolve_approval` refuses any resolver equal to the contract's own
workload. The gate is a human decision, and the code enforces that it is a
*different* principal. C13 tests the self-satisfaction attempt.

## Shadow mode is the default

A mediator that blocks legitimate work on day one gets uninstalled on day one.
Shadow mode records what enforcement *would* have done — including marking the
reason with `[shadow]` so the record is not mistaken for a real denial — and
blocks nothing. C15 asserts that a shadow denial is recorded, marked, and not
enforced.

---

## Component map

```
agentcap/
├── contract.py    parse · validate · hash · sign · verify · diff
├── compile.py     contract → decision function + Rego emission
├── mediator.py    the enforcement point (10 ordered checks)
├── ledger.py      hash-chained signed evidence + redaction
├── leases.py      atomic budget/rate leases + cost model
├── cli.py         init · validate · sign · plan · run · inspect · verify · revoke · explain · doctor
└── adapters/
    ├── mcp.py     MCP JSON-RPC (stdio + HTTP), definition pinning, drift detection
    └── http.py    HTTP tools + subprocess (bubblewrap) execution
```

## The decision order in the mediator

Ordered cheapest-and-most-certain first, so that a call which is already
substantively denied does not generate approval noise or consume budget:

1. contract expiry
2. signature verification
3. tool granted at all
4. tool digest matches the pin
5. argument predicates
6. data-flow / taint rules
7. delegation depth
8. non-delegable capability via delegate
9. per-tool call ceiling
10. budget (atomic check-and-commit)
11. rate limit
12. approval gate

Steps 1–8 are pure functions of the contract and the call. Only 9–12 touch
state.
