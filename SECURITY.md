# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue for a
security problem.

Include, where possible:

- the affected version or commit
- a minimal reproduction
- the impact you believe it has
- whether you intend to publish, and on what timeline

You will get an acknowledgement, an assessment, and a coordinated disclosure
timeline. Credit is offered unless you prefer otherwise.

## Scope

AgentCap is an enforcement point, so the security of the enforcement path is the
product. The following classes are in scope and are treated as high severity:

**Enforcement bypass**
- Any input that produces `allow` where the contract grants nothing
- Any way to make the mediator execute a call it decided to deny or hold
- Predicate evaluation that reaches outside the permitted expression language
- Contract signature or digest verification that can be satisfied without the key

**Evidence integrity**
- Producing a ledger record that verifies but does not reflect the decision made
- Modifying, deleting, or reordering a record without detection by `agentcap verify`
- Causing decisions to go unrecorded while calls still execute

**Budget and delegation**
- Exceeding a USD, call, or egress ceiling through concurrency
- Reaching a capability marked `nonDelegable` through a delegate
- Satisfying an approval gate as the agent itself
- Exceeding `delegation.maxDepth`

**Information disclosure**
- Secrets or credentials appearing in `argsRedacted` or in ledger output
- Private-key material appearing in logs, errors, or plan output

## Known and accepted limitations

These are documented rather than treated as vulnerabilities. They are the honest
boundary of what a mediator can do.

**Unmediated paths are not protected.** A mediator cannot intercept a call it
never sees. Direct SDK calls, shell side channels, browser sessions, ambient
credentials, and alternate transports bypass AgentCap by construction. This is
conformance case C14, it is declared in the conformance output, and it is
disclosed in the README. The mitigation is deployment, not a code change: remove
ambient credentials and route tool access through the mediator.

**Prompt injection is not prevented.** AgentCap reduces the *consequence* of a
successfully injected instruction by denying the action it would need. It does
not detect or filter the injection. Report prompt-injection *bypasses of the
policy layer* — a case where injected content causes an action the contract
should have stopped — but "the agent followed an injected instruction" is
expected behaviour, not a vulnerability.

**Shadow mode does not block.** By design. It records what enforcement would
have done.

## What we ask of deployments

- Do not run with `--no-verify` outside local development.
- Rotate the signing key when a principal changes.
- Treat the ledger as evidence: back it up, and verify the chain before relying
  on it in an investigation.
- Assume the agent host is hostile. The ledger's value comes from being
  verifiable by someone who does not trust that host.
