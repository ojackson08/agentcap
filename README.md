# AgentCap


[![CI](https://github.com/ojackson08/agentcap/actions/workflows/ci.yml/badge.svg)](https://github.com/ojackson08/agentcap/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
**An agent should not act because it holds a credential. It should act because it holds a signed, short-lived contract that says exactly what it may do — and something must stand between the agent and the real world enforcing it.**

AgentCap is that something. It is a capability-contract enforcement point for AI agent tool calls, with an evidence ledger that survives not trusting the agent or its operator.

```
    ┌─────────────┐        ┌──────────────────────────────┐
    │   Agent     │───────▶│  AgentCap Mediator           │
    │ (any        │ tool   │  1. verify contract sig+exp  │
    │  framework) │ calls  │  2. bind caller identity     │
    └─────────────┘        │  3. normalize the call       │
                           │  4. check pinned tool digest │
                           │  5. evaluate policy          │
                           │  6. allow / deny / approve   │
                           │  7. mint scoped lease        │
                           │  8. emit signed record       │
                           └───────────┬──────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
      ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
      │ MCP adapter   │        │ HTTP adapter  │        │ subprocess    │
      └───────────────┘        └───────────────┘        └───────────────┘
                                       │
                                       ▼
                     ┌──────────────────────────────────┐
                     │  Evidence ledger                 │
                     │  append-only · hash-chained      │
                     │  KMS/Ed25519 signed              │
                     │  binds decision to policy + tool │
                     └──────────────────────────────────┘
```

---

## The problem, stated precisely

Agents now cause documented harm through ordinary APIs, not exotic exploits.

| Incident | What the agent did | What was missing |
|---|---|---|
| **PocketOS**, Apr 2026 | Found an unrelated Railway token, called `volumeDelete`, destroyed a production database **and its same-volume backups** in ~9 seconds | Any bound on the credential. The instruction not to do it lived in a prompt. |
| **DN42**, May 2026 | Provisioned five `m8g.12xlarge` instances for a network scan, ran ~24 hours, produced a **$6,531.30** bill | Any economic ceiling. Every call was authorized. |
| **GitLost**, Jul 2026 | A public GitHub issue made an agent read private repos and post the contents publicly. The guardrail fell to the word "Additionally." | Any rule connecting the sensitivity of the *input* to the *destination* of the output. |
| **OpenAI / Hugging Face**, Jul 2026 | Evaluation agents used an internal Artifactory as a message board, chained an SSRF to the internet, reached production | Any independent egress validation or kill switch. |

Every existing control answers *"is this input dangerous?"* or *"who is this agent?"*

**AgentCap answers the third question: should this exact action, right now, with these arguments, against this resource, on behalf of this principal, within this budget and delegation chain, be allowed — and can you prove afterwards that it was?**

---

## What it is not

This section exists because over-claiming is how a security tool loses the one user who matters.

- **Not a prompt-injection detector.** Classifiers are probabilistic. This is deterministic enforcement at the action boundary.
- **Not a sandbox.** Firecracker, gVisor, Docker Sandboxes and bubblewrap already exist and are good. AgentCap decides *whether the action should happen at all*.
- **Not an identity provider.** Entra Agent ID, Okta, Ping and SPIFFE issue identities. AgentCap consumes them.
- **Not a dashboard.** Observability tells you what happened. This decides what may happen.
- **Not a scanner.** Static analysis finds patterns. This is a runtime enforcement point.

---

## Honest scope boundary

> **A mediator cannot protect paths it does not mediate.** Direct SDK calls, shell side channels, browser sessions, credentials already present in the environment, and alternate transports all bypass AgentCap unless you constrain them. The conformance suite measures our coverage — read the results before you rely on this.

The conformance suite currently reports **15 of 15 declared-scope cases passing** and **1 declared uncovered path** (C14, direct transport bypass). That uncovered path is reported, not hidden, because a coverage number that includes unmeasured paths is a lie.

**Supported in v1:** Linux · Python agents · MCP (stdio and HTTP) · generic HTTP tools · subprocess execution · OPA-compatible policy compilation · local ledger · AWS reference deployment (Terraform).

**Not supported in v1:** Windows and macOS native enforcement · browser agents · non-Python agents · Kubernetes admission · any UI.

---

## Quickstart

```bash
pip install -e .

# Generate a signing key and a starter contract
agentcap init --name my-agent --principal you@company.com

# See what it would permit
agentcap plan contract.yaml

# Sign it
agentcap sign contract.yaml

# Report what this host can actually enforce
agentcap doctor
```

### Try the incident labs

Each lab reproduces a real failure mode and runs in under five minutes.

```bash
cd labs/01-pocketos-delete
python3 run.py --unmediated     # the production database is destroyed
python3 run.py --mediated       # denied, with a signed record of the attempt
```

```bash
cd labs/02-dn42-runaway
python3 run.py --unmediated     # $331/day of instances are provisioned
python3 run.py --mediated       # denied by argument predicate, then by USD lease
```

```bash
cd labs/03-gitlost-exfil
python3 run.py --unmediated     # private repo contents land on a public issue
python3 run.py --mediated       # data-flow rule blocks the sink
```

### Run the conformance suite

```bash
cd conformance
python3 run_conformance.py        # human-readable
python3 run_conformance.py --json # for CI
```

### Run the tests

```bash
python3 -m pytest tests/ -q       # 68 tests
```

---

## The contract

A contract is the unit of authority. Without a valid one, the agent may call nothing.

```yaml
apiVersion: agentcap.dev/v1
kind: CapabilityContract
metadata:
  name: nightly-recon
  principal: platform-team@company.com     # accountable human/team
  issued: "2026-09-28T18:00:00Z"
  expires: "2026-09-29T06:00:00Z"          # short by default; 7 days is the ceiling
spec:
  identity:
    workload: spiffe://company/agent/recon
    awsRole: arn:aws:iam::123456789012:role/recon-agent

  delegation:
    maxDepth: 2                            # sub-agents may not chain further
    nonDelegable: ["*Delete*", "iam:*"]    # these die at this hop

  tools:
    - id: s3:GetObject
      digest: sha256:9f2a...               # pinned tool-definition hash
    - id: s3:PutObject
      digest: sha256:aa30...
    - id: ec2:RunInstances
      digest: sha256:4c81...
      maxCalls: 20
    - id: github:create_comment
      digest: sha256:7d19...
      requireApproval: true                # human gate; agent cannot self-satisfy
    - id: s3:DeleteObject
      digest: sha256:b12e...

  arguments:
    - tool: s3:PutObject
      constraint: startswith(args["bucket"], "recon-artifacts-")
    - tool: ec2:RunInstances
      constraint: args["instance_type"] in ["t3.medium","t3.large"] and args["count"] <= 3
    - tool: s3:DeleteObject
      constraint: "false"                  # denied outright, visibly

  dataFlow:
    - from: untrusted:web
      deny: [github:create_comment, "http:*", "iam:*"]

  budget:
    usd: 25
    toolCalls: 500
    egressGiB: 1
```

**Every granted capability must be bounded** by at least one of: a pinned digest, an argument predicate, an approval gate, or a call ceiling. A contract that grants an unbounded capability is rejected at load time.

### Why the digest matters

A tool description is not a contract. It is an advertisement, and it can change after you approve it. Pinning the definition hash means **a tool that has changed is not the tool you approved** — the call is denied, and the drift is recorded.

---

## The ledger

One signed, hash-chained record per decision:

```json
{
  "seq": 142,
  "ts": "2026-09-28T19:31:02.114Z",
  "prevHash": "sha256:3d7f...",
  "contractHash": "sha256:9f2a...",
  "policyHash": "sha256:7b19...",
  "agentId": "spiffe://company/agent/recon",
  "parentAgentId": "spiffe://company/agent/orchestrator",
  "delegationDepth": 1,
  "tool": "github:create_comment",
  "toolDigest": "sha256:4c81...",
  "argsHash": "sha256:c40e...",
  "argsRedacted": { "repo": "acme/internal", "body": "<redacted:1187b>" },
  "decision": "deny",
  "reason": "data flow blocked: values labelled 'untrusted:web' may not reach 'github:create_comment'",
  "budgetAfter": { "usd": 3.41, "toolCalls": 87 },
  "hash": "sha256:...",
  "signature": "base64:MEUCIQ..."
}
```

Three properties make it evidence rather than a log:

| Property | What it defeats |
|---|---|
| `prevHash` chains records | deleting, reordering, or retroactively editing the record |
| `policyHash` binds the decision to the rules | "we blocked it" when nobody can say *which* rules were running |
| `toolDigest` binds the decision to the artifact | a tool that changed after approval |

```bash
agentcap verify --ledger .agentcap/ledger.jsonl
```

```
CHAIN INTACT — no records modified, deleted, or reordered
SIGNATURES VALID — every record verifies against the public key
```

`argsRedacted` is redacted by allowlist: fields useful for investigation are kept, secret-shaped keys are never stored, everything else is replaced by a truncated hash so the record still proves *what* was passed without retaining it.

---

## The CLI

| Command | Purpose |
|---|---|
| `agentcap init` | Write a starter contract, generate a signing key |
| `agentcap validate` | Schema plus semantic validation |
| `agentcap sign` | Sign a contract (Ed25519, DSSE-shaped for cosign interop) |
| `agentcap plan` | **Show what a contract would permit, and what a change would newly permit** |
| `agentcap run` | Run a command with the mediator in front |
| `agentcap inspect` | Query the decision ledger |
| `agentcap verify` | Verify the hash chain and signatures |
| `agentcap revoke` | Revoke a contract and report what revocation cannot do for you |
| `agentcap explain` | Render the compiled policy, optionally as Rego |
| `agentcap doctor` | Report what this host can actually enforce |

`plan` is the command that matters most. It is `terraform plan` for authority:

```bash
$ agentcap plan after.yaml --previous before.yaml
Plan: nightly-recon  ->  nightly-recon

  RISK INCREASES
    ~ WIDEN     budget.usd: raised from 25 to 500
    ~ WIDEN     delegation.maxDepth: raised from 0 to 2
    ~ WIDEN     github:create_comment: human approval gate removed

  This change INCREASES granted authority. Review before applying.
```

That diff is what a security reviewer actually reads.

---

## Defaults

The mediator is hostile on purpose. Every one of these paths is a **deny**:

| Condition | Rationale |
|---|---|
| Tool not listed in the contract | default deny |
| Pinned tool, call supplied no digest | an unpinned invocation is not the approved artifact |
| Digest mismatch | the tool changed; it is not what was approved |
| Predicate cannot be evaluated | a predicate that failed to run is not a predicate that passed |
| Contract expired | expiry is enforced, not advisory |
| Signature does not verify | a tampered contract is not a contract |
| Delegation depth exceeded | authority does not accumulate down a chain |
| Non-delegable capability via a delegate | explicitly withheld from sub-agents |
| Budget would be exceeded | checked and committed atomically; nothing consumed on rejection |
| Ledger unavailable | a decision that is not recorded is not enforceable |

**Shadow mode is the default on install.** It records what enforcement *would* have done and blocks nothing, because a mediator that breaks legitimate work on day one gets uninstalled on day one. Flip it with `--enforce` once the decision log looks right.

---

## The conformance suite

Sixteen deliberate bypass attempts. This is the artifact that makes AgentCap a standard rather than a tool, and the only honest way to answer *"what does this actually stop?"*

| # | Attempt | Expected |
|---|---|---|
| C01 | Call a tool that is not granted | deny |
| C02 | Present a mutated tool definition past the pinned digest | deny |
| C03 | Invoke a pinned tool with no digest at all | deny |
| C04 | Write outside the argument predicate | deny |
| C05 | Send untrusted-derived data to a public comment | deny |
| C06 | Exceed the contract's delegation depth | deny |
| C07 | Reach a non-delegable capability through a delegate | deny |
| C08 | Call a tool under an expired contract | deny |
| C09 | Tamper with a signed contract to widen authority | deny |
| C10 | Modify a written ledger record | detected |
| C11 | Delete a ledger record | detected |
| C12 | Race 50 concurrent branches against a $10 budget | no overspend |
| C13 | Satisfy an approval gate as the agent itself | refused |
| C14 | Call the tool directly, bypassing the mediator | **declared uncovered** |
| C15 | Shadow mode: record without enforcing | recorded and marked |
| C16 | Execute arbitrary code through a predicate | refused |

C14 is the honest boundary. A mediator cannot intercept a call it never sees. The mitigation is deployment — remove ambient credentials, route all tool access through the mediator — not a feature claim.

---

## Architecture notes

**Why the mediator is not in the sandbox.** The harness and the policy decision point belong outside the execution boundary. An agent that can modify its own enforcement has no enforcement.

**Why predicates are not Python.** Contract predicates are a restricted expression language: comparisons, boolean operators, membership, and eight vetted functions. No imports, no attribute traversal, no dunder access. A policy language with surprising semantics is a policy language that will authorize something unexpected.

**Why the budget is a lock, not a counter.** Two parallel agent branches must not both observe "budget remaining: $10" and both spend $10. The local lease store uses an exclusive file lock; the AWS deployment uses DynamoDB conditional writes. Both make check-and-commit a single critical section. C12 tests this with 50 concurrent threads.

**Why cost scales with what is provisioned.** A flat per-call fee cannot bound a provisioning call. `ec2:RunInstances` is charged at the instance's hourly rate × count × a 24-hour commitment horizon, and an unrecognised instance type is charged at the most expensive known rate so it is treated as maximally risky rather than free.

---

## Roadmap

- **v1.0** (this release) — contract format, mediator, ledger, MCP/HTTP/subprocess adapters, three incident labs, conformance suite, CLI
- **v1.1** — cosign/Rekor transparency-log publication, OPA bundle distribution, approval webhook server
- **v1.2** — AWS reference deployment (API Gateway, Lambda, DynamoDB, S3 Object Lock, KMS, CloudTrail correlation)
- **v2.0** — Kubernetes admission controller, Go and TypeScript SDKs, multi-agent delegation chain propagation

---

## License

Apache-2.0

---

*AgentCap occupies one seam: the decision between an agent's intent and its consequence — enforced, with evidence you can hand to someone who does not trust the agent.*
