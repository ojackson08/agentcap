"""AgentCap: a capability-contract enforcement point for AI agent tool calls.

An agent should not act because it holds a credential. It should act because it
holds a signed, short-lived, narrowly-scoped contract that says exactly what it
may do — and something must stand between the agent and the real world
enforcing it, recording what happened in a form that survives not trusting the
agent.

    from agentcap import load, Mediator, Ledger, ToolCall

    contract = load("contracts/recon.yaml")
    ledger = Ledger.open(".agentcap/ledger.jsonl")
    mediator = Mediator(contract, ledger=ledger, shadow=False)

    outcome = mediator.evaluate(ToolCall(tool="aws:s3:DeleteObject", args={...}))
    # -> deny: tool 'aws:s3:DeleteObject' is not granted by this contract
"""

__version__ = "1.0.0"

from .compile import CompiledPolicy, compile_contract, evaluate_predicate, render_policy
from .contract import (
    Contract,
    ContractError,
    diff,
    generate_keypair,
    load,
    load_raw,
    loads,
    parse,
    render_diff,
    sign,
    verify_signature,
)
from .leases import Budget, BudgetExceeded, LeaseStore, RateLimiter
from .ledger import Ledger, LedgerError, make_signer
from .mediator import ALLOW, APPROVE, DENY, Mediator, Outcome, ToolCall, build_mediator

__all__ = [
    "__version__",
    "ALLOW",
    "APPROVE",
    "DENY",
    "Budget",
    "BudgetExceeded",
    "CompiledPolicy",
    "Contract",
    "ContractError",
    "LeaseStore",
    "Ledger",
    "LedgerError",
    "Mediator",
    "Outcome",
    "RateLimiter",
    "ToolCall",
    "build_mediator",
    "compile_contract",
    "diff",
    "evaluate_predicate",
    "generate_keypair",
    "load",
    "load_raw",
    "loads",
    "make_signer",
    "parse",
    "render_diff",
    "render_policy",
    "sign",
    "verify_signature",
]
