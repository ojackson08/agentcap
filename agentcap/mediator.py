"""The mediator: the policy enforcement point between an agent and its tools.

This is the component the whole system exists to operate. Its job is narrow and
its defaults are hostile on purpose:

    unknown tool              -> deny
    unpinned tool definition  -> deny
    expired contract          -> deny
    unverifiable signature    -> deny
    unevaluable predicate     -> deny
    budget would be exceeded  -> deny
    ledger unavailable        -> deny

Every one of those is a fail-closed path. The only way to reach `allow` is to
satisfy a specific, previously-approved, bounded capability.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .compile import (
    CompiledPolicy,
    CompileError,
    compile_contract,
    evaluate_predicate,
    match_pattern,
    tool_is_non_delegable,
)
from .contract import Contract, ContractError, canonical_json, sha256_of, verify_signature
from .ledger import Ledger, make_signer, redact
from .leases import Budget, BudgetExceeded, LeaseStore, RateLimiter, estimate_cost, estimate_egress


# --------------------------------------------------------------------------
# Outcomes
# --------------------------------------------------------------------------

ALLOW = "allow"
DENY = "deny"
APPROVE = "approve"


@dataclass
class Outcome:
    """The result of one enforcement decision.

    `decision` distinguishes three states, and callers must respect all three:

        allow    the call may proceed
        approve  the call is HELD pending an out-of-band human decision;
                 it must not proceed now, and the agent cannot satisfy the gate
        deny     the call must not proceed

    `allowed` is True only for `allow`. Treating `approve` as anything other
    than "do not execute yet" defeats the gate.
    """

    decision: str
    reason: str
    tool: str
    record_hash: str | None = None
    approval_id: str | None = None
    lease: dict | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "tool": self.tool,
            "recordHash": self.record_hash,
            "approvalId": self.approval_id,
            "lease": self.lease,
        }


@dataclass
class ToolCall:
    """A normalized tool invocation, in the shape the mediator evaluates."""

    tool: str
    args: dict = field(default_factory=dict)
    digest: str | None = None
    taint: list[str] = field(default_factory=list)
    parent_agent_id: str | None = None
    delegation_depth: int = 0


@dataclass
class ApprovalRequest:
    """An out-of-band human decision. The agent cannot satisfy this itself."""

    approval_id: str
    tool: str
    args_redacted: dict
    contract_name: str
    principal: str
    requested_at: str
    reason: str


# --------------------------------------------------------------------------
# The mediator
# --------------------------------------------------------------------------

class Mediator:
    """Enforces one contract against every tool call."""

    def __init__(
        self,
        contract: Contract,
        *,
        ledger: Ledger | None = None,
        lease_store: LeaseStore | None = None,
        rate_limiter: RateLimiter | None = None,
        shadow: bool = True,
        verify_signature_required: bool = True,
        public_key_path: str | os.PathLike | None = None,
        approval_sink: Callable[[ApprovalRequest], None] | None = None,
        tool_cost_overrides: dict | None = None,
        tool_egress_overrides: dict | None = None,
        now: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.contract = contract
        self.policy: CompiledPolicy = compile_contract(contract.raw)
        self.ledger = ledger
        self.lease_store = lease_store
        self.rate_limiter = rate_limiter
        self.shadow = shadow
        self.verify_signature_required = verify_signature_required
        self.public_key_path = public_key_path
        self.approval_sink = approval_sink
        self.tool_cost_overrides = tool_cost_overrides or {}
        self.tool_egress_overrides = tool_egress_overrides or {}
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._pending_approvals: dict[str, ApprovalRequest] = {}
        self._decision_count = 0

    # -- setup checks ------------------------------------------------------
    def preflight(self) -> list[str]:
        """Reasons this mediator cannot enforce anything.

        A mediator that cannot prove its own preconditions must not run. This
        returns the list so callers can refuse to start rather than fail open.
        """
        problems: list[str] = []

        if self.contract.is_expired(self._now()):
            problems.append(
                f"contract {self.contract.name!r} expired at "
                f"{self.contract.raw['metadata']['expires']}"
            )

        if self.verify_signature_required:
            if not self.contract.signature:
                problems.append(
                    f"contract {self.contract.name!r} is unsigned and "
                    "signature verification is required"
                )
            elif not verify_signature(self.contract, self.public_key_path):
                problems.append(
                    f"contract {self.contract.name!r} signature does not verify against "
                    "the configured public key"
                )

        if self.ledger is None:
            problems.append(
                "no ledger configured; a decision that is not recorded is not enforceable"
            )

        return problems

    # -- identity binding --------------------------------------------------
    def _bind_identity(self, call: ToolCall) -> str:
        """Resolve the calling agent's identity. Absence is a deny, not a default."""
        return call.parent_agent_id or self.contract.workload

    # -- the decision ------------------------------------------------------
    def evaluate(self, call: ToolCall) -> Outcome:
        """Decide one tool call. Always returns; never raises on a policy problem."""
        self._decision_count += 1

        decision, reason, lease = self._decide(call)

        # Shadow mode records what enforcement *would* have done without
        # stopping anything. This is the default on install, because a mediator
        # that blocks legitimate work on day one gets uninstalled on day one.
        effective = decision
        approval_id = None
        if decision == APPROVE:
            request = self._raise_approval(call, reason)
            approval_id = request.approval_id

        if self.shadow:
            if decision == DENY:
                effective = ALLOW
                reason = f"[shadow] would deny: {reason}"
            elif decision == APPROVE:
                effective = ALLOW
                reason = f"[shadow] would require approval: {reason}"

        record_hash = self._record(call, decision, reason, lease)

        return Outcome(
            decision=effective,
            reason=reason,
            tool=call.tool,
            record_hash=record_hash,
            approval_id=approval_id,
            lease=lease,
        )

    def _decide(self, call: ToolCall) -> tuple[str, str, dict | None]:
        """The deterministic core. Order matters: cheapest and most certain first."""

        # 1. Contract validity.
        if self.contract.is_expired(self._now()):
            return DENY, "contract expired", None

        if self.verify_signature_required:
            if not self.contract.signature:
                return DENY, "contract is unsigned", None
            if not verify_signature(self.contract, self.public_key_path):
                return DENY, "contract signature does not verify", None

        # 2. Is the tool granted at all? Default deny.
        granted = self.policy.tools.get(call.tool)
        if granted is None:
            return DENY, f"tool {call.tool!r} is not granted by this contract", None

        # 3. Is the tool definition the one that was approved?
        if granted.get("digest"):
            if not call.digest:
                return DENY, (
                    f"tool {call.tool!r} is pinned but the call supplied no definition "
                    "digest; an unpinned invocation is not the approved artifact"
                ), None
            if call.digest != granted["digest"]:
                return DENY, (
                    f"tool definition drift: call digest {call.digest[:24]}... does not "
                    f"match pinned {granted['digest'][:24]}..."
                ), None

        # 4. Argument predicates.
        predicates = self.policy.predicates.get(call.tool, [])
        context = {
            "args": call.args,
            "tool": call.tool,
            "agent": self._bind_identity(call),
            "delegation_depth": call.delegation_depth,
            "taint": list(call.taint),
            "principal": self.policy.principal,
        }
        for predicate in predicates:
            try:
                satisfied = evaluate_predicate(predicate, context)
            except CompileError as exc:
                return DENY, f"argument predicate could not be evaluated: {exc}", None
            if not satisfied:
                return DENY, f"argument predicate not satisfied: {predicate}", None

        # 5. Data-flow: may this call receive values from those sources?
        for rule in self.policy.dataflow:
            if rule["from"] in call.taint:
                for sink_pattern in rule["deny"]:
                    if match_pattern(sink_pattern, call.tool):
                        return DENY, (
                            f"data flow blocked: values labelled {rule['from']!r} may not "
                            f"reach {call.tool!r}"
                        ), None

        # 6. Delegation depth.
        if call.delegation_depth > self.policy.max_delegation_depth:
            return DENY, (
                f"delegation depth {call.delegation_depth} exceeds contract limit "
                f"{self.policy.max_delegation_depth}"
            ), None

        if call.parent_agent_id and tool_is_non_delegable(self.policy, call.tool):
            return DENY, (
                f"tool {call.tool!r} is marked non-delegable and may not be called "
                "through a delegate"
            ), None

        # 7. Per-tool call ceiling.
        ceiling = granted.get("maxCalls")
        if ceiling is not None and self.lease_store is not None:
            state = self.lease_store.state(self.contract.name)
            if state.tool_calls >= ceiling:
                return DENY, (
                    f"per-tool call ceiling reached: {state.tool_calls}/{ceiling}"
                ), None

        # 8. Budget. Atomic check-and-commit; nothing is consumed if this raises.
        cost = estimate_cost(call.tool, call.args, self.tool_cost_overrides)
        egress = estimate_egress(call.tool, call.args, self.tool_egress_overrides)
        budget = Budget.from_contract(self.contract.raw["spec"])
        budget_after: dict = {}
        if self.lease_store is not None and (
            budget.usd is not None or budget.tool_calls is not None or budget.egress_gib is not None
        ):
            try:
                state = self.lease_store.check_and_commit(
                    self.contract.name, budget, usd=cost, egress_gib=egress, tool_calls=1
                )
                budget_after = state.to_dict()
            except BudgetExceeded as exc:
                return DENY, f"budget denied: {exc}", None

        # 9. Rate limit.
        if self.rate_limiter is not None:
            try:
                self.rate_limiter.check(self.contract.name)
            except BudgetExceeded as exc:
                return DENY, f"rate denied: {exc}", None

        # 10. Approval gate. Checked last so that a call which is already
        #     denied for a substantive reason does not generate approval noise.
        if granted.get("requireApproval"):
            return APPROVE, f"tool {call.tool!r} requires human approval", None

        lease = {
            "kind": "scoped",
            "tool": call.tool,
            "expires": (self._now() + dt.timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        return ALLOW, "granted by contract", lease

    # -- approvals ---------------------------------------------------------
    def _raise_approval(self, call: ToolCall, reason: str) -> ApprovalRequest:
        digest = hashlib.sha256(
            canonical_json({"tool": call.tool, "args": call.args, "t": self._now().isoformat()})
            .encode("utf-8")
        ).hexdigest()[:12]
        request = ApprovalRequest(
            approval_id=f"apr_{digest}",
            tool=call.tool,
            args_redacted=redact(call.args),
            contract_name=self.contract.name,
            principal=self.policy.principal,
            requested_at=self._now().isoformat().replace("+00:00", "Z"),
            reason=reason,
        )
        self._pending_approvals[request.approval_id] = request
        if self.approval_sink is not None:
            self.approval_sink(request)
        return request

    def resolve_approval(self, approval_id: str, approved: bool, resolver: str) -> bool:
        """Record an out-of-band decision. The resolver is a distinct principal.

        An agent cannot call this in its own favour: the resolver must be a
        different identity from the contract's workload, and that is checked.
        """
        request = self._pending_approvals.get(approval_id)
        if request is None:
            return False
        if resolver == self.contract.workload:
            raise ContractError(
                "approval resolver must be a different principal from the agent's workload"
            )
        self._pending_approvals.pop(approval_id, None)
        if self.ledger is not None:
            self.ledger.append(
                contract=self.contract,
                policy_hash=self.policy.policy_hash(),
                agent_id=resolver,
                tool=request.tool,
                args={"approval_id": approval_id, "approved": approved},
                decision=ALLOW if approved else DENY,
                reason=f"human approval {'granted' if approved else 'refused'} by {resolver}",
                signer=make_signer(),
            )
        return True

    @property
    def pending_approvals(self) -> list[ApprovalRequest]:
        return list(self._pending_approvals.values())

    # -- recording ---------------------------------------------------------
    def _record(
        self, call: ToolCall, decision: str, reason: str, lease: dict | None
    ) -> str | None:
        if self.ledger is None:
            return None
        budget_after: dict = {}
        if self.lease_store is not None:
            budget_after = self.lease_store.state(self.contract.name).to_dict()

        entry = self.ledger.append(
            contract=self.contract,
            policy_hash=self.policy.policy_hash(),
            agent_id=self._bind_identity(call),
            parent_agent_id=call.parent_agent_id,
            delegation_depth=call.delegation_depth,
            tool=call.tool,
            tool_digest=call.digest,
            args=call.args,
            decision=decision,
            reason=reason,
            budget_after=budget_after,
            lease=lease,
            signer=make_signer(),
        )
        return entry.hash()

    # -- introspection -----------------------------------------------------
    def explain(self) -> str:
        from .compile import render_policy

        return render_policy(self.policy)


# --------------------------------------------------------------------------
# Convenience: build a mediator from files
# --------------------------------------------------------------------------

def build_mediator(
    contract_path: str | os.PathLike,
    *,
    ledger_path: str | os.PathLike | None = None,
    state_dir: str | os.PathLike | None = None,
    shadow: bool = True,
    require_signature: bool = True,
    public_key_path: str | os.PathLike | None = None,
) -> Mediator:
    """Construct a mediator with the standard local wiring."""
    from .contract import load as load_contract

    contract = load_contract(contract_path)
    state = Path(state_dir) if state_dir else Path(".agentcap")
    state.mkdir(parents=True, exist_ok=True)

    ledger = Ledger.open(ledger_path or (state / "ledger.jsonl"))
    lease_store = LeaseStore(state / "leases.json")
    rate_limiter = RateLimiter(state / "rate.json")

    return Mediator(
        contract,
        ledger=ledger,
        lease_store=lease_store,
        rate_limiter=rate_limiter,
        shadow=shadow,
        verify_signature_required=require_signature,
        public_key_path=public_key_path,
    )
