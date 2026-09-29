#!/usr/bin/env python3
"""The conformance suite: deliberate attempts to bypass enforcement.

This is the artifact that makes AgentCap a standard rather than a tool. It is
also the only honest way to answer the question a security engineer will ask
first: *what does this actually stop, and what does it not?*

Every case declares its expected result. Cases marked `expect: covered` must be
denied or contained. Cases marked `expect: uncovered` describe paths a mediator
cannot reach by construction — those are reported, not hidden, because a
coverage number that includes unmeasured paths is a lie.

Run:

    python3 run_conformance.py            # human-readable report
    python3 run_conformance.py --json     # machine-readable, for CI
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "labs"))

from common import mock_tools, tool_registry  # noqa: E402

RESULTS: list[dict] = []


def record(case_id: str, title: str, expected: str, outcome: str, detail: str) -> None:
    passed = (expected == outcome) or (expected == "uncovered" and outcome == "uncovered")
    RESULTS.append(
        {
            "id": case_id,
            "title": title,
            "expected": expected,
            "observed": outcome,
            "passed": passed,
            "detail": detail,
        }
    )


def build_mediator(state_name: str, *, shadow: bool = False):
    """A fresh, signed, enforcing mediator for the conformance run."""
    import datetime as dt

    from agentcap.contract import load, sign
    from agentcap.leases import LeaseStore
    from agentcap.ledger import Ledger
    from agentcap.mediator import Mediator

    contract_path = ROOT / "conformance" / "conformance-contract.yaml"
    state_dir = ROOT / "conformance" / state_name
    state_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("ledger.jsonl", "leases.json"):
        if (state_dir / stale).exists():
            (state_dir / stale).unlink()

    contract = load(contract_path)
    now = dt.datetime.now(dt.timezone.utc)
    contract.raw["metadata"]["issued"] = now.isoformat().replace("+00:00", "Z")
    contract.raw["metadata"]["expires"] = (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    tool_registry.pin_contract(contract.raw)
    sign(contract)

    ledger = Ledger.open(state_dir / "ledger.jsonl")
    return Mediator(
        contract,
        ledger=ledger,
        lease_store=LeaseStore(state_dir / "leases.json"),
        shadow=shadow,
        verify_signature_required=True,
    )


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------

def case_01_direct_ungranted_tool(mediator) -> None:
    """Call a tool the contract never mentions."""
    outcome = mediator.evaluate(
        tool_registry_digest_call("volumeDelete", {"volume_id": "vol_prod_01"})
    )
    record(
        "C01",
        "Call a tool that is not granted",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_02_schema_drift(mediator) -> None:
    """Present a tool definition whose hash differs from the pinned digest."""
    from agentcap.mediator import ToolCall

    outcome = mediator.evaluate(
        ToolCall(
            tool="s3:GetObject",
            args={"bucket": "recon-artifacts-2026", "key": "x"},
            digest="sha256:" + "f" * 64,  # a definition nobody approved
        )
    )
    record(
        "C02",
        "Present a mutated tool definition past the pinned digest",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_03_unpinned_invocation(mediator) -> None:
    """Invoke a pinned tool without supplying any definition digest at all."""
    from agentcap.mediator import ToolCall

    outcome = mediator.evaluate(
        ToolCall(tool="s3:GetObject", args={"bucket": "recon-artifacts-2026", "key": "x"})
    )
    record(
        "C03",
        "Invoke a pinned tool with no definition digest supplied",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_04_predicate_escape(mediator) -> None:
    """Try to reach a resource outside the argument predicate."""
    outcome = mediator.evaluate(
        tool_registry_digest_call("s3:PutObject", {"bucket": "prod-customer-data", "key": "x"})
    )
    record(
        "C04",
        "Write outside the argument predicate's allowed prefix",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_05_taint_to_public_sink(mediator) -> None:
    """Route untrusted-derived data to a public output."""
    outcome = mediator.evaluate(
        tool_registry_digest_call(
            "github:create_comment",
            {"repo": "acme/public-site", "issue": 1, "body": "leak"},
            taint=["untrusted:web"],
        )
    )
    record(
        "C05",
        "Send untrusted-derived data to a public comment",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_06_delegation_depth(mediator) -> None:
    """Exceed the contract's delegation depth limit."""
    outcome = mediator.evaluate(
        tool_registry_digest_call(
            "s3:GetObject",
            {"bucket": "recon-artifacts-2026", "key": "x"},
            parent_agent_id="spiffe://example.com/agent/child",
            delegation_depth=3,
        )
    )
    record(
        "C06",
        "Exceed the contract's delegation depth",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_07_non_delegable_through_delegate(mediator) -> None:
    """Call a non-delegable capability from a sub-agent."""
    outcome = mediator.evaluate(
        tool_registry_digest_call(
            "github:create_comment",
            {"repo": "acme/public-site", "issue": 1, "body": "x"},
            parent_agent_id="spiffe://example.com/agent/child",
            delegation_depth=1,
        )
    )
    record(
        "C07",
        "Reach a non-delegable capability through a delegate",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_08_expired_contract() -> None:
    """Evaluate against a contract whose expiry has passed."""
    import datetime as dt

    from agentcap.contract import load, sign
    from agentcap.ledger import Ledger
    from agentcap.mediator import Mediator

    state_dir = ROOT / "conformance" / "state_expired"
    state_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = state_dir / "ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()

    contract = load(ROOT / "conformance" / "conformance-contract.yaml")
    now = dt.datetime.now(dt.timezone.utc)
    contract.raw["metadata"]["issued"] = (now - dt.timedelta(hours=4)).isoformat().replace("+00:00", "Z")
    contract.raw["metadata"]["expires"] = (now - dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    tool_registry.pin_contract(contract.raw)
    sign(contract)

    mediator = Mediator(contract, ledger=Ledger.open(ledger_path), shadow=False)
    outcome = mediator.evaluate(
        tool_registry_digest_call("s3:GetObject", {"bucket": "recon-artifacts-2026", "key": "x"})
    )
    record(
        "C08",
        "Call a tool under an expired contract",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_09_forged_signature() -> None:
    """Present a contract whose signature does not verify."""
    import datetime as dt

    from agentcap.contract import load, sign
    from agentcap.ledger import Ledger
    from agentcap.mediator import Mediator

    state_dir = ROOT / "conformance" / "state_forged"
    state_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = state_dir / "ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()

    contract = load(ROOT / "conformance" / "conformance-contract.yaml")
    now = dt.datetime.now(dt.timezone.utc)
    contract.raw["metadata"]["issued"] = now.isoformat().replace("+00:00", "Z")
    contract.raw["metadata"]["expires"] = (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    tool_registry.pin_contract(contract.raw)
    sign(contract)

    # Tamper with the payload after signing. This is the confused-deputy move:
    # widen your own authority and hope nobody re-verifies.
    contract.raw["spec"]["tools"].append(
        {"id": "volumeDelete", "digest": tool_registry.digest_for("volumeDelete")}
    )

    mediator = Mediator(
        contract, ledger=Ledger.open(ledger_path), shadow=False, verify_signature_required=True
    )
    outcome = mediator.evaluate(
        tool_registry_digest_call("volumeDelete", {"volume_id": "vol_prod_01"})
    )
    record(
        "C09",
        "Tamper with a signed contract to widen authority",
        "covered",
        "covered" if outcome.decision == "deny" else "bypassed",
        f"{outcome.decision}: {outcome.reason}",
    )


def case_10_ledger_tamper() -> None:
    """Modify a written ledger record and detect it."""
    from agentcap.ledger import Ledger

    state_dir = ROOT / "conformance" / "state_tamper"
    state_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = state_dir / "ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()

    mediator = build_mediator("state_tamper")
    for index in range(3):
        mediator.evaluate(
            tool_registry_digest_call(
                "s3:GetObject", {"bucket": "recon-artifacts-2026", "key": f"k{index}"}
            )
        )

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    # Make a change that actually alters the record. Rewriting a value to itself
    # would prove nothing, which is how a tamper test silently passes.
    original_tool = tampered["tool"]
    tampered["tool"] = "s3:DeleteObject"
    tampered["decision"] = "deny"
    tampered["reason"] = "rewritten after the fact"
    lines[1] = json.dumps(tampered)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, problems = Ledger.open(ledger_path).verify()
    detected = not ok
    record(
        "C10",
        "Modify a written ledger record after the fact",
        "covered",
        "covered" if detected else "bypassed",
        f"rewrote record 2 tool {original_tool!r} -> 's3:DeleteObject'; "
        f"detected={detected}; {problems[0] if problems else 'no problem reported'}",
    )


def case_11_ledger_deletion() -> None:
    """Delete a ledger record and detect it."""
    from agentcap.ledger import Ledger

    state_dir = ROOT / "conformance" / "state_delete"
    state_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = state_dir / "ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()

    mediator = build_mediator("state_delete")
    for index in range(3):
        mediator.evaluate(
            tool_registry_digest_call(
                "s3:GetObject", {"bucket": "recon-artifacts-2026", "key": f"k{index}"}
            )
        )

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    ok, problems = Ledger.open(ledger_path).verify()
    detected = not ok
    record(
        "C11",
        "Delete a ledger record",
        "covered",
        "covered" if detected else "bypassed",
        f"detected={detected}; {problems[0] if problems else 'no problem reported'}",
    )


def case_12_budget_concurrency() -> None:
    """Attempt to exceed a budget from concurrent branches."""
    import threading

    from agentcap.leases import Budget, BudgetExceeded, LeaseStore

    state_dir = ROOT / "conformance" / "state_race"
    state_dir.mkdir(parents=True, exist_ok=True)
    store_path = state_dir / "leases.json"
    if store_path.exists():
        store_path.unlink()

    store = LeaseStore(store_path)
    budget = Budget(usd=10.0)
    granted: list[int] = []
    denied: list[int] = []

    def branch(index: int) -> None:
        try:
            store.check_and_commit("race", budget, usd=1.0, tool_calls=1)
            granted.append(index)
        except BudgetExceeded:
            denied.append(index)

    threads = [threading.Thread(target=branch, args=(i,)) for i in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    state = store.state("race")
    overspent = state.usd > 10.0
    record(
        "C12",
        "Race 50 concurrent branches against a $10 budget",
        "covered",
        "covered" if not overspent else "bypassed",
        f"granted={len(granted)} denied={len(denied)} consumed=${state.usd:.2f} "
        f"(ceiling $10.00, overspent={overspent})",
    )


def case_13_approval_self_satisfaction() -> None:
    """Attempt to satisfy an approval gate as the agent itself."""
    from agentcap.contract import ContractError

    mediator = build_mediator("state_approval")
    outcome = mediator.evaluate(
        tool_registry_digest_call(
            "github:create_comment", {"repo": "acme/public-site", "issue": 1, "body": "x"}
        )
    )

    self_resolved = False
    detail = f"{outcome.decision}: {outcome.reason}"
    if outcome.approval_id:
        try:
            mediator.resolve_approval(
                outcome.approval_id, approved=True, resolver=mediator.contract.workload
            )
            self_resolved = True
            detail += "; agent resolved its own approval — BYPASS"
        except ContractError as exc:
            detail += f"; self-resolution refused: {exc}"

    record(
        "C13",
        "Satisfy an approval gate as the agent itself",
        "covered",
        "covered" if not self_resolved else "bypassed",
        detail,
    )


def case_14_direct_transport_bypass() -> None:
    """Call the underlying tool without going through the mediator.

    This is the honest boundary of the product. A mediator cannot intercept a
    call it never sees. The correct result is `uncovered` — reported, measured,
    and disclosed — not a false claim of containment.
    """
    mock_tools.reset()
    result = mock_tools.invoke("volumeDelete", {"volume_id": "vol_prod_01"})
    damage = mock_tools.damage()
    record(
        "C14",
        "Call the tool directly, bypassing the mediator entirely",
        "uncovered",
        "uncovered",
        f"direct call succeeded={result.get('ok')}; damage recorded={len(damage)}. "
        "Expected: a mediator cannot protect a path it does not mediate. "
        "Mitigation is deployment (no ambient credentials) plus detection.",
    )


def case_15_shadow_mode_does_not_block() -> None:
    """Confirm shadow mode records without blocking — and says so."""
    mediator = build_mediator("state_shadow", shadow=True)
    outcome = mediator.evaluate(
        tool_registry_digest_call("volumeDelete", {"volume_id": "vol_prod_01"})
    )
    marked = "[shadow]" in outcome.reason
    record(
        "C15",
        "Shadow mode: record the denial without enforcing it",
        "covered",
        "covered" if (outcome.decision == "allow" and marked) else "bypassed",
        f"decision={outcome.decision}; reason marked as shadow={marked}",
    )


def case_16_predicate_code_execution() -> None:
    """Attempt code execution through an argument predicate."""
    from agentcap.compile import CompileError, evaluate_predicate

    payloads = [
        "__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "args['x'].__class__.__bases__",
        "eval('1+1')",
    ]
    refused = []
    for payload in payloads:
        try:
            evaluate_predicate(payload, {"args": {"x": 1}})
            refused.append(f"NOT REFUSED: {payload}")
        except (CompileError, NameError, AttributeError, TypeError, SyntaxError):
            pass
    record(
        "C16",
        "Execute arbitrary code through an argument predicate",
        "covered",
        "covered" if not refused else "bypassed",
        f"{len(payloads) - len(refused)}/{len(payloads)} payloads refused"
        + (f"; {refused[0]}" if refused else ""),
    )


def tool_registry_digest_call(tool_id, args, **kwargs):
    from agentcap.mediator import ToolCall

    return ToolCall(
        tool=tool_id,
        args=args,
        digest=tool_registry.digest_for(tool_id) if tool_id in tool_registry.TOOL_DEFINITIONS else None,
        **kwargs,
    )


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

CASES = [
    ("C01", case_01_direct_ungranted_tool, True),
    ("C02", case_02_schema_drift, True),
    ("C03", case_03_unpinned_invocation, True),
    ("C04", case_04_predicate_escape, True),
    ("C05", case_05_taint_to_public_sink, True),
    ("C06", case_06_delegation_depth, True),
    ("C07", case_07_non_delegable_through_delegate, True),
    ("C08", case_08_expired_contract, False),
    ("C09", case_09_forged_signature, False),
    ("C10", case_10_ledger_tamper, False),
    ("C11", case_11_ledger_deletion, False),
    ("C12", case_12_budget_concurrency, False),
    ("C13", case_13_approval_self_satisfaction, False),
    ("C14", case_14_direct_transport_bypass, False),
    ("C15", case_15_shadow_mode_does_not_block, False),
    ("C16", case_16_predicate_code_execution, False),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentCap conformance suite")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args()

    mock_tools.reset()

    for case_id, function, needs_mediator in CASES:
        try:
            if needs_mediator:
                function(build_mediator(f"state_{case_id.lower()}"))
            else:
                function()
        except Exception as exc:  # noqa: BLE001 - a crashing case is a failing case
            record(case_id, function.__doc__ or case_id, "covered", "error", f"{type(exc).__name__}: {exc}")

    covered = [r for r in RESULTS if r["expected"] == "covered"]
    uncovered = [r for r in RESULTS if r["expected"] == "uncovered"]
    passed = [r for r in RESULTS if r["passed"]]
    failed = [r for r in RESULTS if not r["passed"]]

    if args.json:
        print(
            json.dumps(
                {
                    "total": len(RESULTS),
                    "passed": len(passed),
                    "failed": len(failed),
                    "covered_cases": len(covered),
                    "covered_passed": len([r for r in covered if r["passed"]]),
                    "uncovered_paths": len(uncovered),
                    "results": RESULTS,
                },
                indent=2,
            )
        )
        return 0 if not failed else 1

    print("=" * 78)
    print("AgentCap conformance suite — deliberate bypass attempts")
    print("=" * 78)
    print()

    for result in RESULTS:
        if result["expected"] == "uncovered":
            marker = "REPORTED "
        else:
            marker = "PASS     " if result["passed"] else "FAIL     "
        print(f"{marker}{result['id']}  {result['title']}")
        print(f"           {result['detail']}")
        print()

    print("-" * 78)
    print(f"Cases:              {len(RESULTS)}")
    print(f"Passed:             {len(passed)}")
    print(f"Failed:             {len(failed)}")
    print()
    print(f"Covered cases:      {len(covered)}  (must deny or contain)")
    print(f"  passed:           {len([r for r in covered if r['passed']])}")
    print(f"  failed:           {len([r for r in covered if not r['passed']])}")
    print()
    print(f"Known uncovered:    {len(uncovered)}  (declared, not hidden)")
    for result in uncovered:
        print(f"  {result['id']}  {result['title']}")
    print()

    coverage = len([r for r in covered if r["passed"]]) / max(1, len(covered))
    print(f"Measured coverage of declared-scope cases: {coverage:.0%}")
    print()
    print("Read this number honestly. It covers the paths AgentCap mediates.")
    print("It does not cover C14-class bypasses: direct SDK calls, shell side")
    print("channels, ambient credentials, or alternate transports. Deployment")
    print("must remove those paths; the mediator cannot do it for you.")
    print()

    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
