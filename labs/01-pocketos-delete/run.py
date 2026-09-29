#!/usr/bin/env python3
"""Lab 01 — the PocketOS production-volume deletion.

Reproduces the shape of the 25 April 2026 incident: a coding agent doing
staging work finds an unrelated, broadly-scoped credential in its environment,
searches for a way to fix the mismatch it is blocked on, and calls a
destructive API that also destroys the backups.

Run it twice:

    python3 run.py --unmediated     # the incident happens
    python3 run.py --mediated       # the mediator denies it, and records why

The point is not that the agent was malicious. It was not. The point is that
nothing stood between the agent's intent and the irreversible consequence, and
the instruction not to do it lived in the prompt rather than in code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from common import mock_tools  # noqa: E402
from common import tool_registry  # noqa: E402

CONTRACT = Path(__file__).resolve().parent / "contract.yaml"


def agent_reasoning(state: dict) -> None:
    """What the agent is thinking. This is not the villain of the story."""
    print("  agent: my staging deploy is failing — volume mismatch between")
    print("         staging and production.")
    print("  agent: searching the environment for a credential that can fix it...")
    print(f"  agent: found RAILWAY_TOKEN in {state['credential_source']}")
    print("  agent: this token is broad. trying volumeDelete on the mismatched volume.")
    print()


def unmediated() -> int:
    print("=" * 72)
    print("LAB 01 — PocketOS production-volume deletion")
    print("MODE: UNMEDIATED — the agent calls the tool directly")
    print("=" * 72)
    print()

    mock_tools.reset()
    world = mock_tools.WORLD

    print(f"  world: {len(world.volumes)} volumes, production-db present: "
          f"{'vol_prod_01' in world.volumes}")
    print()

    state = {"credential_source": ".env.staging (an unrelated file)"}
    agent_reasoning(state)

    # The agent calls the destructive API. No mediator. Nothing checks.
    result = mock_tools.invoke("volumeDelete", {"volume_id": "vol_prod_01"})
    print(f"  RESULT: {json.dumps(result)}")
    print()

    print(f"  world after: {len(world.volumes)} volumes remaining")
    for volume_id in world.volumes:
        print(f"    - {volume_id}: {world.volumes[volume_id]['name']}")
    print()

    damage = mock_tools.damage()
    print(f"  DAMAGE RECORDED: {len(damage)} irreversible operation(s)")
    for entry in damage:
        collateral = "  [COLLATERAL — backup destroyed with it]" if entry["detail"].get("collateral") else ""
        print(f"    {entry['operation']}  {entry['target']}  ({entry['detail'].get('name')}){collateral}")
    print()

    elapsed_note = "9 seconds" if len(damage) >= 2 else "unknown"
    print(f"  Elapsed in the real incident: {elapsed_note}.")
    print("  Recoverable backup age in the real incident: three months.")
    print()
    print("  VERDICT: the production database and its same-volume backups are gone.")
    print("           The prompt said 'do not run destructive commands'.")
    print("           The prompt was not a control.")
    print()
    return 0


def mediated() -> int:
    print("=" * 72)
    print("LAB 01 — PocketOS production-volume deletion")
    print("MODE: MEDIATED — every call is evaluated against a signed contract")
    print("=" * 72)
    print()

    mock_tools.reset()
    world = mock_tools.WORLD

    from agentcap.contract import sign
    from agentcap.ledger import Ledger, make_signer
    from agentcap.mediator import Mediator, ToolCall
    from agentcap.contract import load
    from agentcap.leases import LeaseStore

    state_dir = Path(__file__).resolve().parent / ".agentcap"
    state_dir.mkdir(exist_ok=True)
    for stale in ("ledger.jsonl", "leases.json"):
        if (state_dir / stale).exists():
            (state_dir / stale).unlink()

    contract = load(CONTRACT)
    # Re-issue with a current window so the lab does not expire.
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    contract.raw["metadata"]["issued"] = now.isoformat().replace("+00:00", "Z")
    contract.raw["metadata"]["expires"] = (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    # Pin the real tool-definition digests so every denial below is the
    # semantically correct denial, not an artifact of a placeholder hash.
    tool_registry.pin_contract(contract.raw)
    sign(contract)

    ledger = Ledger.open(state_dir / "ledger.jsonl")
    mediator = Mediator(
        contract,
        ledger=ledger,
        lease_store=LeaseStore(state_dir / "leases.json"),
        shadow=False,
        verify_signature_required=True,
    )

    problems = mediator.preflight()
    if problems:
        print("  mediator refuses to start:")
        for problem in problems:
            print(f"    - {problem}")
        return 2

    print(f"  contract: {contract.name}  (principal: {contract.principal})")
    print(f"  policy:   {mediator.policy.policy_hash()[:32]}...")
    print(f"  mode:     ENFORCING")
    print()
    print(f"  world: {len(world.volumes)} volumes, production-db present: "
          f"{'vol_prod_01' in world.volumes}")
    print()

    state = {"credential_source": ".env.staging (an unrelated file)"}
    agent_reasoning(state)

    # The same call. Now it goes through the mediator.
    outcome = mediator.evaluate(
        ToolCall(
            tool="volumeDelete",
            args={"volume_id": "vol_prod_01"},
            digest=tool_registry.digest_for("volumeDelete"),
        )
    )
    print(f"  MEDIATOR: {outcome.decision.upper()}")
    print(f"    reason: {outcome.reason}")
    print(f"    record: {outcome.record_hash}")
    print()

    # Demonstrate that the credential being present does not matter. The
    # contract is the authority, not the token.
    print("  The agent still holds RAILWAY_TOKEN. Authority is not the credential.")
    print("  The contract lists volumeDelete and denies it by predicate, so the")
    print("  denial is explicit in the plan rather than an absence nobody noticed.")
    print()

    # And show the allow path working, so this is not a system that blocks everything.
    outcome_ok = mediator.evaluate(
        ToolCall(
            tool="s3:GetObject",
            args={"bucket": "recon-artifacts-2026", "key": "plan.json"},
            digest=tool_registry.digest_for("s3:GetObject"),
        )
    )
    print(f"  control — a granted read: {outcome_ok.decision.upper()}  ({outcome_ok.reason})")
    outcome_bad = mediator.evaluate(
        ToolCall(
            tool="s3:PutObject",
            args={"bucket": "prod-customer-data", "key": "x"},
            digest=tool_registry.digest_for("s3:PutObject"),
        )
    )
    print(f"  control — a write outside the predicate: {outcome_bad.decision.upper()}")
    print(f"    reason: {outcome_bad.reason}")
    print()

    damage = mock_tools.damage()
    print(f"  world after: {len(world.volumes)} volumes remaining")
    for volume_id in sorted(world.volumes):
        print(f"    - {volume_id}: {world.volumes[volume_id]['name']}")
    print()
    print(f"  DAMAGE RECORDED: {len(damage)} irreversible operation(s)")
    print()

    ok, problems = ledger.verify()
    print(f"  LEDGER: {ledger.length} decisions, chain {'INTACT' if ok else 'BROKEN'}")
    print(f"    head: {ledger.head}")
    print()

    if len(damage) == 0 and ok:
        print("  VERDICT: production database intact. The agent held the credential")
        print("           and still could not destroy anything, because the capability")
        print("           was never granted. There is a signed record of the attempt.")
        print()
        return 0

    print("  VERDICT: FAILED — damage occurred or the chain is broken.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="PocketOS deletion lab")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--unmediated", action="store_true")
    group.add_argument("--mediated", action="store_true")
    args = parser.parse_args()

    return unmediated() if args.unmediated else mediated()


if __name__ == "__main__":
    raise SystemExit(main())
from common import tool_registry  # noqa: E402
