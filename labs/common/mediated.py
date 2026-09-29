"""Dispatch a tool call through the mediator, then to the mock world.

Labs must demonstrate enforcement, not just evaluation. A mediator that returns
`deny` but whose caller ignores it proves nothing. This helper is the only path
labs use to touch the simulated world, so every side effect in a lab is
necessarily downstream of an `allow` decision.
"""

from __future__ import annotations

from typing import Any

from agentcap.mediator import Mediator, ToolCall

from . import mock_tools, tool_registry


def call(
    mediator: Mediator,
    tool_id: str,
    args: dict,
    *,
    taint: list[str] | None = None,
    parent_agent_id: str | None = None,
    delegation_depth: int = 0,
) -> dict[str, Any]:
    """Evaluate, then execute only if allowed.

    Returns the outcome and, when permitted, the tool result. A denied call
    never reaches `mock_tools.invoke`, so no damage is recorded for it.
    """
    outcome = mediator.evaluate(
        ToolCall(
            tool=tool_id,
            args=args,
            digest=tool_registry.digest_for(tool_id) if tool_id in tool_registry.TOOL_DEFINITIONS else None,
            taint=list(taint or []),
            parent_agent_id=parent_agent_id,
            delegation_depth=delegation_depth,
        )
    )

    if not outcome.allowed:
        return {
            "executed": False,
            "decision": outcome.decision,
            "reason": outcome.reason,
            "record": outcome.record_hash,
            "result": None,
        }

    result = mock_tools.invoke(tool_id, args)
    return {
        "executed": True,
        "decision": outcome.decision,
        "reason": outcome.reason,
        "record": outcome.record_hash,
        "result": result,
    }
