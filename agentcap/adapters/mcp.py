"""MCP adapter: mediates Model Context Protocol tool calls.

MCP is where tool authority is most opaque. A server advertises a tool with a
description and a JSON Schema; nothing in the protocol binds that description to
the code that will actually run, and nothing stops the description from changing
after you approved it. This adapter treats both facts as load-bearing:

  - the tool definition is hashed at approval time and pinned in the contract
  - every call re-hashes the live definition and denies on drift

Supports stdio and HTTP transports. Both are proxied rather than wrapped, so an
unmediated path shows up as a missing record rather than as silent success.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..contract import canonical_json, sha256_bytes
from ..mediator import Mediator, ToolCall


@dataclass
class ToolDefinition:
    """The advertised shape of a tool, as presented by the server."""

    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)

    def digest(self) -> str:
        """Stable hash of the definition.

        Covers name, description and schema. A description change is a
        security-relevant event: it is the channel through which tool-poisoning
        instructions are delivered.
        """
        return sha256_bytes(
            canonical_json(
                {
                    "name": self.name,
                    "description": self.description,
                    "inputSchema": self.input_schema,
                }
            ).encode("utf-8")
        )


def parse_tool_definitions(payload: dict) -> list[ToolDefinition]:
    """Extract tool definitions from an MCP tools/list response."""
    tools = payload.get("result", {}).get("tools") or payload.get("tools") or []
    definitions: list[ToolDefinition] = []
    for entry in tools:
        definitions.append(
            ToolDefinition(
                name=entry.get("name", ""),
                description=entry.get("description", ""),
                input_schema=entry.get("inputSchema", {}) or {},
            )
        )
    return definitions


class MCPProxy:
    """A mediating proxy in front of one MCP server.

    The proxy is the enforcement point. Agents are configured to talk to the
    proxy, not to the server. Anything that reaches the server without a
    corresponding allow record is an uncovered path, and the conformance suite
    measures that rather than assuming it away.
    """

    def __init__(
        self,
        mediator: Mediator,
        *,
        server_command: list[str] | None = None,
        server_url: str | None = None,
        namespace: str = "mcp",
        agent_id: str | None = None,
    ) -> None:
        self.mediator = mediator
        self.server_command = server_command
        self.server_url = server_url
        self.namespace = namespace
        self.agent_id = agent_id or mediator.contract.workload
        self._definitions: dict[str, ToolDefinition] = {}
        self._process: subprocess.Popen | None = None
        self._request_id = 0

    # -- tool identity -----------------------------------------------------
    def qualify(self, tool_name: str) -> str:
        return f"{self.namespace}://{tool_name}"

    def register_definitions(self, definitions: list[ToolDefinition]) -> dict[str, str]:
        """Record live definitions and return their digests, for contract pinning."""
        digests: dict[str, str] = {}
        for definition in definitions:
            self._definitions[definition.name] = definition
            digests[self.qualify(definition.name)] = definition.digest()
        return digests

    def detect_drift(self) -> list[str]:
        """Tools whose definition no longer matches what was pinned.

        Reported before enforcement so an operator learns about drift from a
        report rather than from a blocked production call.
        """
        drifted: list[str] = []
        for name, definition in self._definitions.items():
            qualified = self.qualify(name)
            granted = self.mediator.policy.tools.get(qualified)
            if granted and granted.get("digest") and granted["digest"] != definition.digest():
                drifted.append(
                    f"{qualified}: pinned {granted['digest'][:19]}... "
                    f"live {definition.digest()[:19]}..."
                )
        return drifted

    # -- the mediated call -------------------------------------------------
    def call_tool(
        self,
        tool_name: str,
        arguments: dict | None = None,
        *,
        taint: list[str] | None = None,
        delegation_depth: int = 0,
        parent_agent_id: str | None = None,
    ) -> dict:
        """Evaluate, then (only on allow) forward the call.

        The digest supplied here is computed from the live definition, so a
        server that mutated its tool description after approval is denied.
        """
        arguments = arguments or {}
        qualified = self.qualify(tool_name)

        live = self._definitions.get(tool_name)
        digest = live.digest() if live else None

        outcome = self.mediator.evaluate(
            ToolCall(
                tool=qualified,
                args=arguments,
                digest=digest,
                taint=list(taint or []),
                parent_agent_id=parent_agent_id,
                delegation_depth=delegation_depth,
            )
        )

        if not outcome.allowed:
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "result": None,
            }

        return {
            "mediated": True,
            "decision": outcome.decision,
            "reason": outcome.reason,
            "record": outcome.record_hash,
            "result": self._forward(tool_name, arguments),
        }

    # -- transport ---------------------------------------------------------
    def _forward(self, tool_name: str, arguments: dict) -> Any:
        if self.server_command:
            return self._forward_stdio(tool_name, arguments)
        if self.server_url:
            return self._forward_http(tool_name, arguments)
        return {"note": "no transport configured; decision recorded without execution"}

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _forward_stdio(self, tool_name: str, arguments: dict) -> Any:
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        assert self._process is not None and self._process.stdin and self._process.stdout
        self._process.stdin.write(json.dumps(request) + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline()
        if not line:
            return {"error": "server closed the connection"}
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"error": "unparseable server response"}

    def _forward_http(self, tool_name: str, arguments: dict) -> Any:
        import urllib.error
        import urllib.request

        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        body = json.dumps(request).encode("utf-8")
        http_request = urllib.request.Request(
            self.server_url or "",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            return {"error": str(exc)}

    # -- lifecycle ---------------------------------------------------------
    def start_stdio(self) -> None:
        if not self.server_command:
            raise ValueError("no server_command configured")
        self._process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def stop(self) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None


# --------------------------------------------------------------------------
# Taint propagation
# --------------------------------------------------------------------------

UNTRUSTED_MARKERS = (
    "<untrusted",
    "untrusted_content",
    "external_content",
    "web_content",
)


def label_taint(source: str) -> str:
    """Normalize a taint source into a label the contract can reference."""
    return source if ":" in source else f"untrusted:{source}"


def carries_untrusted(payload: Any) -> bool:
    """Heuristic check for whether a payload contains untrusted-origin markers.

    This is a convenience for adapters, not a security boundary. The boundary
    is the data-flow rule in the contract plus the sink check in the mediator.
    """
    text = canonical_json(payload) if not isinstance(payload, str) else payload
    return any(marker in text for marker in UNTRUSTED_MARKERS)
