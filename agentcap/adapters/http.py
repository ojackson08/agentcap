"""HTTP and subprocess adapters.

Both exist for the same reason: most real agent authority does not travel over
MCP. It travels over a REST call or a shell command. A mediator that only
covers MCP covers the least dangerous half of the problem.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from ..mediator import Mediator, ToolCall


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

@dataclass
class HTTPToolCall:
    """An HTTP request as a tool call."""

    method: str
    url: str
    body: Any = None
    headers: dict | None = None

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urllib.parse.urlparse(self.url).path


class HTTPAdapter:
    """Mediates outbound HTTP tool calls.

    The tool identity is derived from method, host and path so that a contract
    can grant `http://api.internal/repos/*` without granting the whole internet.
    """

    def __init__(self, mediator: Mediator, namespace: str = "http") -> None:
        self.mediator = mediator
        self.namespace = namespace

    def qualify(self, call: HTTPToolCall) -> str:
        return f"{self.namespace}://{call.host}{call.path}"

    def request(
        self,
        call: HTTPToolCall,
        *,
        taint: list[str] | None = None,
        delegation_depth: int = 0,
        parent_agent_id: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        tool_id = self.qualify(call)

        outcome = self.mediator.evaluate(
            ToolCall(
                tool=tool_id,
                args={
                    "method": call.method.upper(),
                    "url_host": call.host,
                    "path": call.path,
                    "body_size": len(json.dumps(call.body)) if call.body is not None else 0,
                },
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
                "response": None,
            }

        if dry_run:
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "response": {"note": "dry run; request not sent"},
            }

        request = urllib.request.Request(
            call.url,
            data=json.dumps(call.body).encode("utf-8") if call.body is not None else None,
            headers={"Content-Type": "application/json", **(call.headers or {})},
            method=call.method.upper(),
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8", errors="replace")
                try:
                    parsed: Any = json.loads(payload)
                except json.JSONDecodeError:
                    parsed = payload[:2000]
                return {
                    "mediated": True,
                    "decision": outcome.decision,
                    "reason": outcome.reason,
                    "record": outcome.record_hash,
                    "response": parsed,
                }
        except urllib.error.HTTPError as exc:
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "response": {"error": f"HTTP {exc.code}"},
            }
        except urllib.error.URLError as exc:
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "response": {"error": str(exc.reason)},
            }


# --------------------------------------------------------------------------
# Subprocess
# --------------------------------------------------------------------------

class SubprocessAdapter:
    """Mediates shell execution.

    Shell is the widest authority an agent can hold, and the hardest to bound
    with argument predicates alone. Three layers:

      1. the command class must be granted by the contract
      2. the argument predicate constrains the specific invocation
      3. bubblewrap isolates the process when available, with an explicit
         network posture rather than an inherited one

    Layer 3 is defence in depth, not the boundary. The boundary is layer 1.
    """

    def __init__(self, mediator: Mediator, namespace: str = "exec") -> None:
        self.mediator = mediator
        self.namespace = namespace
        self.bwrap = shutil.which("bwrap")

    def qualify(self, command: str) -> str:
        return f"{self.namespace}://{os.path.basename(command)}"

    def run(
        self,
        argv: list[str],
        *,
        taint: list[str] | None = None,
        delegation_depth: int = 0,
        parent_agent_id: str | None = None,
        allow_network: bool = False,
        read_paths: list[str] | None = None,
        timeout: int = 60,
    ) -> dict:
        if not argv:
            return {"mediated": True, "decision": "deny", "reason": "empty command"}

        tool_id = self.qualify(argv[0])
        outcome = self.mediator.evaluate(
            ToolCall(
                tool=tool_id,
                args={
                    "argv": " ".join(argv[:8]),
                    "argc": len(argv),
                    "network": allow_network,
                },
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
                "stdout": "",
                "stderr": "",
                "returncode": None,
            }

        final_argv = argv
        sandboxed = False
        if self.bwrap:
            final_argv = self._wrap(argv, allow_network=allow_network, read_paths=read_paths or [])
            sandboxed = True

        try:
            completed = subprocess.run(
                final_argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "sandboxed": sandboxed,
                "stdout": completed.stdout[:4000],
                "stderr": completed.stderr[:4000],
                "returncode": completed.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "mediated": True,
                "decision": outcome.decision,
                "reason": outcome.reason,
                "record": outcome.record_hash,
                "sandboxed": sandboxed,
                "stdout": "",
                "stderr": f"timed out after {timeout}s",
                "returncode": None,
            }

    def _wrap(self, argv: list[str], *, allow_network: bool, read_paths: list[str]) -> list[str]:
        """Build a bubblewrap invocation with an explicit, minimal posture."""
        assert self.bwrap
        wrapped = [
            self.bwrap,
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
        ]
        if not allow_network:
            wrapped.append("--unshare-net")
        for path in read_paths:
            wrapped += ["--ro-bind-try", path, path]
        wrapped += ["--"] + argv
        return wrapped


def sandbox_available() -> dict:
    """Report which isolation primitives this host actually has.

    Reported rather than assumed. A mediator that claims containment it does
    not have is worse than one that admits the gap.
    """
    return {
        "bubblewrap": shutil.which("bwrap") is not None,
        "landlock": os.path.exists("/sys/kernel/security/landlock")
        if os.path.exists("/sys/kernel/security")
        else False,
        "seccomp": os.path.exists("/proc/sys/kernel/seccomp"),
    }
