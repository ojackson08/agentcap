"""The evidence ledger: append-only, hash-chained, signed decision records.

The point of this module is not logging. It is producing evidence that a
reviewer can trust *without trusting the agent, or the agent's operator*.

Three properties make that true:

  prevHash   each record commits to its predecessor, so deletion, reordering,
             or retroactive editing is detectable by anyone holding the chain
  policyHash the decision is bound to the exact rules that produced it
  toolDigest the decision is bound to the exact tool definition that ran

A log tells you what someone said happened. This tells you what the
enforcement point decided, under which rules, against which artifact.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .contract import canonical_json, sha256_bytes, sha256_of

GENESIS = "sha256:" + "0" * 64


class LedgerError(Exception):
    pass


@dataclass
class Decision:
    """One enforcement decision. The unit of evidence."""

    seq: int
    timestamp: str
    contract_hash: str
    contract_name: str
    policy_hash: str
    agent_id: str
    parent_agent_id: str | None
    delegation_depth: int
    tool: str
    tool_digest: str | None
    args_hash: str
    args_redacted: dict
    decision: str            # allow | deny | approve
    reason: str
    budget_after: dict
    lease: dict | None = None
    prev_hash: str = GENESIS
    signature: str | None = None

    def body(self) -> dict:
        """Everything the hash covers. Signature is excluded, it is computed over this."""
        return {
            "seq": self.seq,
            "ts": self.timestamp,
            "contractHash": self.contract_hash,
            "contractName": self.contract_name,
            "policyHash": self.policy_hash,
            "agentId": self.agent_id,
            "parentAgentId": self.parent_agent_id,
            "delegationDepth": self.delegation_depth,
            "tool": self.tool,
            "toolDigest": self.tool_digest,
            "argsHash": self.args_hash,
            "argsRedacted": self.args_redacted,
            "decision": self.decision,
            "reason": self.reason,
            "budgetAfter": self.budget_after,
            "lease": self.lease,
            "prevHash": self.prev_hash,
        }

    def hash(self) -> str:
        return sha256_of(self.body())

    def to_dict(self) -> dict:
        record = self.body()
        record["hash"] = self.hash()
        if self.signature:
            record["signature"] = self.signature
        return record


# --------------------------------------------------------------------------
# Redaction
#
# The ledger must be safe to retain and to hand to an auditor. Argument values
# are hashed for integrity and redacted for storage, except for a small
# allowlist of fields that are useful for investigation and not sensitive.
# --------------------------------------------------------------------------

SAFE_ARG_KEYS = {
    "bucket", "key_prefix", "region", "instance_type", "instanceType", "count",
    "repo", "repository", "path", "method", "url_host", "host", "operation",
    "table", "queue", "topic", "action", "resource_type", "environment", "env",
}

SECRET_HINTS = (
    "token", "secret", "password", "passwd", "credential", "apikey", "api_key",
    "private", "auth", "session", "cookie", "signature", "key",
)


def _is_secretish(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in SECRET_HINTS)


def redact(args: dict) -> dict:
    """Redact argument values for storage.

    Anything not on the safe list is replaced by a truncated hash, so the
    record still proves *what* was passed without retaining it. Secret-looking
    keys are never stored in any form beyond the hash.
    """
    out: dict[str, Any] = {}
    for key, value in (args or {}).items():
        if _is_secretish(key):
            out[key] = "<redacted:secret>"
        elif key in SAFE_ARG_KEYS and isinstance(value, (str, int, float, bool)):
            text = str(value)
            out[key] = text if len(text) <= 120 else text[:117] + "..."
        else:
            digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
            out[key] = f"<redacted:{digest}>"
    return out


# --------------------------------------------------------------------------
# The ledger
# --------------------------------------------------------------------------

@dataclass
class Ledger:
    """Append-only local ledger. S3 Object Lock is the AWS equivalent."""

    path: Path
    records: list[dict] = field(default_factory=list)
    _last_hash: str = GENESIS
    _seq: int = 0

    @classmethod
    def open(cls, path: str | os.PathLike) -> "Ledger":
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        ledger = cls(path=target)
        if target.exists():
            for line in target.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                ledger.records.append(record)
                ledger._last_hash = record["hash"]
                ledger._seq = record["seq"]
        return ledger

    @property
    def head(self) -> str:
        return self._last_hash

    @property
    def length(self) -> int:
        return self._seq

    def append(
        self,
        *,
        contract,
        policy_hash: str,
        agent_id: str,
        tool: str,
        args: dict,
        decision: str,
        reason: str,
        budget_after: dict | None = None,
        tool_digest: str | None = None,
        parent_agent_id: str | None = None,
        delegation_depth: int = 0,
        lease: dict | None = None,
        signer=None,
    ) -> Decision:
        """Append one decision. Returns the record that was written."""
        if decision not in {"allow", "deny", "approve"}:
            raise LedgerError(f"unknown decision outcome: {decision!r}")

        entry = Decision(
            seq=self._seq + 1,
            timestamp=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            contract_hash=contract.hash() if hasattr(contract, "hash") else str(contract),
            contract_name=getattr(contract, "name", "unknown"),
            policy_hash=policy_hash,
            agent_id=agent_id,
            parent_agent_id=parent_agent_id,
            delegation_depth=delegation_depth,
            tool=tool,
            tool_digest=tool_digest,
            args_hash=sha256_of(args or {}),
            args_redacted=redact(args or {}),
            decision=decision,
            reason=reason,
            budget_after=budget_after or {},
            lease=lease,
            prev_hash=self._last_hash,
        )
        if signer is not None:
            entry.signature = signer(canonical_json(entry.body()).encode("utf-8"))

        record = entry.to_dict()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        self.records.append(record)
        self._last_hash = record["hash"]
        self._seq = entry.seq
        return entry

    # -- verification ------------------------------------------------------
    def verify(self, public_key=None) -> tuple[bool, list[str]]:
        """Walk the chain. Returns (ok, problems).

        Detects: modified records, deleted records, reordered records, and
        (when a public key is supplied) forged or missing signatures.
        """
        problems: list[str] = []
        previous = GENESIS

        for index, record in enumerate(self.records, start=1):
            if record.get("seq") != index:
                problems.append(
                    f"record {index}: seq is {record.get('seq')} (expected {index}) — "
                    "a record was deleted or reordered"
                )
            if record.get("prevHash") != previous:
                problems.append(
                    f"record {index}: prevHash does not match the previous record's hash — "
                    "the chain is broken"
                )

            stored_hash = record.get("hash")
            body = {k: v for k, v in record.items() if k not in ("hash", "signature")}
            recomputed = sha256_of(body)
            if stored_hash != recomputed:
                problems.append(
                    f"record {index}: content hash mismatch — the record was modified after "
                    "it was written"
                )

            if public_key is not None:
                if not record.get("signature"):
                    problems.append(f"record {index}: unsigned")
                else:
                    import base64

                    from cryptography.exceptions import InvalidSignature

                    try:
                        public_key.verify(
                            base64.b64decode(record["signature"]),
                            canonical_json(body).encode("utf-8"),
                        )
                    except (InvalidSignature, ValueError):
                        problems.append(f"record {index}: signature does not verify")

            previous = stored_hash or recomputed

        return (not problems), problems


def make_signer(private_key_path: str | os.PathLike | None = None):
    """Return a signing callable, or None if no key is configured."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .contract import _key_dir

    key_path = Path(private_key_path) if private_key_path else _key_dir() / "local.key"
    if not key_path.exists():
        return None

    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        return None

    import base64

    def _sign(payload: bytes) -> str:
        return base64.b64encode(private.sign(payload)).decode("ascii")

    return _sign


def load_public_key(path: str | os.PathLike | None = None):
    from cryptography.hazmat.primitives import serialization

    from .contract import _key_dir

    key_path = Path(path) if path else _key_dir() / "local.pub"
    if not key_path.exists():
        return None
    return serialization.load_pem_public_key(key_path.read_bytes())
