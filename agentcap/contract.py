"""CapabilityContract: load, validate, hash, sign, verify, and diff.

The contract is the unit of authority. Everything else in AgentCap exists to
enforce it and to record that enforcement happened.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "contract.schema.json"


class ContractError(Exception):
    """Raised when a contract cannot be trusted."""


# --------------------------------------------------------------------------
# Canonical serialisation and hashing
# --------------------------------------------------------------------------

def canonical_json(obj: Any) -> str:
    """Deterministic JSON. Two equal contracts must hash identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _parse_time(value: str) -> dt.datetime:
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractError(f"unparseable timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate(contract: dict) -> None:
    """Validate against the JSON Schema. Raises ContractError on any problem."""
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - schema check is required in practice
        raise ContractError("jsonschema is required to validate contracts")

    validator = jsonschema.Draft202012Validator(_load_schema())
    errors = sorted(validator.iter_errors(contract), key=lambda e: list(e.absolute_path))
    if errors:
        lines = []
        for err in errors[:12]:
            location = ".".join(str(p) for p in err.absolute_path) or "<root>"
            lines.append(f"  {location}: {err.message}")
        raise ContractError("contract failed schema validation:\n" + "\n".join(lines))


def validate_semantics(contract: dict) -> None:
    """Checks the schema cannot express. These are the ones that cause incidents."""
    meta = contract["metadata"]
    spec = contract["spec"]

    issued = _parse_time(meta["issued"])
    expires = _parse_time(meta["expires"])
    if expires <= issued:
        raise ContractError("metadata.expires must be after metadata.issued")

    lifetime = (expires - issued).total_seconds()
    if lifetime > 7 * 24 * 3600:
        raise ContractError(
            f"contract lifetime is {lifetime / 3600:.1f}h; contracts must be short-lived "
            "(7 days is the ceiling). Long-lived authority is how standing credentials happen."
        )

    if not meta["principal"].strip():
        raise ContractError("metadata.principal must name an accountable human or team")

    # A tool listed with no digest and no argument predicate and no approval gate
    # is an unbounded capability. That is the thing this system exists to prevent.
    for tool in spec.get("tools", []):
        has_digest = bool(tool.get("digest"))
        has_predicate = any(a["tool"] == tool["id"] for a in spec.get("arguments", []))
        has_approval = bool(tool.get("requireApproval"))
        has_ceiling = tool.get("maxCalls") is not None
        if not (has_digest or has_predicate or has_approval or has_ceiling):
            raise ContractError(
                f"tool {tool['id']!r} is unbounded: it has no digest, no argument "
                "predicate, no approval gate, and no call ceiling. Every granted "
                "capability must be bounded by at least one of these."
            )

    seen = set()
    for tool in spec.get("tools", []):
        if tool["id"] in seen:
            raise ContractError(f"duplicate tool id: {tool['id']}")
        seen.add(tool["id"])

    for rule in spec.get("arguments", []):
        if rule["tool"] not in seen:
            raise ContractError(
                f"argument predicate references tool {rule['tool']!r} which is not in spec.tools"
            )

    delegation = spec.get("delegation", {})
    if delegation.get("maxDepth", 0) > 4:
        raise ContractError("delegation.maxDepth above 4 is not permitted")


def parse(text: str) -> dict:
    """Parse and fully validate contract text, returning the raw mapping."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ContractError(f"contract is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ContractError("contract must be a YAML mapping")
    _normalize_timestamps(raw)
    validate(raw)
    validate_semantics(raw)
    return raw


def loads(text: str) -> "Contract":
    """Parse contract text into a Contract."""
    return Contract(raw=parse(text))


def load(path: str | os.PathLike) -> "Contract":
    """Load and fully validate a contract from a YAML file."""
    return loads(Path(path).read_text(encoding="utf-8"))


def load_raw(path: str | os.PathLike) -> dict:
    """Load a contract as a plain mapping, for diffing."""
    return parse(Path(path).read_text(encoding="utf-8"))


def _normalize_timestamps(raw: dict) -> None:
    """Coerce YAML-native datetimes into ISO strings.

    YAML 1.1 resolves an unquoted `2026-09-26T18:00:00Z` to a datetime object.
    That is convenient for humans writing contracts by hand and wrong for a
    signed artifact: the canonical hash must be computed over a stable
    representation, not over whatever the local YAML loader happened to return.
    """
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        return
    for key in ("issued", "expires"):
        value = metadata.get(key)
        if isinstance(value, dt.datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=dt.timezone.utc)
            metadata[key] = value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Contract object
# --------------------------------------------------------------------------

@dataclass
class Contract:
    raw: dict
    signature: str | None = None
    signer: str | None = None

    # -- derived -----------------------------------------------------------
    @property
    def name(self) -> str:
        return self.raw["metadata"]["name"]

    @property
    def principal(self) -> str:
        return self.raw["metadata"]["principal"]

    @property
    def workload(self) -> str:
        return self.raw["spec"]["identity"]["workload"]

    @property
    def expires(self) -> dt.datetime:
        return _parse_time(self.raw["metadata"]["expires"])

    @property
    def policy_hash(self) -> str | None:
        return self.raw["spec"].get("policyHash")

    def hash(self) -> str:
        return sha256_of(self.raw)

    def tool(self, tool_id: str) -> dict | None:
        for entry in self.raw["spec"].get("tools", []):
            if entry["id"] == tool_id:
                return entry
        return None

    def is_expired(self, now: dt.datetime | None = None) -> bool:
        now = now or dt.datetime.now(dt.timezone.utc)
        return now >= self.expires

    # -- serialisation -----------------------------------------------------
    def to_envelope(self) -> dict:
        """The signed statement. Signature covers exactly this payload."""
        return {
            "payloadType": "application/vnd.agentcap.contract+json",
            "payload": base64.b64encode(canonical_json(self.raw).encode("utf-8")).decode("ascii"),
            "signatures": (
                [{"keyid": self.signer or "local", "sig": self.signature}]
                if self.signature
                else []
            ),
        }

    @classmethod
    def from_envelope(cls, envelope: dict) -> "Contract":
        payload = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        sigs = envelope.get("signatures") or []
        return cls(
            raw=payload,
            signature=sigs[0]["sig"] if sigs else None,
            signer=sigs[0]["keyid"] if sigs else None,
        )


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------

def _key_dir() -> Path:
    return Path(os.environ.get("AGENTCAP_KEY_DIR", Path.home() / ".agentcap"))


def generate_keypair(path: str | os.PathLike | None = None) -> tuple[str, str]:
    """Create an Ed25519 keypair. Returns (private_path, public_path)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    target = Path(path) if path else _key_dir() / "local"
    target.parent.mkdir(parents=True, exist_ok=True)

    private = Ed25519PrivateKey.generate()
    private_path = target.with_suffix(".key")
    public_path = target.with_suffix(".pub")

    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_path), str(public_path)


def sign(contract: Contract, private_key_path: str | os.PathLike | None = None) -> Contract:
    """Sign the canonical contract payload. Mirrors DSSE shape for cosign interop."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_path = Path(private_key_path) if private_key_path else _key_dir() / "local.key"
    if not key_path.exists():
        generate_keypair(str(key_path.with_suffix("")))
    if not key_path.exists():
        raise ContractError(f"private key not found: {key_path}")

    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ContractError("only Ed25519 signing keys are supported")

    payload = canonical_json(contract.raw).encode("utf-8")
    contract.signature = base64.b64encode(private.sign(payload)).decode("ascii")
    contract.signer = hashlib.sha256(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()[:16]
    return contract


def verify_signature(contract: Contract, public_key_path: str | os.PathLike | None = None) -> bool:
    """Verify the signature. Returns False rather than raising; callers deny on False."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not contract.signature:
        return False
    key_path = Path(public_key_path) if public_key_path else _key_dir() / "local.pub"
    if not key_path.exists():
        return False

    public = serialization.load_pem_public_key(key_path.read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        return False

    payload = canonical_json(contract.raw).encode("utf-8")
    try:
        public.verify(base64.b64decode(contract.signature), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------
# Diffing: what would this change newly permit?
# --------------------------------------------------------------------------

@dataclass
class Diff:
    """The reviewable artifact. This is what a security reviewer reads."""

    newly_permitted: list[str] = field(default_factory=list)
    newly_denied: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    widened: list[str] = field(default_factory=list)
    narrowed: list[str] = field(default_factory=list)
    identity_changed: bool = False
    principal_changed: bool = False
    expiry_changed: str | None = None

    @property
    def has_risk_increase(self) -> bool:
        return bool(self.newly_permitted or self.widened or self.principal_changed)


def diff(before: dict, after: dict) -> Diff:
    """Compare two contracts and surface risk-relevant changes."""
    result = Diff()

    old_tools = {t["id"]: t for t in before["spec"].get("tools", [])}
    new_tools = {t["id"]: t for t in after["spec"].get("tools", [])}

    for tool_id in sorted(set(new_tools) - set(old_tools)):
        result.newly_permitted.append(tool_id)
    for tool_id in sorted(set(old_tools) - set(new_tools)):
        result.newly_denied.append(tool_id)

    for tool_id in sorted(set(old_tools) & set(new_tools)):
        old, new = old_tools[tool_id], new_tools[tool_id]
        if old == new:
            continue
        result.modified.append(tool_id)
        # Losing a digest is a widening: the tool is no longer pinned.
        if old.get("digest") and not new.get("digest"):
            result.widened.append(
                f"{tool_id}: tool definition pin removed — the tool may now change "
                "underneath this contract without a new approval"
            )
            # Also surface it as a newly-permitted entry, because the reviewer
            # scanning the GRANT list must not have to notice an absence.
            result.newly_permitted.append(f"{tool_id} (unpinned definition)")
        # Losing an approval gate is a widening.
        if old.get("requireApproval") and not new.get("requireApproval"):
            result.widened.append(f"{tool_id}: human approval gate removed")
        # Raising or removing a call ceiling is a widening.
        old_max, new_max = old.get("maxCalls"), new.get("maxCalls")
        if old_max is not None and (new_max is None or new_max > old_max):
            result.widened.append(f"{tool_id}: call ceiling raised or removed")

    old_args = {(a["tool"], a["constraint"]) for a in before["spec"].get("arguments", [])}
    new_args = {(a["tool"], a["constraint"]) for a in after["spec"].get("arguments", [])}
    for tool_id, _ in sorted(new_args - old_args):
        result.widened.append(f"{tool_id}: argument predicate added or loosened")
    for tool_id, _ in sorted(old_args - new_args):
        result.narrowed.append(f"{tool_id}: argument predicate removed or tightened")

    old_flow = {(r["from"], tuple(r["deny"])) for r in before["spec"].get("dataFlow", [])}
    new_flow = {(r["from"], tuple(r["deny"])) for r in after["spec"].get("dataFlow", [])}
    for src, sinks in sorted(new_flow - old_flow):
        result.widened.append(f"dataflow: {src} now blocked from fewer sinks" if sinks else f"dataflow: {src} rule removed")
    for src, sinks in sorted(old_flow - new_flow):
        result.narrowed.append(f"dataflow: {src} rule tightened")

    old_budget = before["spec"].get("budget", {})
    new_budget = after["spec"].get("budget", {})
    for key in ("usd", "toolCalls", "egressGiB"):
        old_val, new_val = old_budget.get(key), new_budget.get(key)
        if old_val != new_val:
            if old_val is None or (new_val is not None and new_val > old_val):
                result.widened.append(f"budget.{key}: raised from {old_val} to {new_val}")
            else:
                result.narrowed.append(f"budget.{key}: lowered from {old_val} to {new_val}")

    old_deleg = before["spec"].get("delegation", {})
    new_deleg = after["spec"].get("delegation", {})
    if new_deleg.get("maxDepth", 0) > old_deleg.get("maxDepth", 0):
        result.widened.append(
            f"delegation.maxDepth: raised from {old_deleg.get('maxDepth', 0)} "
            f"to {new_deleg.get('maxDepth', 0)}"
        )
    removed_non_delegable = set(old_deleg.get("nonDelegable", [])) - set(
        new_deleg.get("nonDelegable", [])
    )
    for capability in sorted(removed_non_delegable):
        result.widened.append(f"delegation.nonDelegable: {capability} may now be delegated")

    if before["spec"]["identity"] != after["spec"]["identity"]:
        result.identity_changed = True
    if before["metadata"]["principal"] != after["metadata"]["principal"]:
        result.principal_changed = True
    if before["metadata"]["expires"] != after["metadata"]["expires"]:
        result.expiry_changed = (
            f"{before['metadata']['expires']} -> {after['metadata']['expires']}"
        )

    return result


def render_diff(result: Diff) -> str:
    """Human-readable plan output."""
    lines: list[str] = []

    if result.has_risk_increase:
        lines.append("  RISK INCREASES")
        for item in result.newly_permitted:
            lines.append(f"    + GRANT     {item}")
        for item in result.widened:
            lines.append(f"    ~ WIDEN     {item}")
        if result.principal_changed:
            lines.append("    ~ PRINCIPAL changed (accountability moves)")
        if result.identity_changed:
            lines.append("    ~ IDENTITY  changed (workload anchor moves)")
        lines.append("")

    if result.newly_denied or result.narrowed:
        lines.append("  RISK DECREASES")
        for item in result.newly_denied:
            lines.append(f"    - REVOKE    {item}")
        for item in result.narrowed:
            lines.append(f"    - NARROW    {item}")
        lines.append("")

    if result.modified and not (result.widened or result.newly_permitted):
        lines.append("  NEUTRAL CHANGES")
        for item in result.modified:
            lines.append(f"    = MODIFY    {item}")
        lines.append("")

    if not any(
        [result.newly_permitted, result.newly_denied, result.modified,
         result.widened, result.narrowed]
    ):
        lines.append("  No changes.")

    if result.expiry_changed:
        lines.append(f"  Expiry: {result.expiry_changed}")

    return "\n".join(lines)


def copy_contract(raw: dict) -> dict:
    return copy.deepcopy(raw)
