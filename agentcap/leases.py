"""Atomic budget and rate leases.

A dashboard tells you after the fact that an agent spent $6,531. A lease stops
the spend. This module is the difference between those two products.

The hard part is not counting. It is *atomicity under concurrency*: two parallel
agent branches must not both observe "budget remaining: $10" and both spend $10.
The local implementation uses an OS-level exclusive lock so the check-and-commit
is a single critical section. The AWS implementation uses a DynamoDB conditional
write, which is the same idea expressed as a storage guarantee.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path


class BudgetExceeded(Exception):
    """Raised when a call would exceed the contract's lease. Callers deny."""


@dataclass
class Budget:
    """The spend envelope from a contract."""

    usd: float | None = None
    tool_calls: int | None = None
    egress_gib: float | None = None

    @classmethod
    def from_contract(cls, spec: dict) -> "Budget":
        raw = spec.get("budget", {}) or {}
        return cls(
            usd=raw.get("usd"),
            tool_calls=raw.get("toolCalls"),
            egress_gib=raw.get("egressGiB"),
        )

    def to_dict(self) -> dict:
        out = {}
        if self.usd is not None:
            out["usd"] = self.usd
        if self.tool_calls is not None:
            out["toolCalls"] = self.tool_calls
        if self.egress_gib is not None:
            out["egressGiB"] = self.egress_gib
        return out


@dataclass
class SpendState:
    """Consumed so far, keyed by contract."""

    usd: float = 0.0
    tool_calls: int = 0
    egress_gib: float = 0.0

    def to_dict(self) -> dict:
        return {
            "usd": round(self.usd, 6),
            "toolCalls": self.tool_calls,
            "egressGiB": round(self.egress_gib, 6),
        }


class LeaseStore:
    """A check-and-commit budget store that is safe under concurrent branches.

    Every mutation happens inside an exclusive file lock, so a read-modify-write
    from one branch cannot interleave with another. This is the property that
    makes the difference between a budget and a suggestion.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.lock_path.touch(exist_ok=True)

    # -- internal ----------------------------------------------------------
    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def _locked(self):
        handle = self.lock_path.open("r+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    # -- public ------------------------------------------------------------
    def state(self, contract_name: str) -> SpendState:
        with self._locked():
            raw = self._read().get(contract_name, {})
        return SpendState(
            usd=float(raw.get("usd", 0.0)),
            tool_calls=int(raw.get("toolCalls", 0)),
            egress_gib=float(raw.get("egressGiB", 0.0)),
        )

    def check_and_commit(
        self,
        contract_name: str,
        budget: Budget,
        *,
        usd: float = 0.0,
        tool_calls: int = 1,
        egress_gib: float = 0.0,
        dry_run: bool = False,
    ) -> SpendState:
        """Atomically verify headroom and consume it.

        Raises BudgetExceeded if the call would exceed any ceiling. On raise,
        nothing is committed — the budget is left exactly as it was.
        """
        handle = self._locked()
        try:
            data = self._read()
            raw = data.get(contract_name, {})
            current = SpendState(
                usd=float(raw.get("usd", 0.0)),
                tool_calls=int(raw.get("toolCalls", 0)),
                egress_gib=float(raw.get("egressGiB", 0.0)),
            )

            projected_usd = current.usd + usd
            projected_calls = current.tool_calls + tool_calls
            projected_egress = current.egress_gib + egress_gib

            if budget.usd is not None and projected_usd > budget.usd:
                raise BudgetExceeded(
                    f"USD ceiling: {projected_usd:.4f} would exceed {budget.usd:.4f} "
                    f"(consumed {current.usd:.4f})"
                )
            if budget.tool_calls is not None and projected_calls > budget.tool_calls:
                raise BudgetExceeded(
                    f"tool-call ceiling: {projected_calls} would exceed {budget.tool_calls} "
                    f"(consumed {current.tool_calls})"
                )
            if budget.egress_gib is not None and projected_egress > budget.egress_gib:
                raise BudgetExceeded(
                    f"egress ceiling: {projected_egress:.4f} GiB would exceed "
                    f"{budget.egress_gib:.4f} GiB (consumed {current.egress_gib:.4f})"
                )

            if dry_run:
                return current

            updated = SpendState(
                usd=projected_usd, tool_calls=projected_calls, egress_gib=projected_egress
            )
            data[contract_name] = updated.to_dict()
            self._write(data)
            return updated
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def reset(self, contract_name: str | None = None) -> None:
        with self._locked():
            if contract_name is None:
                self._write({})
            else:
                data = self._read()
                data.pop(contract_name, None)
                self._write(data)


class RateLimiter:
    """Simple sliding-window rate limit, also under an exclusive lock."""

    def __init__(self, path: str | os.PathLike, max_per_minute: int | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.lock_path.touch(exist_ok=True)
        self.max_per_minute = max_per_minute

    def check(self, contract_name: str) -> None:
        if self.max_per_minute is None:
            return
        handle = self.lock_path.open("r+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            now = time.time()
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}
            stamps = [t for t in data.get(contract_name, []) if now - t < 60.0]
            if len(stamps) >= self.max_per_minute:
                raise BudgetExceeded(
                    f"rate limit: {len(stamps)} calls in the last 60s "
                    f"(max {self.max_per_minute}/min)"
                )
            stamps.append(now)
            data[contract_name] = stamps
            self.path.write_text(json.dumps(data), encoding="utf-8")
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


# --------------------------------------------------------------------------
# Cost estimation
#
# A mediator that cannot estimate cost cannot bound it. These are deliberately
# coarse, conservative defaults; operators override them per tool.
# --------------------------------------------------------------------------

DEFAULT_TOOL_COSTS_USD: dict[str, float] = {
    "aws:ec2:RunInstances": 0.50,
    "ec2:RunInstances": 0.50,
    "aws:ec2:CreateVolume": 0.10,
    "ec2:CreateVolume": 0.10,
    "aws:s3:PutObject": 0.0001,
    "s3:PutObject": 0.0001,
    "aws:s3:GetObject": 0.00001,
    "s3:GetObject": 0.00001,
    "s3:DeleteObject": 0.0,
    "volumeDelete": 0.0,
    "aws:lambda:Invoke": 0.00002,
    "aws:bedrock:InvokeModel": 0.01,
    "mcp://github/create_comment": 0.0,
    "mcp://github/list_issues": 0.0,
    "github:create_comment": 0.0,
    "github:list_issues": 0.0,
    "github:read_file": 0.0,
}

DEFAULT_TOOL_EGRESS_GIB: dict[str, float] = {
    "http:egress": 0.01,
    "aws:s3:PutObject": 0.005,
    "s3:PutObject": 0.005,
}


def _lookup(table: dict, tool_id: str) -> float:
    """Resolve a cost for a tool id, tolerating the `aws:` prefix convention.

    Tool ids are written by humans in contracts and by adapters in code. A cost
    table that silently misses on a prefix mismatch reports $0.00 consumed while
    the agent spends real money — which is the exact failure this module exists
    to prevent. So try the id as given, then with and without the prefix.
    """
    if tool_id in table:
        return float(table[tool_id])
    if tool_id.startswith("aws:"):
        return float(table.get(tool_id[4:], 0.0))
    return float(table.get(f"aws:{tool_id}", 0.0))


# Approximate on-demand hourly rates, USD. Coarse on purpose: a cost model that
# is wrong by a few percent still bounds spend, while one that is missing an
# instance class entirely does not bound anything.
EC2_HOURLY_USD: dict[str, float] = {
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "t3.xlarge": 0.1664,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m6i.large": 0.096,
    "m6i.2xlarge": 0.384,
    "m8g.large": 0.0908,
    "m8g.xlarge": 0.1816,
    "m8g.4xlarge": 0.7264,
    "m8g.12xlarge": 2.7648,
    "m8g.24xlarge": 5.5296,
    "c7g.16xlarge": 2.32,
    "r6i.8xlarge": 2.016,
    "g5.12xlarge": 5.672,
    "p4d.24xlarge": 32.7726,
}

# The horizon over which a provisioning call's cost is charged against the
# budget. An agent that launches instances has committed to paying for them;
# charging only the first hour would let it commit to a week of spend against
# an hourly budget. One day is the conservative default and matches the shape
# of the DN42 incident, where harm accrued over roughly 24 hours.
DEFAULT_COMMITMENT_HOURS = 24.0


def estimate_cost(
    tool_id: str,
    args: dict,
    overrides: dict | None = None,
    commitment_hours: float = DEFAULT_COMMITMENT_HOURS,
) -> float:
    """Estimate the cost a call commits the operator to.

    For provisioning calls this is the projected commitment over the horizon,
    not a flat per-call fee. A budget that cannot see the size of what is being
    provisioned cannot bound it — which is precisely how the DN42 bill happened.
    """
    table = dict(DEFAULT_TOOL_COSTS_USD)
    if overrides:
        table.update(overrides)

    if tool_id.endswith("ec2:RunInstances"):
        instance_type = str(args.get("instance_type", args.get("InstanceType", "")) or "")
        count = int(args.get("count", args.get("MaxCount", 1)) or 1)
        count = max(1, count)
        hourly = EC2_HOURLY_USD.get(instance_type)
        if hourly is None:
            # Unknown instance class: charge the most expensive known rate, so an
            # unrecognised type is treated as maximally risky rather than free.
            hourly = max(EC2_HOURLY_USD.values())
        return hourly * count * commitment_hours

    return _lookup(table, tool_id)


def estimate_egress(tool_id: str, args: dict, overrides: dict | None = None) -> float:
    table = dict(DEFAULT_TOOL_EGRESS_GIB)
    if overrides:
        table.update(overrides)
    return _lookup(table, tool_id)
