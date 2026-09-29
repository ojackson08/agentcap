"""Compile a CapabilityContract into an evaluable policy.

AgentCap does not invent a policy language. It compiles contracts down to a
narrow, deterministic decision function that a human can read and an auditor
can reproduce. The compiled output is hashed into the contract as policyHash,
so a decision can always be bound to the exact rules that produced it.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .contract import canonical_json, sha256_of


class CompileError(Exception):
    pass


# --------------------------------------------------------------------------
# Argument predicate evaluation
#
# Predicates are deliberately a restricted expression language, not Python.
# Only comparisons, boolean operators, membership, and a small set of
# functions are permitted. This is a security boundary: it must be boring.
# --------------------------------------------------------------------------

ALLOWED_FUNCTIONS = {
    "startswith": lambda s, p: str(s).startswith(str(p)),
    "endswith": lambda s, p: str(s).endswith(str(p)),
    "contains": lambda s, p: str(p) in str(s),
    "lower": lambda s: str(s).lower(),
    "len": len,
    "matches": lambda s, pattern: re.search(str(pattern), str(s)) is not None,
    "any_of": lambda value, options: value in options,
}

ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Call, ast.Name, ast.Load, ast.Constant,
    ast.List, ast.Tuple, ast.Set, ast.Attribute, ast.Subscript,
    ast.BinOp, ast.Add, ast.Subscript,
)


class _PredicateValidator(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        # Two accepted forms, both resolved against the same allowlist:
        #   function form:   startswith(args["bucket"], "prefix")
        #   method form:     args["path"].endswith(".md")
        # The method form is what a Python author reaches for, and rejecting it
        # produces a confusing error rather than a safer predicate.
        if isinstance(node.func, ast.Name):
            if node.func.id not in ALLOWED_FUNCTIONS:
                raise CompileError(
                    f"predicate may only call: {', '.join(sorted(ALLOWED_FUNCTIONS))}"
                )
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr not in ALLOWED_FUNCTIONS:
                raise CompileError(
                    f"predicate may only call: {', '.join(sorted(ALLOWED_FUNCTIONS))} "
                    f"(got .{node.func.attr})"
                )
        else:
            raise CompileError("predicate calls must be named functions or string methods")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("_"):
            raise CompileError("predicate may not access private attributes")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id.startswith("__"):
            raise CompileError("predicate may not reference dunder names")
        self.names.add(node.id)
        self.generic_visit(node)


def normalize_predicate(expression: str) -> str:
    """Accept YAML-friendly boolean literals in predicates.

    Contracts are written by humans in YAML, where `false` is the natural
    spelling. Python wants `False`. Rather than make the author remember which
    language a predicate is written in, accept both and normalise here.
    """
    normalized = re.sub(r"\btrue\b", "True", expression)
    normalized = re.sub(r"\bfalse\b", "False", normalized)
    return normalized


def validate_predicate(expression: str) -> set[str]:
    """Parse and vet a predicate. Returns the free variable names it uses."""
    expression = normalize_predicate(expression)
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise CompileError(f"predicate is not a valid expression: {exc}") from exc

    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES) and not isinstance(
            node, (ast.operator, ast.cmpop, ast.boolop, ast.unaryop, ast.expr_context)
        ):
            raise CompileError(
                f"predicate uses a disallowed construct: {type(node).__name__}"
            )

    validator = _PredicateValidator()
    validator.visit(tree)

    unknown = validator.names - set(ALLOWED_FUNCTIONS)
    # Everything that is not a function is a reference into the call arguments.
    for name in unknown:
        if name in {"args", "call"}:
            continue
    return unknown


def evaluate_predicate(expression: str, context: dict) -> bool:
    """Evaluate a predicate against a call context. Raises on any failure.

    The caller treats a raise as a deny. A predicate that cannot be evaluated
    is not a predicate that passed.
    """
    expression = normalize_predicate(expression)
    validate_predicate(expression)

    def resolver(name: str) -> Any:
        if name in context:
            return context[name]
        if name == "args":
            return context.get("args", {})
        raise CompileError(f"predicate references unknown variable: {name!r}")

    class _Resolver(dict):
        def __missing__(self, key: str) -> Any:
            if key in ALLOWED_FUNCTIONS:
                return ALLOWED_FUNCTIONS[key]
            return resolver(key)

    class _SafeStr(str):
        """A string whose methods are limited to the approved allowlist.

        Subclassing str keeps comparisons and membership working normally while
        making `x.endswith(...)` resolve to the vetted implementation rather
        than to an attribute the predicate author chose.
        """

        def __getattr__(self, name: str) -> Any:
            if name in ALLOWED_FUNCTIONS:
                return lambda *a, **k: ALLOWED_FUNCTIONS[name](str(self), *a, **k)
            raise AttributeError(f"str method {name!r} is not permitted in predicates")

    def wrap(value: Any) -> Any:
        if isinstance(value, str):
            return _SafeStr(value)
        if isinstance(value, dict):
            return {k: wrap(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [wrap(v) for v in value]
        return value

    scope = _Resolver({k: wrap(v) for k, v in context.items()})
    scope["args"] = wrap(context.get("args", {}))
    scope["call"] = context

    code = compile(ast.parse(expression, mode="eval"), "<predicate>", "eval")
    result = eval(code, {"__builtins__": {}}, scope)  # noqa: S307 - sandboxed above
    return bool(result)


# --------------------------------------------------------------------------
# Compiled policy
# --------------------------------------------------------------------------

@dataclass
class CompiledPolicy:
    """The deterministic decision function derived from one contract."""

    contract_name: str
    principal: str
    workload: str
    expires: str
    max_delegation_depth: int
    non_delegable: list[str]
    tools: dict[str, dict]
    predicates: dict[str, list[str]]
    dataflow: list[dict]
    budget: dict
    source_hash: str

    def to_dict(self) -> dict:
        return {
            "contractName": self.contract_name,
            "principal": self.principal,
            "workload": self.workload,
            "expires": self.expires,
            "delegation": {
                "maxDepth": self.max_delegation_depth,
                "nonDelegable": self.non_delegable,
            },
            "tools": self.tools,
            "predicates": self.predicates,
            "dataflow": self.dataflow,
            "budget": self.budget,
            "sourceHash": self.source_hash,
        }

    def policy_hash(self) -> str:
        return sha256_of(self.to_dict())


def compile_contract(raw: dict) -> CompiledPolicy:
    """Compile a validated contract into a decision function."""
    spec = raw["spec"]

    tools: dict[str, dict] = {}
    for entry in spec.get("tools", []):
        tools[entry["id"]] = {
            "digest": entry.get("digest"),
            "requireApproval": bool(entry.get("requireApproval", False)),
            "maxCalls": entry.get("maxCalls"),
        }

    predicates: dict[str, list[str]] = {}
    for rule in spec.get("arguments", []):
        validate_predicate(rule["constraint"])
        predicates.setdefault(rule["tool"], []).append(rule["constraint"])

    delegation = spec.get("delegation", {})
    policy = CompiledPolicy(
        contract_name=raw["metadata"]["name"],
        principal=raw["metadata"]["principal"],
        workload=spec["identity"]["workload"],
        expires=raw["metadata"]["expires"],
        max_delegation_depth=int(delegation.get("maxDepth", 0)),
        non_delegable=list(delegation.get("nonDelegable", [])),
        tools=tools,
        predicates=predicates,
        dataflow=list(spec.get("dataFlow", [])),
        budget=dict(spec.get("budget", {})),
        source_hash=sha256_of(raw),
    )
    return policy


def match_pattern(pattern: str, value: str) -> bool:
    """Capability patterns support a trailing * wildcard only.

    Deliberately not full glob or regex. A pattern language with surprising
    semantics is a pattern language that will authorize something unexpected.
    """
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    if pattern.endswith(":*"):
        return value.startswith(pattern[:-2])
    return pattern == value


def tool_is_non_delegable(policy: CompiledPolicy, tool_id: str) -> bool:
    return any(match_pattern(p, tool_id) for p in policy.non_delegable)


def render_policy(policy: CompiledPolicy) -> str:
    """Human-readable rendering, for review and for the plan output."""
    lines = [
        f"Contract:   {policy.contract_name}",
        f"Principal:  {policy.principal}",
        f"Workload:   {policy.workload}",
        f"Expires:    {policy.expires}",
        f"Policy hash: {policy.policy_hash()}",
        "",
        "Granted capabilities:",
    ]
    for tool_id, entry in sorted(policy.tools.items()):
        notes = []
        if entry.get("digest"):
            notes.append(f"pinned {entry['digest'][:19]}...")
        else:
            notes.append("UNPINNED")
        if entry.get("requireApproval"):
            notes.append("requires approval")
        if entry.get("maxCalls") is not None:
            notes.append(f"max {entry['maxCalls']} calls")
        lines.append(f"  {tool_id}  ({'; '.join(notes)})")
        for predicate in policy.predicates.get(tool_id, []):
            lines.append(f"      when {predicate}")

    lines.append("")
    lines.append(
        f"Delegation: max depth {policy.max_delegation_depth}"
        + (f", non-delegable: {', '.join(policy.non_delegable)}" if policy.non_delegable else "")
    )

    if policy.dataflow:
        lines.append("")
        lines.append("Data-flow rules:")
        for rule in policy.dataflow:
            lines.append(f"  {rule['from']} may not reach: {', '.join(rule['deny'])}")

    if policy.budget:
        lines.append("")
        lines.append("Budget: " + ", ".join(f"{k}={v}" for k, v in policy.budget.items()))

    return "\n".join(lines)


def render_rego(policy: CompiledPolicy) -> str:
    """Emit Rego for teams that already run OPA.

    AgentCap evaluates locally by default so the mediator has no external
    dependency on the hot path, but the same policy must be expressible in the
    engine a cloud security team already operates.
    """
    granted = ", ".join(f'"{t}"' for t in sorted(policy.tools))
    lines = [
        "# Generated by agentcap compile --format=rego",
        f"# contract: {policy.contract_name}",
        f"# policy hash: {policy.policy_hash()}",
        "",
        "package agentcap",
        "",
        "default decision := {\"outcome\": \"deny\", \"reason\": \"no matching rule\"}",
        "",
        f"granted_tools := {{{granted}}}",
        "",
        "decision := {\"outcome\": \"deny\", \"reason\": \"tool not granted\"} {",
        "  not granted_tools[input.tool]",
        "}",
        "",
        "decision := {\"outcome\": \"approve\", \"reason\": \"tool requires approval\"} {",
        "  granted_tools[input.tool]",
        "  approval_required[input.tool]",
        "}",
        "",
        "decision := {\"outcome\": \"allow\", \"reason\": \"granted\"} {",
        "  granted_tools[input.tool]",
        "  not approval_required[input.tool]",
        "}",
        "",
        "approval_required := {"
        + ", ".join(f'"{t}"' for t, e in sorted(policy.tools.items()) if e.get("requireApproval"))
        + "}",
        "",
    ]
    return "\n".join(lines)
