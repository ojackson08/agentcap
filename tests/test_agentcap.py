"""Unit tests for AgentCap.

Run: python3 -m pytest tests/ -v
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentcap.compile import (  # noqa: E402
    CompileError,
    compile_contract,
    evaluate_predicate,
    match_pattern,
    render_policy,
    validate_predicate,
)
from agentcap.contract import (  # noqa: E402
    Contract,
    ContractError,
    canonical_json,
    diff,
    generate_keypair,
    loads,
    parse,
    render_diff,
    sha256_of,
    sign,
    verify_signature,
)
from agentcap.leases import (  # noqa: E402
    Budget,
    BudgetExceeded,
    LeaseStore,
    estimate_cost,
)
from agentcap.ledger import Ledger, redact  # noqa: E402
from agentcap.mediator import ALLOW, APPROVE, DENY, Mediator, ToolCall  # noqa: E402


def make_contract(**overrides) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    raw = {
        "apiVersion": "agentcap.dev/v1",
        "kind": "CapabilityContract",
        "metadata": {
            "name": "test-agent",
            "principal": "tester@example.com",
            "issued": now.isoformat().replace("+00:00", "Z"),
            "expires": (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "identity": {"workload": "spiffe://test/agent"},
            "delegation": {"maxDepth": 1, "nonDelegable": ["*Delete*"]},
            "tools": [
                {"id": "s3:GetObject", "digest": "sha256:" + "a" * 64},
                {"id": "s3:PutObject", "digest": "sha256:" + "b" * 64},
                {"id": "volumeDelete", "digest": "sha256:" + "c" * 64},
                {"id": "github:create_comment", "digest": "sha256:" + "d" * 64,
                 "requireApproval": True},
            ],
            "arguments": [
                {"tool": "s3:PutObject", "constraint": 'startswith(args["bucket"], "ok-")'},
                {"tool": "volumeDelete", "constraint": "false"},
            ],
            "dataFlow": [{"from": "untrusted:web", "deny": ["github:create_comment"]}],
            "budget": {"usd": 10, "toolCalls": 100},
        },
    }
    raw.update(overrides)
    return raw


@pytest.fixture
def keypair(tmp_path):
    private, public = generate_keypair(str(tmp_path / "test"))
    return private, public


# --------------------------------------------------------------------------
# Contract
# --------------------------------------------------------------------------

class TestContract:
    def test_canonical_json_is_stable(self):
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_hash_changes_when_content_changes(self):
        first = make_contract()
        second = make_contract()
        second["spec"]["tools"].append({"id": "x:y", "digest": "sha256:" + "e" * 64})
        assert sha256_of(first) != sha256_of(second)

    def test_rejects_long_lifetime(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw = make_contract()
        raw["metadata"]["issued"] = now.isoformat().replace("+00:00", "Z")
        raw["metadata"]["expires"] = (now + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z")
        with pytest.raises(ContractError, match="short-lived"):
            parse(json.dumps(raw))

    def test_rejects_expiry_before_issue(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw = make_contract()
        raw["metadata"]["issued"] = now.isoformat().replace("+00:00", "Z")
        raw["metadata"]["expires"] = (now - dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        with pytest.raises(ContractError, match="after"):
            parse(json.dumps(raw))

    def test_rejects_unbounded_tool(self):
        raw = make_contract()
        raw["spec"]["tools"].append({"id": "danger:op"})
        with pytest.raises(ContractError, match="unbounded"):
            parse(json.dumps(raw))

    def test_rejects_duplicate_tools(self):
        raw = make_contract()
        raw["spec"]["tools"].append({"id": "s3:GetObject", "digest": "sha256:" + "f" * 64})
        with pytest.raises(ContractError, match="duplicate"):
            parse(json.dumps(raw))

    def test_rejects_orphan_predicate(self):
        raw = make_contract()
        raw["spec"]["arguments"].append({"tool": "not:granted", "constraint": "true"})
        with pytest.raises(ContractError, match="not in spec.tools"):
            parse(json.dumps(raw))

    def test_rejects_excessive_delegation_depth(self):
        raw = make_contract()
        raw["spec"]["delegation"]["maxDepth"] = 9
        with pytest.raises(ContractError, match="maxDepth"):
            parse(json.dumps(raw))

    def test_accepts_yaml_boolean_literals(self):
        raw = make_contract()
        raw["spec"]["arguments"] = [{"tool": "volumeDelete", "constraint": "false"}]
        contract = loads(json.dumps(raw))
        assert contract.name == "test-agent"

    def test_sign_and_verify(self, keypair):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        assert verify_signature(contract, public)

    def test_verify_fails_after_tamper(self, keypair):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        contract.raw["spec"]["tools"].append({"id": "evil:op", "digest": "sha256:" + "9" * 64})
        assert not verify_signature(contract, public)

    def test_unsigned_contract_does_not_verify(self):
        contract = Contract(raw=parse(json.dumps(make_contract())))
        assert not verify_signature(contract)


# --------------------------------------------------------------------------
# Diff — the reviewable artifact
# --------------------------------------------------------------------------

class TestDiff:
    def test_detects_newly_permitted_tool(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["spec"]["tools"].append({"id": "iam:CreateUser", "digest": "sha256:" + "1" * 64})
        result = diff(before, parse(json.dumps(after_raw)))
        assert "iam:CreateUser" in result.newly_permitted
        assert result.has_risk_increase

    def test_detects_removed_approval_gate(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        for tool in after_raw["spec"]["tools"]:
            if tool["id"] == "github:create_comment":
                tool.pop("requireApproval", None)
        result = diff(before, parse(json.dumps(after_raw)))
        assert any("approval gate removed" in w for w in result.widened)
        assert result.has_risk_increase

    def test_detects_removed_digest(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        # Remove the pin from a tool that stays bounded by its argument
        # predicate. A tool with no bound at all is rejected by contract
        # validation outright, so this is the realistic widening: still
        # permitted, no longer pinned to an approved definition.
        for tool in after_raw["spec"]["tools"]:
            if tool["id"] == "s3:PutObject":
                tool.pop("digest")
        result = diff(before, parse(json.dumps(after_raw)))
        assert any("pin removed" in w for w in result.widened)
        assert any("unpinned" in g for g in result.newly_permitted)
        assert result.has_risk_increase

    def test_detects_raised_budget(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["spec"]["budget"]["usd"] = 500
        result = diff(before, parse(json.dumps(after_raw)))
        assert any("budget.usd" in w for w in result.widened)

    def test_detects_principal_change(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["metadata"]["principal"] = "someone-else@example.com"
        result = diff(before, parse(json.dumps(after_raw)))
        assert result.principal_changed
        assert result.has_risk_increase

    def test_detects_delegation_widening(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["spec"]["delegation"]["maxDepth"] = 3
        result = diff(before, parse(json.dumps(after_raw)))
        assert any("maxDepth" in w for w in result.widened)

    def test_narrowing_is_not_a_risk_increase(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["spec"]["budget"]["usd"] = 1
        result = diff(before, parse(json.dumps(after_raw)))
        assert not result.has_risk_increase

    def test_identical_contracts_produce_no_changes(self):
        raw = parse(json.dumps(make_contract()))
        result = diff(raw, raw)
        assert not result.has_risk_increase
        assert not result.modified

    def test_render_diff_mentions_widening(self):
        before = parse(json.dumps(make_contract()))
        after_raw = make_contract()
        after_raw["spec"]["budget"]["usd"] = 999
        text = render_diff(diff(before, parse(json.dumps(after_raw))))
        assert "RISK INCREASES" in text


# --------------------------------------------------------------------------
# Compile and predicates
# --------------------------------------------------------------------------

class TestPredicates:
    def test_startswith(self):
        assert evaluate_predicate('startswith(args["b"], "ok-")', {"args": {"b": "ok-1"}})
        assert not evaluate_predicate('startswith(args["b"], "ok-")', {"args": {"b": "bad"}})

    def test_method_form(self):
        assert evaluate_predicate('args["p"].endswith(".md")', {"args": {"p": "a.md"}})
        assert not evaluate_predicate('args["p"].endswith(".md")', {"args": {"p": "a.exe"}})

    def test_membership(self):
        assert evaluate_predicate('args["t"] in ["a", "b"]', {"args": {"t": "a"}})
        assert not evaluate_predicate('args["t"] in ["a", "b"]', {"args": {"t": "c"}})

    def test_boolean_conjunction(self):
        predicate = 'args["t"] in ["x"] and args["n"] <= 3'
        assert evaluate_predicate(predicate, {"args": {"t": "x", "n": 3}})
        assert not evaluate_predicate(predicate, {"args": {"t": "x", "n": 4}})

    def test_literal_false_denies(self):
        assert not evaluate_predicate("false", {"args": {}})

    def test_rejects_import(self):
        with pytest.raises(CompileError):
            validate_predicate("__import__('os').system('id')")

    def test_rejects_dunder_access(self):
        with pytest.raises(CompileError):
            validate_predicate("args['x'].__class__.__bases__")

    def test_rejects_unknown_function(self):
        with pytest.raises(CompileError):
            validate_predicate("open('/etc/passwd').read()")

    def test_unknown_variable_raises_at_eval(self):
        with pytest.raises(CompileError):
            evaluate_predicate('args["a"] == missing_var', {"args": {"a": 1}})


class TestCompile:
    def test_compiles_tools_and_predicates(self):
        policy = compile_contract(parse(json.dumps(make_contract())))
        assert "s3:GetObject" in policy.tools
        assert policy.tools["github:create_comment"]["requireApproval"] is True
        assert policy.predicates["s3:PutObject"]

    def test_policy_hash_is_stable(self):
        raw = parse(json.dumps(make_contract()))
        assert compile_contract(raw).policy_hash() == compile_contract(raw).policy_hash()

    def test_policy_hash_changes_with_rules(self):
        first = compile_contract(parse(json.dumps(make_contract())))
        after_raw = make_contract()
        after_raw["spec"]["budget"]["usd"] = 99
        second = compile_contract(parse(json.dumps(after_raw)))
        assert first.policy_hash() != second.policy_hash()

    def test_pattern_matching(self):
        assert match_pattern("*", "anything")
        assert match_pattern("*Delete*", "s3:DeleteObject") is False  # prefix wildcards only
        assert match_pattern("aws:s3:*", "aws:s3:PutObject")
        assert match_pattern("exact", "exact")
        assert not match_pattern("exact", "exact2")

    def test_render_policy_includes_predicates(self):
        text = render_policy(compile_contract(parse(json.dumps(make_contract()))))
        assert "s3:PutObject" in text
        assert "requires approval" in text


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------

class TestLedger:
    def test_appends_and_chains(self, tmp_path):
        ledger = Ledger.open(tmp_path / "l.jsonl")
        contract = Contract(raw=parse(json.dumps(make_contract())))
        first = ledger.append(
            contract=contract, policy_hash="sha256:x", agent_id="a", tool="t",
            args={}, decision="allow", reason="ok",
        )
        second = ledger.append(
            contract=contract, policy_hash="sha256:x", agent_id="a", tool="t",
            args={}, decision="deny", reason="no",
        )
        assert second.prev_hash == first.hash()

    def test_verify_detects_modification(self, tmp_path):
        path = tmp_path / "l.jsonl"
        ledger = Ledger.open(path)
        contract = Contract(raw=parse(json.dumps(make_contract())))
        for index in range(3):
            ledger.append(
                contract=contract, policy_hash="sha256:x", agent_id="a",
                tool=f"t{index}", args={}, decision="allow", reason="ok",
            )
        lines = path.read_text().splitlines()
        record = json.loads(lines[1])
        record["tool"] = "tampered"
        lines[1] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n")

        ok, problems = Ledger.open(path).verify()
        assert not ok
        assert any("modified" in p for p in problems)

    def test_verify_detects_deletion(self, tmp_path):
        path = tmp_path / "l.jsonl"
        ledger = Ledger.open(path)
        contract = Contract(raw=parse(json.dumps(make_contract())))
        for index in range(3):
            ledger.append(
                contract=contract, policy_hash="sha256:x", agent_id="a",
                tool=f"t{index}", args={}, decision="allow", reason="ok",
            )
        lines = path.read_text().splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        ok, problems = Ledger.open(path).verify()
        assert not ok
        assert any("deleted or reordered" in p for p in problems)

    def test_verify_passes_on_intact_chain(self, tmp_path):
        ledger = Ledger.open(tmp_path / "l.jsonl")
        contract = Contract(raw=parse(json.dumps(make_contract())))
        for index in range(3):
            ledger.append(
                contract=contract, policy_hash="sha256:x", agent_id="a",
                tool=f"t{index}", args={}, decision="allow", reason="ok",
            )
        ok, problems = ledger.verify()
        assert ok and not problems

    def test_redaction_hides_secrets(self):
        result = redact({"token": "secret-value", "api_key": "abc"})
        assert result["token"] == "<redacted:secret>"
        assert result["api_key"] == "<redacted:secret>"

    def test_redaction_keeps_safe_fields(self):
        result = redact({"bucket": "recon-artifacts-2026", "region": "us-east-1"})
        assert result["bucket"] == "recon-artifacts-2026"

    def test_redaction_hashes_unknown_fields(self):
        result = redact({"custom_blob": "some content"})
        assert result["custom_blob"].startswith("<redacted:")

    def test_rejects_unknown_decision(self, tmp_path):
        ledger = Ledger.open(tmp_path / "l.jsonl")
        contract = Contract(raw=parse(json.dumps(make_contract())))
        with pytest.raises(Exception):
            ledger.append(
                contract=contract, policy_hash="x", agent_id="a", tool="t",
                args={}, decision="maybe", reason="?",
            )


# --------------------------------------------------------------------------
# Leases
# --------------------------------------------------------------------------

class TestLeases:
    def test_commits_within_budget(self, tmp_path):
        store = LeaseStore(tmp_path / "leases.json")
        state = store.check_and_commit("c", Budget(usd=10), usd=3)
        assert state.usd == 3

    def test_rejects_over_budget(self, tmp_path):
        store = LeaseStore(tmp_path / "leases.json")
        store.check_and_commit("c", Budget(usd=10), usd=8)
        with pytest.raises(BudgetExceeded):
            store.check_and_commit("c", Budget(usd=10), usd=5)

    def test_rejection_does_not_consume(self, tmp_path):
        store = LeaseStore(tmp_path / "leases.json")
        store.check_and_commit("c", Budget(usd=10), usd=8)
        with pytest.raises(BudgetExceeded):
            store.check_and_commit("c", Budget(usd=10), usd=5)
        assert store.state("c").usd == 8

    def test_tool_call_ceiling(self, tmp_path):
        store = LeaseStore(tmp_path / "leases.json")
        store.check_and_commit("c", Budget(tool_calls=2), tool_calls=2)
        with pytest.raises(BudgetExceeded):
            store.check_and_commit("c", Budget(tool_calls=2), tool_calls=1)

    def test_egress_ceiling(self, tmp_path):
        store = LeaseStore(tmp_path / "leases.json")
        with pytest.raises(BudgetExceeded):
            store.check_and_commit("c", Budget(egress_gib=1), egress_gib=2)

    def test_concurrent_branches_cannot_overspend(self, tmp_path):
        import threading

        store = LeaseStore(tmp_path / "leases.json")
        budget = Budget(usd=10)
        granted = []

        def branch():
            try:
                store.check_and_commit("c", budget, usd=1)
                granted.append(1)
            except BudgetExceeded:
                pass

        threads = [threading.Thread(target=branch) for _ in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(granted) == 10
        assert store.state("c").usd == 10.0

    def test_cost_scales_with_instance_type(self):
        cheap = estimate_cost("ec2:RunInstances", {"instance_type": "t3.medium", "count": 1})
        dear = estimate_cost("ec2:RunInstances", {"instance_type": "m8g.12xlarge", "count": 5})
        assert dear > cheap * 100

    def test_unknown_instance_type_is_not_free(self):
        cost = estimate_cost("ec2:RunInstances", {"instance_type": "mystery.huge", "count": 1})
        assert cost > 0

    def test_aws_prefix_resolves(self):
        assert estimate_cost("aws:s3:PutObject", {}) == estimate_cost("s3:PutObject", {})


# --------------------------------------------------------------------------
# Mediator
# --------------------------------------------------------------------------

class TestMediator:
    def build(self, tmp_path, keypair, **kwargs):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        ledger = Ledger.open(tmp_path / "ledger.jsonl")
        mediator = Mediator(
            contract, ledger=ledger, shadow=False,
            verify_signature_required=True, public_key_path=public, **kwargs,
        )
        return mediator

    def test_denies_ungranted_tool(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(ToolCall(tool="iam:CreateUser", args={}))
        assert outcome.decision == DENY

    def test_allows_granted_tool_with_digest(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="s3:GetObject", args={"bucket": "b", "key": "k"},
                     digest="sha256:" + "a" * 64)
        )
        assert outcome.decision == ALLOW

    def test_denies_on_digest_mismatch(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="s3:GetObject", args={}, digest="sha256:" + "z" * 64)
        )
        assert outcome.decision == DENY
        assert "drift" in outcome.reason

    def test_denies_on_missing_digest_when_pinned(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(ToolCall(tool="s3:GetObject", args={}))
        assert outcome.decision == DENY

    def test_denies_on_predicate_failure(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="s3:PutObject", args={"bucket": "prod"}, digest="sha256:" + "b" * 64)
        )
        assert outcome.decision == DENY

    def test_denies_on_taint(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="github:create_comment", args={}, digest="sha256:" + "d" * 64,
                     taint=["untrusted:web"])
        )
        assert outcome.decision == DENY

    def test_approval_required_when_no_taint(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="github:create_comment", args={}, digest="sha256:" + "d" * 64)
        )
        assert outcome.decision == APPROVE

    def test_denies_on_delegation_depth(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="s3:GetObject", args={}, digest="sha256:" + "a" * 64,
                     delegation_depth=5)
        )
        assert outcome.decision == DENY

    def test_denies_non_delegable_via_delegate(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="volumeDelete", args={}, digest="sha256:" + "c" * 64,
                     parent_agent_id="child", delegation_depth=1)
        )
        assert outcome.decision == DENY

    def test_denies_expired_contract(self, tmp_path, keypair):
        private, public = keypair
        now = dt.datetime.now(dt.timezone.utc)
        raw = make_contract()
        raw["metadata"]["issued"] = (now - dt.timedelta(hours=3)).isoformat().replace("+00:00", "Z")
        raw["metadata"]["expires"] = (now - dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        contract = Contract(raw=parse(json.dumps(raw)))
        sign(contract, private)
        mediator = Mediator(
            contract, ledger=Ledger.open(tmp_path / "l.jsonl"), shadow=False,
            verify_signature_required=True, public_key_path=public,
        )
        outcome = mediator.evaluate(ToolCall(tool="s3:GetObject", args={}))
        assert outcome.decision == DENY
        assert "expired" in outcome.reason

    def test_denies_unsigned_when_verification_required(self, tmp_path, keypair):
        _, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        mediator = Mediator(
            contract, ledger=Ledger.open(tmp_path / "l.jsonl"), shadow=False,
            verify_signature_required=True, public_key_path=public,
        )
        outcome = mediator.evaluate(ToolCall(tool="s3:GetObject", args={}))
        assert outcome.decision == DENY

    def test_denies_tampered_signature(self, tmp_path, keypair):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        contract.raw["spec"]["tools"].append({"id": "evil:op", "digest": "sha256:" + "9" * 64})
        mediator = Mediator(
            contract, ledger=Ledger.open(tmp_path / "l.jsonl"), shadow=False,
            verify_signature_required=True, public_key_path=public,
        )
        outcome = mediator.evaluate(ToolCall(tool="evil:op", args={}, digest="sha256:" + "9" * 64))
        assert outcome.decision == DENY

    def test_shadow_mode_records_without_blocking(self, tmp_path, keypair):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        ledger = Ledger.open(tmp_path / "l.jsonl")
        mediator = Mediator(
            contract, ledger=ledger, shadow=True,
            verify_signature_required=True, public_key_path=public,
        )
        outcome = mediator.evaluate(ToolCall(tool="iam:CreateUser", args={}))
        assert outcome.decision == ALLOW
        assert "[shadow]" in outcome.reason
        assert ledger.length == 1

    def test_preflight_reports_missing_ledger(self, tmp_path, keypair):
        private, public = keypair
        contract = Contract(raw=parse(json.dumps(make_contract())))
        sign(contract, private)
        mediator = Mediator(contract, ledger=None, shadow=False, public_key_path=public)
        assert any("ledger" in p for p in mediator.preflight())

    def test_every_decision_is_recorded(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        for tool in ("s3:GetObject", "iam:CreateUser", "s3:PutObject"):
            mediator.evaluate(ToolCall(tool=tool, args={}, digest="sha256:" + "a" * 64))
        assert mediator.ledger.length == 3

    def test_agent_cannot_self_approve(self, tmp_path, keypair):
        mediator = self.build(tmp_path, keypair)
        outcome = mediator.evaluate(
            ToolCall(tool="github:create_comment", args={}, digest="sha256:" + "d" * 64)
        )
        assert outcome.decision == APPROVE
        with pytest.raises(ContractError):
            mediator.resolve_approval(
                outcome.approval_id, approved=True, resolver=mediator.contract.workload
            )
