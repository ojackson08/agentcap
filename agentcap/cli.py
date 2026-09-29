"""The agentcap CLI.

Six commands, no UI. `plan` is the one that matters most: it shows what a
contract change would *newly permit*, which is the artifact a security reviewer
actually reads.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .compile import compile_contract, render_policy, render_rego
from .contract import (
    Contract,
    ContractError,
    diff,
    generate_keypair,
    load,
    load_raw,
    render_diff,
    sign,
    verify_signature,
)
from .ledger import Ledger, load_public_key
from .mediator import Mediator, ToolCall, build_mediator

STARTER_CONTRACT = """\
apiVersion: agentcap.dev/v1
kind: CapabilityContract
metadata:
  name: {name}
  principal: {principal}
  issued: "{issued}"
  expires: "{expires}"
spec:
  identity:
    workload: spiffe://local/agent/{name}

  delegation:
    maxDepth: 0
    nonDelegable:
      - "*Delete*"

  tools:
    - id: aws:s3:GetObject
      digest: sha256:{zero}
      allow: [read]
    - id: aws:s3:PutObject
      digest: sha256:{zero}
    - id: aws:ec2:RunInstances
      digest: sha256:{zero}
    - id: mcp://github/create_comment
      digest: sha256:{zero}
      requireApproval: true
    - id: aws:s3:DeleteObject
      digest: sha256:{zero}

  arguments:
    - tool: aws:s3:PutObject
      constraint: startswith(args["bucket"], "agent-artifacts-")
    - tool: aws:ec2:RunInstances
      constraint: args["instance_type"] in ["t3.medium", "t3.large"] and args["count"] <= 3
    - tool: aws:s3:DeleteObject
      constraint: "false"

  dataFlow:
    - from: untrusted:web
      deny: [mcp://github/create_comment, http://*, aws:iam:*]

  budget:
    usd: 25
    toolCalls: 500
    egressGiB: 1
"""


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    """Write a starter contract and generate a signing key if needed."""
    import datetime as dt

    target = Path(args.output or "contract.yaml")
    if target.exists() and not args.force:
        print(f"error: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1

    now = dt.datetime.now(dt.timezone.utc)
    body = STARTER_CONTRACT.format(
        name=args.name or "my-agent",
        principal=args.principal or os.environ.get("USER", "unknown") + "@local",
        issued=now.isoformat().replace("+00:00", "Z"),
        expires=(now + dt.timedelta(hours=12)).isoformat().replace("+00:00", "Z"),
        zero="0" * 64,
    )
    target.write_text(body, encoding="utf-8")
    print(f"wrote {target}")

    key_dir = Path(os.environ.get("AGENTCAP_KEY_DIR", Path.home() / ".agentcap"))
    if not (key_dir / "local.key").exists():
        private, public = generate_keypair(str(key_dir / "local"))
        print(f"generated signing key: {private}")
        print(f"generated public key:  {public}")
    else:
        print(f"using existing signing key: {key_dir / 'local.key'}")

    print()
    print("Next: replace the placeholder digests with real tool-definition hashes,")
    print("      then run `agentcap sign` and `agentcap plan`.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        contract = load(args.contract)
    except ContractError as exc:
        print(f"INVALID\n{exc}", file=sys.stderr)
        return 1

    policy = compile_contract(contract.raw)
    print(f"VALID  {contract.name}")
    print(f"  principal:  {contract.principal}")
    print(f"  workload:   {contract.workload}")
    print(f"  expires:    {contract.raw['metadata']['expires']}")
    print(f"  tools:      {len(policy.tools)}")
    print(f"  policyHash: {policy.policy_hash()}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    try:
        contract = load(args.contract)
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sign(contract, args.key)
    envelope = contract.to_envelope()

    output = Path(args.output or str(args.contract).replace(".yaml", ".signed.json"))
    output.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    print(f"signed  {contract.name}")
    print(f"  signer: {contract.signer}")
    print(f"  wrote:  {output}")

    if shutil.which("cosign"):
        print("  cosign detected: for transparency-log publication, run")
        print(f"    cosign upload blob --yes --key <key> {output}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """Show what a contract change would newly permit. Terraform plan for authority."""
    try:
        after = load(args.contract)
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.previous:
        print(render_policy(compile_contract(after.raw)))
        return 0

    try:
        before_raw = load_raw(args.previous)
        after_raw = load_raw(args.contract)
    except ContractError as exc:
        print(f"error reading previous contract: {exc}", file=sys.stderr)
        return 1

    result = diff(before_raw, after_raw)
    print(f"Plan: {before_raw['metadata']['name']}  ->  {after_raw['metadata']['name']}")
    print()
    print(render_diff(result))
    print()

    if result.has_risk_increase:
        print("  This change INCREASES granted authority. Review before applying.")
        return 0
    print("  This change does not increase granted authority.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command with the mediator in front of it."""
    mediator = build_mediator(
        args.contract,
        shadow=args.shadow,
        require_signature=not args.no_verify,
    )

    problems = mediator.preflight()
    if problems and not args.shadow:
        print("refusing to start; preconditions not met:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    print(f"contract: {mediator.contract.name}")
    print(f"policy:   {mediator.policy.policy_hash()[:24]}...")
    print(f"mode:     {'SHADOW (nothing is blocked)' if args.shadow else 'ENFORCING'}")
    print(f"ledger:   {mediator.ledger.path if mediator.ledger else 'none'}")
    print()

    if not args.command:
        print("no command given; nothing to run")
        return 0

    env = dict(os.environ)
    env["AGENTCAP_CONTRACT"] = str(args.contract)
    env["AGENTCAP_STATE_DIR"] = str(
        Path(args.state_dir) if args.state_dir else Path(".agentcap")
    )
    env["AGENTCAP_SHADOW"] = "1" if args.shadow else "0"
    env["AGENTCAP_POLICY_HASH"] = mediator.policy.policy_hash()

    completed = subprocess.run(args.command, env=env, check=False)
    return completed.returncode


def cmd_inspect(args: argparse.Namespace) -> int:
    """Query the ledger."""
    ledger = Ledger.open(args.ledger)
    records = ledger.records

    if args.decision:
        records = [r for r in records if r["decision"] == args.decision]
    if args.tool:
        records = [r for r in records if args.tool in r["tool"]]

    if args.json:
        print(json.dumps(records[-args.limit :], indent=2))
        return 0

    print(f"ledger: {ledger.path}")
    print(f"records: {ledger.length} total, showing {min(len(records), args.limit)}")
    print(f"head:    {ledger.head}")
    print()

    denied = sum(1 for r in ledger.records if r["decision"] == "deny")
    allowed = sum(1 for r in ledger.records if r["decision"] == "allow")
    pending = sum(1 for r in ledger.records if r["decision"] == "approve")
    print(f"allow={allowed}  deny={denied}  approve={pending}")
    print()

    for record in records[-args.limit :]:
        marker = {"allow": "ALLOW", "deny": "DENY ", "approve": "APPR "}[record["decision"]]
        print(f"  {record['seq']:>5}  {marker}  {record['tool']}")
        print(f"         {record['reason']}")
        print(f"         policy={record['policyHash'][7:19]}... record={record['hash'][7:19]}...")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the ledger's hash chain and signatures."""
    ledger = Ledger.open(args.ledger)
    public_key = None
    if not args.no_signature:
        public_key = load_public_key(args.public_key)

    ok, problems = ledger.verify(public_key=public_key)

    print(f"ledger:  {ledger.path}")
    print(f"records: {ledger.length}")
    print(f"head:    {ledger.head}")
    print()

    if ok:
        if ledger.length == 0:
            print("CHAIN INTACT — but the ledger is empty, so nothing was verified.")
            return 0
        print("CHAIN INTACT — no records modified, deleted, or reordered")
        if public_key is not None:
            print("SIGNATURES VALID — every record verifies against the public key")
        else:
            print("(signatures not checked; no public key available)")
        return 0

    print(f"CHAIN BROKEN — {len(problems)} problem(s):", file=sys.stderr)
    for problem in problems[:25]:
        print(f"  - {problem}", file=sys.stderr)
    return 1


def cmd_revoke(args: argparse.Namespace) -> int:
    """Revoke a contract: block new calls, record the revocation."""
    state_dir = Path(args.state_dir or ".agentcap")
    state_dir.mkdir(parents=True, exist_ok=True)
    revoked_path = state_dir / "revoked.json"

    revoked = {}
    if revoked_path.exists():
        revoked = json.loads(revoked_path.read_text(encoding="utf-8"))

    import datetime as dt

    revoked[args.contract_name] = {
        "revokedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "reason": args.reason or "manual revocation",
    }
    revoked_path.write_text(json.dumps(revoked, indent=2), encoding="utf-8")

    print(f"REVOKED  {args.contract_name}")
    print(f"  reason: {revoked[args.contract_name]['reason']}")
    print(f"  at:     {revoked[args.contract_name]['revokedAt']}")
    print()
    print("  Next steps this command cannot do for you:")
    print("    - revoke any STS sessions or OAuth tokens minted under this contract")
    print("    - cancel queued work items that reference it")
    print("    - preserve the ledger slice covering this contract before rotating state")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    contract = load(args.contract)
    policy = compile_contract(contract.raw)
    if args.format == "rego":
        print(render_rego(policy))
    else:
        print(render_policy(policy))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what this host can actually enforce."""
    from .adapters import sandbox_available

    print(f"agentcap {__version__}")
    print()
    print("Isolation primitives:")
    for name, present in sandbox_available().items():
        print(f"  {'yes' if present else 'no ':>4}  {name}")
    print()
    print("Signing:")
    key_dir = Path(os.environ.get("AGENTCAP_KEY_DIR", Path.home() / ".agentcap"))
    print(f"  {'yes' if (key_dir / 'local.key').exists() else 'no ':>4}  private key at {key_dir}")
    print(f"  {'yes' if (key_dir / 'local.pub').exists() else 'no ':>4}  public key")
    print()
    print("Optional:")
    for tool in ("cosign", "opa", "git"):
        present = shutil.which(tool) is not None
        print(f"  {'yes' if present else 'no ':>4}  {tool}")
    print()
    print("Reminder: a mediator cannot protect paths it does not mediate.")
    print("Run the conformance suite to see measured coverage, not assumed coverage.")
    return 0


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcap",
        description="Capability-contract enforcement for AI agent tool calls.",
    )
    parser.add_argument("--version", action="version", version=f"agentcap {__version__}")
    sub = parser.add_subparsers(dest="command_name", required=True)

    p_init = sub.add_parser("init", help="write a starter contract")
    p_init.add_argument("--name", help="contract name")
    p_init.add_argument("--principal", help="accountable human or team")
    p_init.add_argument("--output", help="output path (default contract.yaml)")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate", help="validate a contract")
    p_validate.add_argument("contract")
    p_validate.set_defaults(func=cmd_validate)

    p_sign = sub.add_parser("sign", help="sign a contract")
    p_sign.add_argument("contract")
    p_sign.add_argument("--key", help="private key path")
    p_sign.add_argument("--output", help="output envelope path")
    p_sign.set_defaults(func=cmd_sign)

    p_plan = sub.add_parser("plan", help="show what a contract would allow, or what changed")
    p_plan.add_argument("contract")
    p_plan.add_argument("--previous", help="previous contract, to diff against")
    p_plan.set_defaults(func=cmd_plan)

    p_run = sub.add_parser("run", help="run a command with the mediator in front")
    p_run.add_argument("contract")
    p_run.add_argument("--shadow", action="store_true", default=True,
                       help="record decisions without blocking (default)")
    p_run.add_argument("--enforce", dest="shadow", action="store_false",
                       help="actually block denied calls")
    p_run.add_argument("--no-verify", action="store_true",
                       help="do not require a valid contract signature")
    p_run.add_argument("--state-dir", help="state directory (default .agentcap)")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="command to run")
    p_run.set_defaults(func=cmd_run)

    p_inspect = sub.add_parser("inspect", help="query the decision ledger")
    p_inspect.add_argument("--ledger", default=".agentcap/ledger.jsonl")
    p_inspect.add_argument("--decision", choices=["allow", "deny", "approve"])
    p_inspect.add_argument("--tool")
    p_inspect.add_argument("--limit", type=int, default=20)
    p_inspect.add_argument("--json", action="store_true")
    p_inspect.set_defaults(func=cmd_inspect)

    p_verify = sub.add_parser("verify", help="verify the ledger hash chain")
    p_verify.add_argument("--ledger", default=".agentcap/ledger.jsonl")
    p_verify.add_argument("--public-key")
    p_verify.add_argument("--no-signature", action="store_true")
    p_verify.set_defaults(func=cmd_verify)

    p_revoke = sub.add_parser("revoke", help="revoke a contract")
    p_revoke.add_argument("contract_name")
    p_revoke.add_argument("--reason")
    p_revoke.add_argument("--state-dir")
    p_revoke.set_defaults(func=cmd_revoke)

    p_explain = sub.add_parser("explain", help="render the compiled policy")
    p_explain.add_argument("contract")
    p_explain.add_argument("--format", choices=["text", "rego"], default="text")
    p_explain.set_defaults(func=cmd_explain)

    p_doctor = sub.add_parser("doctor", help="report what this host can enforce")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
