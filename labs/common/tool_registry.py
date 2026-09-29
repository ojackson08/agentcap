"""Tool definitions for the labs, with real digests.

A contract that pins a placeholder digest denies everything for the wrong
reason, which teaches the wrong lesson. These definitions are the actual
artifacts the labs' contracts pin, so a denial in a lab is always the
semantically correct denial:

    volumeDelete          -> not granted by the contract
    s3:PutObject          -> argument predicate not satisfied
    github:create_comment -> requires human approval / data-flow blocked
    ec2:RunInstances      -> argument predicate not satisfied
"""

from __future__ import annotations

import json

from agentcap.contract import sha256_bytes

# The advertised shape of each tool. In a real deployment these come from the
# MCP tools/list response or from an OpenAPI spec; here they are fixtures.
TOOL_DEFINITIONS: dict[str, dict] = {
    "volumeDelete": {
        "name": "volumeDelete",
        "description": "Delete a persistent volume and all data on it. Irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {"volume_id": {"type": "string"}},
            "required": ["volume_id"],
        },
    },
    "ec2:RunInstances": {
        "name": "RunInstances",
        "description": "Launch EC2 instances.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_type": {"type": "string"},
                "count": {"type": "integer"},
                "region": {"type": "string"},
            },
            "required": ["instance_type", "count"],
        },
    },
    "s3:GetObject": {
        "name": "GetObject",
        "description": "Read an object from S3.",
        "inputSchema": {
            "type": "object",
            "properties": {"bucket": {"type": "string"}, "key": {"type": "string"}},
            "required": ["bucket", "key"],
        },
    },
    "s3:PutObject": {
        "name": "PutObject",
        "description": "Write an object to S3.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket": {"type": "string"},
                "key": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["bucket", "key"],
        },
    },
    "s3:DeleteObject": {
        "name": "DeleteObject",
        "description": "Permanently delete an object from S3.",
        "inputSchema": {
            "type": "object",
            "properties": {"bucket": {"type": "string"}, "key": {"type": "string"}},
            "required": ["bucket", "key"],
        },
    },
    "github:list_issues": {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        },
    },
    "github:read_file": {
        "name": "read_file",
        "description": "Read a file from a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}, "path": {"type": "string"}},
            "required": ["repo", "path"],
        },
    },
    "github:create_comment": {
        "name": "create_comment",
        "description": "Post a comment on an issue. Visible to everyone with repo access.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "issue": {"type": "integer"},
                "body": {"type": "string"},
            },
            "required": ["repo", "issue", "body"],
        },
    },
    "http:egress": {
        "name": "egress",
        "description": "Make an outbound HTTP request.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
            "required": ["url"],
        },
    },
}


def digest_for(tool_id: str) -> str:
    definition = TOOL_DEFINITIONS[tool_id]
    return sha256_bytes(
        json.dumps(definition, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def all_digests() -> dict[str, str]:
    return {tool_id: digest_for(tool_id) for tool_id in TOOL_DEFINITIONS}


def pin_contract(raw: dict) -> dict:
    """Rewrite a contract's tool digests to the real definitions.

    Called by the lab runners so that every denial they print is the denial a
    real deployment would produce, not an artifact of a placeholder hash.
    """
    for entry in raw["spec"].get("tools", []):
        tool_id = entry["id"]
        if tool_id in TOOL_DEFINITIONS:
            entry["digest"] = digest_for(tool_id)
    return raw


def digest_map_for(tool_ids: list[str]) -> dict[str, str]:
    return {tool_id: digest_for(tool_id) for tool_id in tool_ids if tool_id in TOOL_DEFINITIONS}
