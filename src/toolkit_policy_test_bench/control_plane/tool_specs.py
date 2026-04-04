"""
CLI command -> ToolSpec mapping for toolkit-policy-test-bench.

Maps the primary CLI subcommands (keygen, pack, run, compare, validate-report)
to ToolSpec contracts with appropriate permission scope and approval policy.

'run' executes policy suites against LLM predictions (READ_ONLY + AUTO).
'compare' compares reports (READ_ONLY + AUTO).
'validate-report' validates a report file (READ_ONLY + AUTO).
'keygen' generates signing keypairs (WORKSPACE_WRITE + REQUIRE_APPROVAL).
'pack' operates on suite zips -- create/sign write files; inspect/verify are read-only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import ApprovalPolicy, AuthorityBoundary, PermissionScope, ToolSpec


@dataclass
class ToolkitCommandSpec:
    """Maps a CLI subcommand name to its ToolSpec and authority boundary."""

    command: str
    spec: ToolSpec
    boundary: AuthorityBoundary


def _make_spec(
    name: str,
    description: str,
    scope: PermissionScope = PermissionScope.READ_ONLY,
    input_schema: dict[str, Any] | None = None,
) -> ToolSpec:
    """Create a ToolSpec for a policy-test-bench CLI command."""
    return ToolSpec(
        name=name,
        description=description,
        category="tool",
        version="0.1.0",
        owner="toolkit-policy-test-bench",
        permission_scope=scope,
        input_schema=input_schema,
        output_schema=None,
        sandbox_requirement=None,
        aliases=None,
    )


_READ_ONLY_AUTO = AuthorityBoundary(
    scope=PermissionScope.READ_ONLY,
    approval=ApprovalPolicy.AUTO,
)

_WRITE_APPROVE = AuthorityBoundary(
    scope=PermissionScope.WORKSPACE_WRITE,
    approval=ApprovalPolicy.REQUIRE_APPROVAL,
)

# -- Per-command specs ---------------------------------------------------------

TOOLKIT_TOOL_SPECS: dict[str, ToolkitCommandSpec] = {
    "run": ToolkitCommandSpec(
        command="run",
        spec=_make_spec(
            name="run",
            description=(
                "Run a policy test suite against LLM prediction files, detecting "
                "PII leakage and policy regressions. Read-only analysis."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "suite": {"type": "string", "description": "Path to suite dir or zip"},
                    "predictions": {"type": "string", "description": "Path to predictions JSONL"},
                    "out": {"type": "string", "description": "Output report path"},
                    "format": {"type": "string", "enum": ["json", "text"]},
                },
                "required": ["suite", "predictions"],
            },
        ),
        boundary=_READ_ONLY_AUTO,
    ),
    "compare": ToolkitCommandSpec(
        command="compare",
        spec=_make_spec(
            name="compare",
            description=(
                "Compare a candidate policy report against a baseline report. "
                "Read-only; reports regressions and improvements to stdout."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "baseline": {"type": "string", "description": "Baseline report path"},
                    "candidate": {"type": "string", "description": "Candidate report path"},
                    "format": {"type": "string", "enum": ["json", "text"]},
                },
                "required": ["baseline", "candidate"],
            },
        ),
        boundary=_READ_ONLY_AUTO,
    ),
    "validate-report": ToolkitCommandSpec(
        command="validate-report",
        spec=_make_spec(
            name="validate_report",
            description=(
                "Validate a policy report JSON file against the expected schema. "
                "Read-only."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "report": {"type": "string", "description": "Path to report JSON"},
                },
                "required": ["report"],
            },
        ),
        boundary=_READ_ONLY_AUTO,
    ),
    "keygen": ToolkitCommandSpec(
        command="keygen",
        spec=_make_spec(
            name="keygen",
            description=(
                "Generate an Ed25519 keypair for signing suite packs. "
                "Writes key files to disk. Requires approval."
            ),
            scope=PermissionScope.WORKSPACE_WRITE,
            input_schema={
                "type": "object",
                "properties": {
                    "private_key": {"type": "string"},
                    "public_key": {"type": "string"},
                },
                "required": ["private_key", "public_key"],
            },
        ),
        boundary=_WRITE_APPROVE,
    ),
    "pack": ToolkitCommandSpec(
        command="pack",
        spec=_make_spec(
            name="pack",
            description=(
                "Suite pack utilities (create, inspect, verify, sign, verify-signature). "
                "Create and sign sub-commands write files; inspect and verify are read-only."
            ),
            scope=PermissionScope.WORKSPACE_WRITE,
            input_schema={
                "type": "object",
                "properties": {
                    "subcommand": {
                        "type": "string",
                        "enum": ["create", "inspect", "verify", "sign", "verify-signature"],
                    },
                    "suite": {"type": "string"},
                    "out": {"type": "string"},
                },
                "required": ["subcommand"],
            },
        ),
        boundary=_WRITE_APPROVE,
    ),
}


def get_tool_spec(command: str) -> ToolkitCommandSpec | None:
    """Return the ToolkitCommandSpec for a CLI subcommand, or None if unknown."""
    return TOOLKIT_TOOL_SPECS.get(command)


__all__ = ["TOOLKIT_TOOL_SPECS", "ToolkitCommandSpec", "get_tool_spec"]
