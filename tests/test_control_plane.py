"""
Tests for toolkit-policy-test-bench control_plane adapter.

Coverage:
  - contracts: PermissionScope ordinal, AuthorityBoundary helpers
  - config: build_config_hierarchy (platform defaults, overrides, CLI)
  - tool_specs: TOOLKIT_TOOL_SPECS covers all 5 commands, get_tool_spec lookup
  - Optional framework import: _HAS_EXECUTION_CONTRACTS flag is a bool (no crash)
"""
from __future__ import annotations

from toolkit_policy_test_bench.control_plane.contracts import (
    ApprovalPolicy,
    AuthorityBoundary,
    PermissionScope,
    ToolSpec,
    _HAS_EXECUTION_CONTRACTS,
)
from toolkit_policy_test_bench.control_plane.config import (
    CONFIG_LEVELS,
    ToolkitConfigContract,
    build_config_hierarchy,
)
from toolkit_policy_test_bench.control_plane.tool_specs import (
    TOOLKIT_TOOL_SPECS,
    get_tool_spec,
)


# -- contracts ----------------------------------------------------------------


class TestPermissionScope:
    def test_values_are_strings(self) -> None:
        assert PermissionScope.READ_ONLY.value == "read_only"
        assert PermissionScope.WORKSPACE_WRITE.value == "workspace_write"
        assert PermissionScope.FULL_ACCESS.value == "full_access"

    def test_ordinal_ascending(self) -> None:
        boundary = AuthorityBoundary(scope=PermissionScope.FULL_ACCESS, approval=ApprovalPolicy.AUTO)
        assert boundary.scope_allows(PermissionScope.READ_ONLY)

    def test_lower_does_not_satisfy_higher(self) -> None:
        boundary = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.AUTO)
        assert not boundary.scope_allows(PermissionScope.WORKSPACE_WRITE)
        assert not boundary.scope_allows(PermissionScope.FULL_ACCESS)


class TestApprovalPolicy:
    def test_values_are_strings(self) -> None:
        assert ApprovalPolicy.AUTO.value == "auto"
        assert ApprovalPolicy.REQUIRE_APPROVAL.value == "require_approval"
        assert ApprovalPolicy.DENY.value == "deny"


class TestAuthorityBoundary:
    def test_is_denied(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.DENY)
        assert b.is_denied()
        assert not b.needs_approval()

    def test_needs_approval(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.FULL_ACCESS, approval=ApprovalPolicy.REQUIRE_APPROVAL)
        assert b.needs_approval()
        assert not b.is_denied()

    def test_auto_neither(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.WORKSPACE_WRITE, approval=ApprovalPolicy.AUTO)
        assert not b.is_denied()
        assert not b.needs_approval()

    def test_sandbox_defaults_none(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.AUTO)
        assert b.sandbox is None


class TestToolSpec:
    def test_construction(self) -> None:
        spec = ToolSpec(
            name="run",
            description="test",
            category="tool",
            version="0.1.0",
            owner="toolkit-policy-test-bench",
            permission_scope=PermissionScope.READ_ONLY,
        )
        assert spec.name == "run"
        assert spec.permission_scope == PermissionScope.READ_ONLY
        assert spec.input_schema is None

    def test_repr_contains_name(self) -> None:
        spec = ToolSpec(
            name="compare",
            description="test",
            category="tool",
            version="0.1.0",
            owner="o",
            permission_scope=PermissionScope.READ_ONLY,
        )
        assert "compare" in repr(spec)


class TestFrameworkFlag:
    def test_flag_is_bool(self) -> None:
        assert isinstance(_HAS_EXECUTION_CONTRACTS, bool)


# -- config -------------------------------------------------------------------


class TestConfigLevels:
    def test_ordering(self) -> None:
        assert CONFIG_LEVELS["platform_default"] < CONFIG_LEVELS["toolkit_config"]
        assert CONFIG_LEVELS["toolkit_config"] < CONFIG_LEVELS["cli_override"]


class TestBuildConfigHierarchy:
    def test_defaults(self) -> None:
        cfg = build_config_hierarchy()
        assert cfg.toolkit_id == "TK-PT"
        assert cfg.toolkit_name == "toolkit-policy-test-bench"
        assert cfg.log_format == "json"
        assert cfg.structured_logging is True
        assert cfg.fail_fast is False
        assert cfg.max_failures == 0
        assert cfg.timeout_seconds == 300

    def test_toolkit_config_overrides_defaults(self) -> None:
        cfg = build_config_hierarchy(toolkit_config={"fail_fast": True, "timeout_seconds": 60})
        assert cfg.fail_fast is True
        assert cfg.timeout_seconds == 60
        assert cfg.toolkit_id == "TK-PT"

    def test_cli_overrides_toolkit_config(self) -> None:
        cfg = build_config_hierarchy(
            toolkit_config={"max_failures": 5},
            cli_overrides={"max_failures": 10},
        )
        assert cfg.max_failures == 10

    def test_unknown_keys_go_to_extra(self) -> None:
        cfg = build_config_hierarchy(toolkit_config={"custom_flag": True})
        assert cfg.extra.get("custom_flag") is True

    def test_returns_toolkit_config_contract(self) -> None:
        cfg = build_config_hierarchy()
        assert isinstance(cfg, ToolkitConfigContract)


# -- tool_specs ---------------------------------------------------------------


class TestToolkitToolSpecs:
    def test_all_five_commands_present(self) -> None:
        expected = {"run", "compare", "validate-report", "keygen", "pack"}
        assert set(TOOLKIT_TOOL_SPECS.keys()) == expected

    def test_read_only_commands_are_auto(self) -> None:
        for cmd in ("run", "compare", "validate-report"):
            s = TOOLKIT_TOOL_SPECS[cmd]
            assert s.spec.permission_scope == PermissionScope.READ_ONLY, cmd
            assert s.boundary.approval == ApprovalPolicy.AUTO, cmd

    def test_write_commands_require_approval(self) -> None:
        for cmd in ("keygen", "pack"):
            s = TOOLKIT_TOOL_SPECS[cmd]
            assert s.spec.permission_scope == PermissionScope.WORKSPACE_WRITE, cmd
            assert s.boundary.approval == ApprovalPolicy.REQUIRE_APPROVAL, cmd

    def test_boundary_scope_matches_spec_scope(self) -> None:
        for name, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.boundary.scope == cmd_spec.spec.permission_scope, name

    def test_no_sandbox_required(self) -> None:
        for name, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.spec.sandbox_requirement is None, name

    def test_run_requires_suite_and_predictions(self) -> None:
        schema = TOOLKIT_TOOL_SPECS["run"].spec.input_schema
        assert schema is not None
        required = schema.get("required", [])
        assert "suite" in required
        assert "predictions" in required

    def test_compare_requires_baseline_and_candidate(self) -> None:
        schema = TOOLKIT_TOOL_SPECS["compare"].spec.input_schema
        assert schema is not None
        required = schema.get("required", [])
        assert "baseline" in required
        assert "candidate" in required

    def test_pack_has_subcommand_enum(self) -> None:
        schema = TOOLKIT_TOOL_SPECS["pack"].spec.input_schema
        assert schema is not None
        subcommand_prop = schema.get("properties", {}).get("subcommand", {})
        assert "create" in subcommand_prop.get("enum", [])

    def test_command_name_matches_key(self) -> None:
        for key, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.command == key

    def test_owner_is_toolkit(self) -> None:
        for cmd_spec in TOOLKIT_TOOL_SPECS.values():
            assert cmd_spec.spec.owner == "toolkit-policy-test-bench"


class TestGetToolSpec:
    def test_returns_spec_for_known_command(self) -> None:
        spec = get_tool_spec("run")
        assert spec is not None
        assert spec.command == "run"

    def test_returns_none_for_unknown_command(self) -> None:
        assert get_tool_spec("nonexistent") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert get_tool_spec("") is None
