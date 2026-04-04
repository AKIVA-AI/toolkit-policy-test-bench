"""
Config hierarchy contract for toolkit-policy-test-bench.

Three-tier hierarchy (mirrors Akiva platform pattern):
  Level 0 -- Platform defaults (global Akiva CLI conventions)
  Level 1 -- Toolkit config (pyproject.toml / config file)
  Level 2 -- CLI overrides (argv flags)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolkitConfigContract:
    """
    Resolved configuration contract for toolkit-policy-test-bench.

    All fields represent resolved values after applying the three-tier
    hierarchy (platform defaults -> toolkit config -> CLI overrides).
    """

    # -- Identity --------------------------------------------------------------
    toolkit_id: str = "TK-PT"
    toolkit_name: str = "toolkit-policy-test-bench"
    version: str = "0.1.0"

    # -- Runtime behaviour -----------------------------------------------------
    log_format: str = "json"  # 'json' | 'text'
    structured_logging: bool = True
    output_format: str = "json"  # 'json' | 'text'

    # -- Policy test bench defaults --------------------------------------------
    fail_fast: bool = False
    max_failures: int = 0  # 0 = unlimited
    timeout_seconds: int = 300

    # -- Extension -------------------------------------------------------------
    extra: dict[str, Any] = field(default_factory=dict)


# Config hierarchy levels -- mirrors the TypeScript CONFIG_HIERARCHY_LEVELS pattern
# used in HubZone and Website adapters.
CONFIG_LEVELS = {
    "platform_default": 0,
    "toolkit_config": 1,
    "cli_override": 2,
}


def build_config_hierarchy(
    toolkit_config: dict[str, Any] | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> ToolkitConfigContract:
    """
    Merge config tiers into a resolved ToolkitConfigContract.

    Priority: CLI overrides > toolkit config > platform defaults.

    Parameters
    ----------
    toolkit_config:
        Values loaded from pyproject.toml [tool.toolkit-policy-test-bench]
        or equivalent config file.
    cli_overrides:
        Values parsed from CLI argv.

    Returns
    -------
    ToolkitConfigContract
        Fully resolved configuration contract.
    """
    # Start with platform defaults
    resolved: dict[str, Any] = {
        "toolkit_id": "TK-PT",
        "toolkit_name": "toolkit-policy-test-bench",
        "version": "0.1.0",
        "log_format": "json",
        "structured_logging": True,
        "output_format": "json",
        "fail_fast": False,
        "max_failures": 0,
        "timeout_seconds": 300,
        "extra": {},
    }

    # Layer 1: toolkit config
    if toolkit_config:
        for k, v in toolkit_config.items():
            if k in resolved:
                resolved[k] = v
            else:
                resolved["extra"][k] = v

    # Layer 2: CLI overrides (highest priority)
    if cli_overrides:
        for k, v in cli_overrides.items():
            if k in resolved:
                resolved[k] = v
            else:
                resolved["extra"][k] = v

    return ToolkitConfigContract(**{k: v for k, v in resolved.items()})


__all__ = ["ToolkitConfigContract", "CONFIG_LEVELS", "build_config_hierarchy"]
