from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .compare import CompareBudget, compare_reports
from .pack import create_pack, load_suite_from_path
from .plugins import DetectorPlugin, DetectorRegistry, registry
from .report import PolicyReport
from .runner import run_suite
from .suite import PolicyCase, PolicySuite

try:
    __version__ = version("toolkit-policy-test-bench")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

__all__ = [
    "CompareBudget",
    "DetectorPlugin",
    "DetectorRegistry",
    "PolicyCase",
    "PolicyReport",
    "PolicySuite",
    "__version__",
    "compare_reports",
    "create_pack",
    "load_suite_from_path",
    "registry",
    "run_suite",
]

