# toolkit-policy-test-bench — Codebase Map

**Last updated:** 2026-04-04
**Archetype:** 9 — Developer Tool / CLI
**Source LOC:** 1,872 | **Test LOC:** 1,571 | **Tests:** 102

## Entry Points

| Entry | Path | Purpose |
|-------|------|---------|
| CLI | `src/toolkit_policy_test_bench/cli.py:main` | Primary CLI (`toolkit-policy`) |
| Module | `src/toolkit_policy_test_bench/__main__.py` | `python -m toolkit_policy_test_bench` |
| API | `src/toolkit_policy_test_bench/__init__.py` | Programmatic API (10 exports) |

## Source Layout

```
src/toolkit_policy_test_bench/
  __init__.py          (30)   Public API exports (__all__)
  __main__.py           (7)   Module entry point
  cli.py              (448)   CLI parser + 8 subcommand handlers
  runner.py           (134)   Core suite execution engine
  detectors.py         (31)   Built-in PII/secret regex patterns
  plugins.py          (185)   Custom detector plugin system (DetectorRegistry)
  suite.py             (64)   PolicySuite + PolicyCase data models
  report.py            (28)   PolicyReport data model
  compare.py           (62)   Report comparison + CompareBudget
  io.py               (265)   Path validation + file I/O (JSON/JSONL/text/bytes)
  json_schema.py       (55)   JSON output schema validation
  pack.py             (116)   Suite packing (zip), manifest, zip-slip prevention
  signing.py           (63)   Ed25519 keygen/sign/verify (optional cryptography dep)
  hashing.py           (12)   SHA-256 file hashing
  formatting.py        (39)   JSON/table output formatting
  control_plane/
    __init__.py        (47)   Control-plane exports
    contracts.py      (129)   PermissionScope, ApprovalPolicy, AuthorityBoundary, ToolSpec
    config.py         (108)   ToolkitConfigContract (3-tier config hierarchy)
    tool_specs.py     (175)   5 ToolkitCommandSpec definitions (run/compare/validate/keygen/pack)
```

## Data Flow

```
Suite (JSON) + Predictions (JSONL)
  --> runner.run_suite()
    --> detectors.detect_pii/detect_secrets (built-in regex)
    --> plugins.registry.run_pii/run_secrets (custom detectors)
    --> json_schema.validate_json (if schema checks enabled)
  --> PolicyReport (JSON)
    --> compare.compare_reports (baseline vs candidate)
    --> Exit code for CI gating
```

## CLI Commands

| Command | Handler | Permission | Approval |
|---------|---------|------------|----------|
| `run` | `_cmd_run` | READ_ONLY | AUTO |
| `compare` | `_cmd_compare` | READ_ONLY | AUTO |
| `validate-report` | `_cmd_validate_report` | READ_ONLY | AUTO |
| `keygen` | `_cmd_keygen` | WORKSPACE_WRITE | REQUIRE_APPROVAL |
| `pack create` | `_cmd_pack_create` | WORKSPACE_WRITE | REQUIRE_APPROVAL |
| `pack inspect` | `_cmd_pack_inspect` | READ_ONLY | AUTO |
| `pack verify` | `_cmd_pack_verify` | READ_ONLY | AUTO |
| `pack sign` | `_cmd_pack_sign` | WORKSPACE_WRITE | REQUIRE_APPROVAL |
| `pack verify-signature` | `_cmd_pack_verify_sig` | READ_ONLY | AUTO |

## Test Layout

```
tests/
  conftest.py              (7)   sys.path fixture
  test_cli.py            (144)   CLI version, pack inspect, compare exit codes
  test_control_plane.py  (221)   Contracts, config hierarchy, tool specs (18 tests)
  test_detectors_and_schema.py (49)  PII/secret detection, JSON schema (5 tests)
  test_enhancements.py   (412)   IO validation, CLI edge cases (30 tests)
  test_hardening.py      (618)   Zip-slip, plugins, formatting, edge cases (32 tests)
  test_pack_load_twice.py (35)   Suite reload cleanup (1 test)
  test_pack_run_compare.py (85)  End-to-end pack->run->compare (1 test)
```

## CI Pipeline

```
ci.yml: test (3.10/3.11/3.12) + security (bandit/pip-audit) + lint (ruff) + sbom --> build
```

## Dependencies

- **Runtime:** Zero (by design)
- **Optional:** `cryptography>=43.0.0` (signing)
- **Dev:** pytest, pytest-cov, ruff, pyright, cryptography
