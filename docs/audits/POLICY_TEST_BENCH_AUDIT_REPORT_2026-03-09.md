# toolkit-policy-test-bench System Audit Report

**Date:** 2026-03-09
**Auditor:** Claude Code (Automated)
**Archetype:** 9 -- Developer Tool / CLI
**Previous Audit:** None (initial audit)

## Composite Score: 68.8/100

| # | Dimension | Weight | Score (0-10) | Weighted | Status |
|---|-----------|--------|-------------|----------|--------|
| 1 | Architecture Integrity | 8% | 8 | 6.4 | PASS |
| 2 | Authentication & Authorization | 2% | 4 | 0.8 | N/A for CLI |
| 3 | Data Isolation & RLS | 0% | 0 | 0.0 | N/A |
| 4 | API Surface Quality | 12% | 8 | 9.6 | PASS |
| 5 | Data Layer Integrity | 2% | 6 | 1.2 | -- |
| 6 | Frontend Quality | 0% | 0 | 0.0 | N/A |
| 7 | Testing & QA | 15% | 7 | 10.5 | PASS (min 7) |
| 8 | Security Posture | 10% | 8 | 8.0 | PASS (min 6) |
| 9 | Observability & Monitoring | 5% | 5 | 2.5 | -- |
| 10 | Deployment & Infrastructure | 10% | 7 | 7.0 | PASS (min 6) |
| 11 | Documentation Accuracy | 10% | 7 | 7.0 | PASS (min 6) |
| 12 | Domain Capability Depth | 8% | 8 | 6.4 | PASS (min 6) |
| 13 | AI/ML Capability | 5% | 5 | 2.5 | -- |
| 14 | Connectivity & Channel Interface | 2% | 3 | 0.6 | -- |
| 15 | Agentic UI/UX | 0% | 0 | 0.0 | N/A |
| 16 | User Experience & Interface | 0% | 0 | 0.0 | N/A |
| 17 | User Journey & Persona Alignment | 0% | 0 | 0.0 | N/A |
| 18 | Zero Trust Architecture | 2% | 4 | 0.8 | -- |
| 19 | Enterprise Security & Compliance | 5% | 6 | 3.0 | -- |
| 20 | Operational Readiness | 2% | 4 | 0.8 | -- |
| 21 | Agentic Workspace | 2% | 2 | 0.4 | -- |
| | **Total** | **100%** | | **68.8** | |

**Minimum checks:** Dim 7: 7 (PASS), Dim 4: 8 (PASS), Dim 8: 8 (PASS), Dim 10: 7 (PASS), Dim 11: 7 (PASS), Dim 12: 8 (PASS). Composite 68.8 >= 60 (PASS).

**All archetype minimums met. Composite passes threshold.**

---

## Dimension 1: Architecture Integrity (Score: 8)

**Weight: 8%**

### Findings
- Well-structured package: `toolkit_policy_test_bench` with 11 modules across clear concerns
- Total source: ~1,247 LOC -- the most substantial of the 4 toolkits
- Clean separation: detectors, runner, suite, pack, compare, report, io, json_schema, signing, hashing, cli
- `__init__.py` exports full public API with `__all__`
- Proper src layout, setuptools config, entry point `toolkit-policy`
- No circular dependencies
- Uses `importlib.metadata` for dynamic version resolution

### Gaps
- `pack.py` line 69 has inline `import hashlib` inside function (lazy import, minor style issue)
- `_rm_tree` in `pack.py` is a custom implementation -- could use `shutil.rmtree`

---

## Dimension 2: Authentication & Authorization (Score: 4)

**Weight: 2%**

### Findings
- Ed25519 keypair generation and signing via `cryptography` library
- Suite pack signing and verification workflow (sign -> verify-signature)
- Pack integrity verification via SHA-256 manifest

### Gaps
- No key rotation support
- No key management guidance
- Private key file permissions not restricted

---

## Dimension 3: Data Isolation & RLS (Score: 0)

**Weight: 0% -- N/A**

---

## Dimension 4: API Surface Quality (Score: 8)

**Weight: 12%**

### Findings
- Rich CLI with 7 subcommands: `keygen`, `pack create`, `pack verify`, `pack sign`, `pack verify-signature`, `run`, `compare`, `validate-report`
- `--version` flag present
- Consistent exit codes (0, 2, 3, 4)
- Nested subcommand structure (`pack` with sub-subcommands)
- Full programmatic API exported: `PolicySuite`, `PolicyCase`, `PolicyReport`, `CompareBudget`, `run_suite`, `compare_reports`, `create_pack`, `load_suite_from_path`
- JSON I/O throughout
- JSONL format for cases and predictions
- `CompareBudget` dataclass for CI gating with configurable thresholds

### Gaps
- No machine-readable error output (errors go to logger, exit codes only)
- No streaming mode for large prediction files

---

## Dimension 5: Data Layer Integrity (Score: 6)

**Weight: 2%**

### Findings
- Comprehensive IO module with validation: `read_json`, `write_json`, `read_jsonl`, `read_text`, `write_text`, `read_bytes`
- Path validation for reads and writes
- JSONL parsing with line-number error reporting
- SHA-256 file hashing for pack integrity

### Gaps
- `load_suite_from_path` extracts zip to temp dir without cleanup on failure
- `extractall` used without path validation (potential zip slip, though low risk for local CLI)

---

## Dimension 6: Frontend Quality (Score: 0)

**Weight: 0% -- N/A**

---

## Dimension 7: Testing & QA (Score: 7)

**Weight: 15%**

### Findings
- 5 test files totaling ~696 LOC:
  - `test_cli.py` (145 lines) -- CLI integration tests
  - `test_detectors_and_schema.py` (50 lines) -- PII/secret detector unit tests
  - `test_enhancements.py` (372 lines) -- enhancement coverage
  - `test_pack_load_twice.py` (36 lines) -- pack idempotency test
  - `test_pack_run_compare.py` (86 lines) -- end-to-end workflow test
- Coverage threshold: `fail_under = 60`
- CI matrix: Python 3.10, 3.11, 3.12
- Ruff linting
- Test-to-source ratio ~0.56:1

### Gaps
- Coverage threshold (60%) is low for a security-focused tool
- No fuzzing of PII/secret detectors
- No performance benchmarks for large prediction files

---

## Dimension 8: Security Posture (Score: 8)

**Weight: 10%**

### Findings
- PII detection: email, phone, SSN, credit card patterns via regex
- Secret detection: AWS access keys, JWTs, OpenAI-like keys, Slack tokens
- Ed25519 signing for pack integrity
- No hardcoded secrets, no eval/exec/shell=True
- CI includes bandit + safety scanning
- SECURITY.md present
- Designed explicitly for security/compliance testing of LLM outputs

### Gaps
- No Dependabot configuration
- Regex-based detection has known false positive/negative rates -- no accuracy documentation
- `extractall` without zip member path validation
- Credit card regex is overly broad (`\b(?:\d[ -]*?){13,19}\b`)

---

## Dimension 9: Observability & Monitoring (Score: 5)

**Weight: 5%**

### Findings
- Consistent logging throughout all modules
- `--verbose` flag for DEBUG level
- Logs to stderr

### Gaps
- No structured logging
- No metrics collection
- No timing/performance tracking

---

## Dimension 10: Deployment & Infrastructure (Score: 7)

**Weight: 10%**

### Findings
- Dockerfile with python:3.11-slim
- docker-compose.yml with volume mounts for policies/results
- CI: test -> security -> lint -> build
- Codecov integration with `fail_ci_if_error: false`
- Package build with twine check

### Gaps
- No PyPI publishing
- No Docker registry publishing
- Deprecated docker-compose version key

---

## Dimension 11: Documentation Accuracy (Score: 7)

**Weight: 10%**

### Findings
- README.md (80 lines): concepts, quickstart, all CLI commands, exit codes documented
- Clear data format documentation (Suite, Case, Predictions, Report concepts)
- All CLI subcommands listed with examples
- QUICKSTART.md, CONTRIBUTING.md, DEPLOYMENT.md, SECURITY.md present
- Docstrings on IO functions
- `__all__` exports documented

### Gaps
- No API documentation for programmatic use
- No changelog
- No architecture decision records
- Suite JSON schema not formally documented (only by example)

---

## Dimension 12: Domain Capability Depth (Score: 8)

**Weight: 8%**

### Findings
- **PII detection**: 4 categories (email, phone, SSN, credit card)
- **Secret detection**: 4 patterns (AWS, JWT, OpenAI, Slack)
- **Policy constraints**: must_contain, must_not_contain, regex_must_match, regex_must_not_match, max_output_chars
- **JSON schema validation**: required keys, optional keys, extra key control
- **Suite packaging**: zip-based packs with manifest and integrity hashing
- **Report comparison**: CI gating with configurable budgets (fail rate, PII hits, secret hits)
- **Case tagging**: categorize test cases
- **Case-insensitive matching**: configurable
- **Signing workflow**: keygen -> sign -> verify for supply chain integrity

### Gaps
- No custom detector plugin system
- No HIPAA-specific patterns (medical record numbers, etc.)
- No severity levels for detections
- No remediation suggestions
- No batch/parallel processing

---

## Dimension 13: AI/ML Capability (Score: 5)

**Weight: 5%**

### Findings
- Designed to test LLM outputs for policy compliance
- Framework-agnostic (works with any text predictions)

### Gaps
- No LLM integration for dynamic testing
- No prompt injection detection
- No hallucination detection
- No toxicity scoring

---

## Dimension 14: Connectivity & Channel Interface (Score: 3)

**Weight: 2%**

### Findings
- CLI interface
- JSON/JSONL file I/O
- Programmatic Python API via imports

### Gaps
- No REST API
- No webhook integration
- No CI/CD plugin (GitHub Action, GitLab CI template)

---

## Dimensions 15-17: UI/UX (Score: 0)

**Weight: 0% each -- N/A**

---

## Dimension 18: Zero Trust Architecture (Score: 4)

**Weight: 2%**

### Findings
- Input path validation
- JSON parsing with error handling
- No network calls

### Gaps
- Zip extraction without path validation (zip slip risk)
- No resource limits on prediction file size
- Regex patterns could be vulnerable to ReDoS on crafted input

---

## Dimension 19: Enterprise Security & Compliance (Score: 6)

**Weight: 5%**

### Findings
- Ed25519 signing for tamper-evident packs
- PII/secret detection as core functionality
- CI security scanning
- MIT license

### Gaps
- No audit trail / logging of compliance runs
- No SOC 2 mapping
- No data retention policies

---

## Dimension 20: Operational Readiness (Score: 4)

**Weight: 2%**

### Findings
- Docker deployment option
- CI pipeline functional

### Gaps
- No production deployment evidence
- No runbook
- No monitoring

---

## Dimension 21: Agentic Workspace (Score: 2)

**Weight: 2%**

### Findings
- Standalone CLI tool

### Gaps
- No agent/MCP integration -- expected for archetype

---

## Sprint Tasks (Gap Closure)

### Sprint 0 (P0 -- Security Hardening)
1. Add Dependabot configuration
2. Fix zip extraction to validate member paths (zip slip prevention)
3. Raise coverage threshold from 60% to 70%
4. Add ReDoS-safe timeout on regex matching

### Sprint 1 (Depth)
5. Add custom detector plugin system (load Python modules or YAML patterns)
6. Add severity levels (low/medium/high/critical) to detections
7. Add HIPAA PII patterns (MRN, DEA numbers)
8. Add GitHub Action workflow template for easy CI integration
9. Add formal JSON schema for suite.json format
10. Add structured JSON logging option

### Sprint 2 (Enterprise)
11. Add audit trail logging (who ran what suite, when, results)
12. Add batch processing for multiple prediction files
13. Add performance benchmarks in CI
14. Update docker-compose to remove deprecated version key
15. Add PyPI publish step to CI
