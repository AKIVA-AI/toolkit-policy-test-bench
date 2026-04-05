# toolkit-policy-test-bench — Full System Audit

**Date:** 2026-04-04
**Auditor:** Claude Code (Automated)
**Standards Baseline:** Akiva Build Standard v2.14, Archetypes v2.0
**Archetype:** 9 — Developer Tool / CLI
**Previous Audit:** 2026-03-09 (68.8 reported, 67.5 recalculated)
**System:** `toolkit-policy-test-bench/` — PII/secret leakage and policy regression tests for LLM outputs

## Standards Evaluated

| Standard | Version | Applicability |
|----------|---------|---------------|
| Build Standard | v2.14 | Full |
| System Archetypes | v2.0 | Archetype 9 |
| Sprint Execution Protocol | v3.4 | SA-1 through SA-13 |
| Repository Controls | v1.3 | Full |
| Operational Standard | v1.4 | Partial (CLI tool) |
| Pre-Push Standard | v1.2 | Full |
| AI Agent Runtime Standard | v1.8 | Conditional — control-plane contracts |
| AI Service Standard | v1.5 | Not applicable (no AI/LLM usage) |
| AI Resilience Standard | v1.3 | Not applicable (no AI surfaces) |
| AI Governance & Ethics Standard | v1.1 | Conditional — tool validates AI outputs |
| BENCHMARK Standard | v1.5 | Conditional — no self-healing implemented |
| Integration & Webhook Standard | v1.1 | Not applicable (no integrations) |
| Data Isolation Standard | v1.1 | Not applicable (0% weight, no multi-tenancy) |
| User Trust Standard | v1.4 | Minimal — CLI trust signals |
| Compliance Framework Standard | v1.0 | SBOM/SLSA required for Arch 9 |

## Verified Current State

| Metric | Value | Evidence |
|--------|-------|----------|
| Tests | 102 passing | `pytest --cov` run 2026-04-04 |
| Coverage | 85.01% branch | `--cov-fail-under=70` enforced |
| Lint | All checks passed | `ruff check src/ tests/` |
| Type-check | 14 errors (optional dep) | pyright — all in `signing.py` cryptography imports |
| Source LOC | 1,872 | 19 Python files (15 root + 4 control_plane) |
| Test LOC | 1,571 | 8 test files, 0.84:1 test-to-source ratio |
| CI status | Last run: SUCCESS | `eda1cb4` on main, 2026-04-04 |
| Git tags | None | No releases published |
| Branch protection | None | GitHub API confirms unprotected |
| Python versions | 3.10, 3.11, 3.12 | CI matrix |

---

## Composite Score: 69.4/100

| # | Dimension | Weight | Score | Weighted | Prev | Delta | Status |
|---|-----------|--------|-------|----------|------|-------|--------|
| 1 | Architecture & Design | 8% | 8 | 6.4 | 8 | = | PASS (min 6) |
| 2 | Auth & Identity | 2% | 4 | 0.8 | 4 | = | — |
| 3 | RLS / Data Isolation | 0% | 0 | 0.0 | 0 | = | N/A |
| 4 | API Surface Quality | 12% | 8 | 9.6 | 8 | = | PASS (min 7) |
| 5 | Data Layer & Durability | 2% | 6 | 1.2 | 6 | = | — |
| 6 | Frontend Quality | 0% | 0 | 0.0 | 0 | = | N/A |
| 7 | Testing & QA | 15% | **8** | **12.0** | 7 | **+1** | PASS (min 7) |
| 8 | Security Posture | 10% | 8 | 8.0 | 8 | = | PASS (min 6) |
| 9 | Observability & Monitoring | 5% | **6** | **3.0** | 5 | **+1** | — |
| 10 | CI/CD Maturity | 10% | 7 | 7.0 | 7 | = | PASS (min 6) |
| 11 | Documentation & Knowledge | 10% | 7 | 7.0 | 7 | = | PASS (min 6) |
| 12 | Domain Capability | 8% | 8 | 6.4 | 8 | = | PASS (min 6) |
| 13 | AI/ML Capability | 5% | 5 | 2.5 | 5 | = | — |
| 14 | Connectivity & Integrations | 2% | 3 | 0.6 | 3 | = | — |
| 15 | Agentic UI/UX | 0% | 0 | 0.0 | 0 | = | N/A |
| 16 | UX Quality & Accessibility | 0% | 0 | 0.0 | 0 | = | N/A |
| 17 | User Journey & Personas | 0% | 0 | 0.0 | 0 | = | N/A |
| 18 | Zero Trust Architecture | 2% | 4 | 0.8 | 4 | = | — |
| 19 | Enterprise Security & Compliance | 5% | **5** | **2.5** | 6 | **-1** | — |
| 20 | Operational Readiness | 2% | 4 | 0.8 | 4 | = | — |
| 21 | Agentic Workspace | 2% | **4** | **0.8** | 2 | **+2** | — |
| | **Total** | **100%** | | **69.4** | 67.5* | **+1.9** | **PASS** |

*Previous audit reported 68.8 but weighted sum recalculates to 67.5 with the stated weights and scores.

### Minimum Threshold Checks

| Dimension | Required | Actual | Status |
|-----------|----------|--------|--------|
| Dim 1 (Architecture) | >= 6 | 8 | PASS |
| Dim 4 (API Surface) | >= 7 | 8 | PASS |
| Dim 7 (Testing) | >= 7 | 8 | PASS |
| Dim 8 (Security) | >= 6 | 8 | PASS |
| Dim 10 (CI/CD) | >= 6 | 7 | PASS |
| Dim 11 (Documentation) | >= 6 | 7 | PASS |
| Dim 12 (Domain Capability) | >= 6 | 8 | PASS |
| Composite | >= 60 | 69.4 | PASS |

**All archetype minimums met. System is production-viable.**

---

## Dimension Details

### Dimension 1: Architecture & Design — 8/10

**Weight: 8% | Standard: Build Standard v2.14 § Architecture | Minimum: 6**

**Evidence:**
- 19-module package with clean separation: detectors, runner, suite, pack, compare, report, io, json_schema, signing, hashing, cli, formatting, plugins, control_plane (4 modules)
- 1,872 source LOC — substantial for a single-purpose CLI
- `__init__.py` exports full public API with `__all__` (10 symbols)
- Proper `src/` layout, setuptools config, entry point `toolkit-policy`
- No circular dependencies
- `importlib.metadata` for dynamic version resolution
- Control-plane adapter with optional framework import pattern (`try/except ImportError` + `_HAS_*` flags) — matches cross-repo Python import standard
- State durability: T0 (ephemeral) — appropriate for Arch 9

**Gaps:**
- `pack.py:69` has inline `import hashlib` (lazy import, minor style)
- `_rm_tree` in `pack.py` is a custom implementation (could use `shutil.rmtree`)

**Standards Cited:** Build Standard v2.14 § Architecture, Archetypes v2.0 § Arch 9

---

### Dimension 2: Auth & Identity — 4/10

**Weight: 2% | Standard: Build Standard v2.14 § Auth | No minimum for Arch 9**

**Evidence:**
- Ed25519 keypair generation and signing via `cryptography` library
- Suite pack signing and verification workflow (`keygen` -> `pack sign` -> `pack verify-signature`)
- Pack integrity verification via SHA-256 manifest (`pack verify`)

**Gaps:**
- No key rotation support or guidance
- No key management best-practices documentation
- Private key file permissions not restricted (no `os.chmod` after generation)
- No certificate chain or trust hierarchy

**Standards Cited:** Auth & Identity (not required for Arch 9 CLI)

---

### Dimension 3: RLS / Data Isolation — 0/10

**Weight: 0% — N/A for Arch 9**

---

### Dimension 4: API Surface Quality — 8/10

**Weight: 12% | Standard: Build Standard v2.14 § API Design, AI Agent Runtime v1.8 § Tool Registration | Minimum: 7**

**Evidence:**
- 8 CLI subcommands: `keygen`, `pack create`, `pack inspect`, `pack verify`, `pack sign`, `pack verify-signature`, `run`, `compare`, `validate-report`
- `--version`, `--verbose`, `--log-format {text,json}` global flags
- Consistent exit codes: 0 (success), 2 (CLI error), 3 (unexpected), 4 (validation failed)
- Nested subcommand structure (`pack` with 5 sub-subcommands)
- Full programmatic API exported: `PolicySuite`, `PolicyCase`, `PolicyReport`, `CompareBudget`, `run_suite`, `compare_reports`, `create_pack`, `load_suite_from_path`, `registry`, `DetectorPlugin`, `DetectorRegistry`
- JSON/JSONL I/O throughout
- `CompareBudget` dataclass for CI gating with configurable thresholds
- Control-plane `ToolSpec` definitions for 5 commands with input/output schemas (Agent Runtime v1.8 § Tool Registration)

**Gaps:**
- No machine-readable error output (errors via logger only, not structured JSON on stderr)
- No streaming mode for large prediction files

**Standards Cited:** Build Standard v2.14 § API Design, AI Agent Runtime v1.8 §2 Tool Registration, Archetypes v2.0 § Arch 9 ("CLI interface IS the product")

---

### Dimension 5: Data Layer & Durability — 6/10

**Weight: 2% | Standard: Build Standard v2.14 § Data Layer | No minimum for Arch 9**

**Evidence:**
- File-based I/O with comprehensive validation (`io.py`: 265 LOC)
- Functions: `read_json`, `write_json`, `read_jsonl`, `read_text`, `write_text`, `read_bytes`
- Path validators: `validate_path_for_read`, `validate_path_for_write`, `validate_dir_for_read`
- SHA-256 hashing for pack manifest (`hashing.py`)
- Zip-slip prevention in `_safe_extract` (`pack.py`)
- State durability T0-T1 — appropriate for Arch 9 per Build Standard

**Gaps:**
- No file locking for concurrent access
- No atomic write (write then rename) pattern

**Standards Cited:** Build Standard v2.14 § State Durability Tiers (T0 acceptable for Arch 9)

---

### Dimension 6: Frontend Quality — 0/10

**Weight: 0% — N/A for Arch 9 CLI**

---

### Dimension 7: Testing & QA — 8/10 (was 7)

**Weight: 15% | Standard: Build Standard v2.14 § Testing, Repository Controls v1.3 § CI Matrix | Minimum: 7**

**Evidence:**
- **102 tests passing** (up from previous audit)
- **85.01% branch coverage** (threshold enforced at 70% in CI)
- Python 3.10/3.11/3.12 matrix in CI (Repository Controls v1.3 § Matrix Testing)
- Test categories: unit (detectors, schema, IO, config), integration (CLI, pack, suite), E2E (`test_pack_run_compare.py`), security (zip-slip — 3 tests), edge cases (malformed JSON, empty suites, concurrent detection)
- 1,571 test LOC vs 1,872 source LOC (0.84:1 ratio)
- Coverage enforced in CI (`--cov-fail-under=70`)
- Codecov integration (non-blocking on upload failure)
- 18 control-plane tests (`test_control_plane.py`: contracts, config hierarchy, tool specs)

**Gaps:**
- `control_plane/contracts.py` at 25% coverage — the fallback class definitions (lines 30-110) are tested only via the inline implementations, not via the `akiva_execution_contracts` import path (expected — framework not installed in CI)
- No fuzzing or property-based testing (relevant for regex-based security tool)
- No performance benchmarks
- No mutation testing

**Why +1:** Coverage jumped from ~70% to 85%, test count grew to 102, and control-plane tests were added. Meets all Repository Controls matrix testing requirements.

**Standards Cited:** Build Standard v2.14 § Testing, Repository Controls v1.3 § CI Matrix, Sprint Protocol v3.4 SA-2

---

### Dimension 8: Security Posture — 8/10

**Weight: 10% | Standard: Build Standard v2.14 § Security, Repository Controls v1.3 § SAST, Sprint Protocol v3.4 SA-4 | Minimum: 6**

**Evidence:**
- PII detection IS the core function: email, phone, SSN, credit card patterns
- Secret detection: AWS access keys, JWTs, OpenAI-like keys, Slack tokens
- `bandit -r src/` in CI (blocking) — AST-based SAST
- `safety check` in CI (blocking) — dependency vulnerability scanning
- Ed25519 signing for pack integrity
- SHA-256 manifest verification
- Zip-slip prevention with path traversal check (`_safe_extract`) — 3 dedicated tests
- No `eval()` / `exec()` / `shell=True` anywhere in codebase
- No hardcoded secrets
- Path validation on all file I/O operations
- Dependabot configured (weekly, pip + GitHub Actions)
- Zero core runtime dependencies (attack surface minimized)
- Custom detector plugin system validates `kind` field (rejects invalid detector types)

**Gaps:**
- No ReDoS timeout protection on regex patterns — crafted input could slow detectors. Relevant because this IS a regex-based security tool processing untrusted LLM output.
- No resource limits on prediction file size (potential DoS on large files)
- Private key file permissions not enforced after `keygen`
- `safety` is deprecated/limited vs. `pip-audit` for vulnerability scanning
- Pyright reports 14 errors in `signing.py` — all from optional `cryptography` imports. Acceptable pattern for optional deps but not clean.

**Why no change:** Same code-level security posture. ReDoS and resource limits were noted in previous audit; no new regressions. SBOM gap impacts Dim 19 (enterprise compliance), not Dim 8 (code security).

**Standards Cited:** Build Standard v2.14 § Security, Repository Controls v1.3 §6 SAST, Sprint Protocol v3.4 SA-4, Archetypes v2.0 § Arch 9 ("No vulnerabilities in tools users install into pipelines")

---

### Dimension 9: Observability & Monitoring — 6/10 (was 5)

**Weight: 5% | Standard: Build Standard v2.14 § Observability, AI Agent Runtime v1.8 §7 | No minimum for Arch 9**

**Evidence:**
- Structured JSON logging (`--log-format json`) — new since last audit
- `JsonFormatter` class in `cli.py` for machine-parseable log output
- `--verbose` flag for debug-level logging
- Per-run `PolicyReport` with detailed per-case results, summary stats
- Exit codes for CI integration (4 distinct codes)
- Report comparison output (deltas for fail_rate, pii_hits, secret_hits)

**Gaps:**
- No unique run ID per execution (Agent Runtime v1.8 §7 requires "Run ID per execution")
- No cost/token tracking (not applicable — tool doesn't call LLMs)
- No metrics or tracing infrastructure
- No performance baselines documented (`docs/PERFORMANCE_BASELINES.md` missing per Operational Standard v1.4)

**Why +1:** Structured JSON logging was added, enabling CI pipeline integration and log aggregation. Meets basic observability for Arch 9.

**Standards Cited:** Build Standard v2.14 § Observability, AI Agent Runtime v1.8 §7, Operational Standard v1.4

---

### Dimension 10: CI/CD Maturity — 7/10

**Weight: 10% | Standard: Build Standard v2.14 § CI/CD, Repository Controls v1.3 | Minimum: 6**

**Evidence:**
- 4-job pipeline: `test` -> `security` -> `lint` -> `build` (with `needs` dependency)
- Python 3.10/3.11/3.12 matrix (Repository Controls v1.3)
- Coverage enforced (`--cov-fail-under=70`)
- Codecov upload (Python 3.11, non-blocking)
- Dependabot for pip + GitHub Actions (weekly cadence)
- Pre-commit hooks: ruff (check + format) + pyright
- Package build (`python -m build`) + metadata validation (`twine check dist/*`)
- Last CI run: SUCCESS (`eda1cb4`, 2026-04-04)

**Gaps:**
- **No branch protection on `main`** — GitHub API confirms "Branch not protected". Repository Controls v1.3 requires "Branch protection on main (no force-push, require status checks)". Score impact: -1 per standard.
- **No release automation** — no git tags, no PyPI publishing step. Archetypes v2.0 requires "Automated release pipeline" and "PyPI/npm package published with version tags" for Arch 9.
- No path-filtered workflows (CI runs on all pushes regardless of changed files)
- No aggregator job (single gate for N workflows)
- `docker-compose.yml` uses deprecated `version: "3.8"` key

**Why no change:** Build pipeline is solid and passes, but branch protection and release automation are missing — same gaps as previous audit.

**Standards Cited:** Build Standard v2.14 § CI/CD, Repository Controls v1.3 §3-4, Archetypes v2.0 § Arch 9 Required Capabilities

---

### Dimension 11: Documentation & Knowledge — 7/10

**Weight: 10% | Standard: Build Standard v2.14 § Documentation, Repository Controls v1.3 § Templates | Minimum: 6**

**Evidence:**
- `README.md` (232 lines): concepts, quickstart, full CLI reference, custom plugin example, CI integration, exit codes, license
- `CONTRIBUTING.md`: dev setup, quality gates (ruff, pyright, pytest)
- `SECURITY.md`: supported versions, reporting process, sandboxing guidance
- `DEPLOYMENT.md`: Docker quick start, local install, configuration, production CI/CD
- `QUICKSTART.md`: installation, basic usage examples
- `CHANGELOG.md`: v0.1.0 and v0.2.0 with Added/Changed/Security sections
- `CLAUDE.md`: Akiva alignment metadata
- `LICENSE`: MIT
- Previous audit report in `docs/audits/`

**Gaps:**
- **No `docs/CODEBASE_MAP.md`** — mandatory per Build Standard v2.14 Phase 0.5. Required before any audit/sprint work.
- **No issue templates** (`.github/ISSUE_TEMPLATE/bug_report.md`, `feature_request.md`) — Repository Controls v1.3
- **No PR template** (`.github/PULL_REQUEST_TEMPLATE.md`) — Repository Controls v1.3
- No auto-generated API docs — Repository Controls v1.3 says "Docs hand-maintained: Dim 11 capped at 7"
- No architecture decision records (ADRs)
- Suite JSON schema not formally documented (only by example in README)

**Why capped at 7:** Repository Controls v1.3 explicitly caps Dim 11 at 7 for hand-maintained docs without auto-generation.

**Standards Cited:** Build Standard v2.14 § Documentation, Repository Controls v1.3 §1-2 (templates), Build Standard Phase 0.5 (CODEBASE_MAP)

---

### Dimension 12: Domain Capability — 8/10

**Weight: 8% | Standard: Build Standard v2.14 § Domain Capability | Minimum: 6**

**Evidence:**
- 4 PII detection patterns: email, phone, SSN, credit card
- 4 secret detection patterns: AWS access key, JWT, OpenAI-like key, Slack token
- 9 policy constraint types: `must_contain`, `must_not_contain`, `regex_must_match`, `regex_must_not_match`, `max_output_chars`, `case_insensitive`, `pii`, `secrets`, `json_schema`
- JSON schema validation for LLM outputs (`json_schema.py`)
- Suite packing with SHA-256 manifest + Ed25519 signing
- Report comparison for CI gating (`CompareBudget` with configurable thresholds)
- Custom detector plugin system (`DetectorPlugin`, `DetectorRegistry`, JSON pattern files)
- Case tagging for selective test runs
- Control-plane `ToolSpec` definitions (5 commands with input schemas, permission scopes, approval policies)

**Gaps:**
- No HIPAA-specific PII patterns (medical record numbers, health plan IDs)
- No severity levels for detections (all hits treated equally)
- No batch/parallel processing for large test suites
- No remediation suggestions (detection only, no fix guidance)
- No detection confidence scores

**Standards Cited:** Build Standard v2.14 § Domain Capability, AI Governance & Ethics v1.1 (tool validates AI outputs), Archetypes v2.0 § Arch 9 ("Domain logic IS the tool")

---

### Dimension 13: AI/ML Capability — 5/10

**Weight: 5% | Standard: AI Service Standard v1.5, AI Governance & Ethics v1.1, BENCHMARK v1.5 | No minimum for Arch 9**

**Evidence:**
- Tool tests LLM outputs but does **not use AI itself** — all detection is regex-based
- AI Service Standard v1.5 not applicable (no LLM calls, no prompt architecture, no model selection)
- AI Resilience Standard v1.3 not applicable (no AI surfaces to degrade)
- Control-plane contracts define `ToolSpec` for agent runtime integration (Agent Runtime v1.8)
- Tool serves as a governance artifact for AI systems (AI Governance & Ethics v1.1 § tool evaluates AI outputs)

**Gaps:**
- No eval sets for the tool itself (the tool IS an eval tool, but doesn't self-evaluate)
- No BENCHMARK Engineering integration (no self-healing, no dependency monitoring beyond Dependabot)
- No model card or evaluation methodology documentation (AI Governance & Ethics v1.1 conditional requirement)
- No ML-based detection (could improve accuracy over regex-only)

**Standards Cited:** AI Service v1.5 (N/A), AI Resilience v1.3 (N/A), AI Governance & Ethics v1.1 (conditional), BENCHMARK v1.5 (conditional), Agent Runtime v1.8 §2

---

### Dimension 14: Connectivity & Integrations — 3/10

**Weight: 2% | Standard: Integration & Webhook Standard v1.1 | No minimum for Arch 9**

**Evidence:**
- File-based I/O only — no network calls, no API endpoints, no webhooks
- CI integration via exit codes and JSON output (indirect)
- Docker support for containerized execution

**Gaps:**
- No MCP server (Integration Standard v1.1 §1 — optional for Arch 9)
- No external service integration
- No API mode (HTTP server)
- No webhook support

**Standards Cited:** Integration & Webhook Standard v1.1 (optional for Arch 9)

---

### Dimensions 15-17: Agentic UI/UX, UX Quality, User Journey — 0/10

**Weight: 0% — N/A for Arch 9 CLI**

---

### Dimension 18: Zero Trust Architecture — 4/10

**Weight: 2% | Standard: Build Standard v2.14 § Zero Trust | No minimum for Arch 9**

**Evidence:**
- Pack signing (Ed25519) establishes artifact trust
- SHA-256 manifest verification for tamper detection
- Zip-slip prevention validates extraction paths
- Path validation on all file operations
- Control-plane `AuthorityBoundary` with `PermissionScope` and `ApprovalPolicy`

**Gaps:**
- No key rotation
- No trust chain (no CA, no chain-of-custody)
- No signed releases (git tags + GPG/SSH signatures)
- No runtime integrity checking

**Standards Cited:** Build Standard v2.14 § Zero Trust, User Trust Standard v1.4 T-6 (provenance)

---

### Dimension 19: Enterprise Security & Compliance — 5/10 (was 6)

**Weight: 5% | Standard: Compliance Framework Standard v1.0, Repository Controls v1.3 §8-10 | No minimum for Arch 9**

**Evidence:**
- MIT license (OSI-approved)
- `bandit` + `safety` in CI (blocking)
- Dependabot configured (weekly)
- `SECURITY.md` with reporting process
- Ed25519 signing capability

**Gaps:**
- **No SBOM generation** — Compliance Framework Standard v1.0 and Repository Controls v1.3 §8-10 require CycloneDX SBOM for Arch 9 ("SBOM / SLSA Level 2: REQUIRED — Tools installed into CI pipelines must have supply chain transparency"). Not present in CI or build pipeline.
- **No SLSA attestation** — no provenance attestation, no build system integrity verification
- No signed releases (git tags with GPG/SSH signatures)
- No `pip-audit` (uses `safety` which has licensing/coverage limitations)
- No compliance mapping documented
- No license audit of dependencies (though zero runtime deps mitigates this)

**Why -1:** Compliance Framework Standard v1.0 (published 2026-03-27, after previous audit on 2026-03-09) newly requires SBOM/SLSA Level 2 for Arch 9. This standard was not in effect during the previous audit. The requirement is now unmet.

**Standards Cited:** Compliance Framework Standard v1.0 § SBOM, Repository Controls v1.3 §8-10, Archetypes v2.0 § Arch 9 Certification Requirements

---

### Dimension 20: Operational Readiness — 4/10

**Weight: 2% | Standard: Operational Standard v1.4 | No minimum for Arch 9**

**Evidence:**
- Dockerfile present (`python:3.11-slim`)
- `docker-compose.yml` with volume mounts
- `DEPLOYMENT.md` with install instructions
- CLI `--help` works as smoke test

**Gaps:**
- No release tags (no versions published)
- No PyPI publishing
- No health endpoint (expected for CLI)
- No performance baselines (`docs/PERFORMANCE_BASELINES.md`)
- No incident response process (early-stage)
- `docker-compose.yml` uses deprecated `version: "3.8"` key

**Standards Cited:** Operational Standard v1.4 § CLI Tools, Archetypes v2.0 § Arch 9

---

### Dimension 21: Agentic Workspace — 4/10 (was 2)

**Weight: 2% | Standard: Build Standard v2.14 § Agentic Workspace, AI Agent Runtime v1.8 | No minimum for Arch 9**

**Evidence:**
- Control-plane adapter (`src/toolkit_policy_test_bench/control_plane/`) — 459 LOC across 4 modules
- `PermissionScope` enum: `READ_ONLY`, `WORKSPACE_WRITE`, `FULL_ACCESS`
- `ApprovalPolicy` enum: `AUTO`, `REQUIRE_APPROVAL`, `DENY`
- `AuthorityBoundary` class with `scope_allows()`, `is_denied()`, `needs_approval()`
- `ToolSpec` class with full metadata: name, description, category, version, owner, permission_scope, input/output schema, sandbox_requirement, aliases
- `ToolkitConfigContract` with three-tier config hierarchy: platform defaults -> toolkit config -> CLI overrides
- 5 `ToolkitCommandSpec` definitions mapping CLI commands to ToolSpecs
- Optional import from `akiva_execution_contracts` with inline fallback — matches cross-repo import standard
- 18 dedicated control-plane tests

**Gaps:**
- No actual agent orchestration or execution
- No dynamic tool creation/modification
- No registry queries (read-only definitions)
- `PolicyRuntime` imported but never used (placeholder)
- `contracts.py` at 25% coverage (fallback definitions tested, framework path not)

**Why +2:** Control-plane adapter is a real implementation (459 LOC, 18 tests), not a stub. Defines workspace integration contracts per Agent Runtime v1.8 §2. Still no runtime agentic capabilities, so capped at 4.

**Standards Cited:** Build Standard v2.14 § Agentic Workspace, AI Agent Runtime v1.8 §2 Tool Registration, §13 Operational Policies

---

## SA Gate Results (Sprint Protocol v3.4)

| Gate | Status | Notes |
|------|--------|-------|
| SA-1: Lint & Type-Check | PARTIAL | ruff passes; pyright has 14 errors (optional dep pattern — acceptable) |
| SA-2: Test Suite | PASS | 102 tests pass, 85% coverage, no regression |
| SA-3: Build Success | PASS | `python -m build` + `twine check` pass in CI |
| SA-4: Security Gate | PASS | No eval/exec/shell=True; bandit+safety pass; no hardcoded secrets |
| SA-5: Audit Verification | N/A | No prior sprint task to verify |
| SA-6: API Layer Coverage | PASS | All CLI commands have tests |
| SA-7: Structural Artifacts | PASS | No database; config matches implementation |
| SA-8: Dimension Minimums | PASS | All 7 minimums met |
| SA-9: Parallel Merge | N/A | Single-agent development |
| SA-10: Compliance Evidence | FAIL | No SBOM generation; no compliance mapping |
| SA-11: Capability Contract | PASS | ToolSpecs defined and tested for all 5 commands |
| SA-12: Dynamic Assembly | N/A | No dynamic agent creation |
| SA-13: Policy Runtime Smoke | N/A | PolicyRuntime imported but not implemented |

---

## Gap Analysis

### Agent-Fixable Gaps (sprint work)

| # | Gap | Dimensions | Impact | Effort |
|---|-----|------------|--------|--------|
| G1 | Create `docs/CODEBASE_MAP.md` | D11 | Required by Phase 0.5 | Small |
| G2 | Add SBOM generation to CI (CycloneDX via `cyclonedx-py`) | D19 | +1 Dim 19 (5->6), unblocks SLSA | Medium |
| G3 | Add issue templates + PR template | D10, D11 | Repo Controls v1.3 requirement | Small |
| G4 | Improve `contracts.py` test coverage (25% -> 80%+) | D7 | Strengthens control-plane testing | Small |
| G5 | Add ReDoS timeout on regex detectors (`re.match` with timeout or `regex` lib) | D8 | Hardens security for untrusted input | Medium |
| G6 | Add resource limits on prediction file size | D8 | Prevents DoS on large files | Small |
| G7 | Add unique run ID to report output | D9 | Agent Runtime v1.8 §7 requirement | Small |
| G8 | Remove deprecated `version` key from `docker-compose.yml` | D20 | Cleanup | Trivial |
| G9 | Create first release tag (v0.2.0) | D10, D19, D20 | Enables SBOM, PyPI path | Small |
| G10 | Add auto-generated API docs (pdoc/sphinx) in CI | D11 | Uncaps Dim 11 above 7 | Medium |
| G11 | Add path-filtered CI triggers | D10 | Avoids unnecessary CI runs | Small |
| G12 | Replace `safety` with `pip-audit` | D8, D19 | Better coverage + actively maintained | Small |

### Human-Only Gaps

| # | Gap | Dimensions | Impact |
|---|-----|------------|--------|
| H1 | Enable branch protection on `main` (require status checks, no force-push) | D10 | +1 Dim 10 (7->8) |
| H2 | Publish to PyPI with release automation | D10, D19, D20 | +1 Dim 10, +1 Dim 20 |
| H3 | SLSA Level 2 attestation (signing infrastructure) | D19 | +1 Dim 19 |
| H4 | Security pen test (regex DoS, path traversal, zip extraction) | D8 | Validates security claims |
| H5 | Key rotation strategy + documentation | D2, D18 | Requires security architecture decisions |

---

## Path to 75/100

**Current: 69.4 — Target: 75.0 — Delta needed: +5.6**

Agent-fixable sprint plan:

| Action | Dimension Change | Weighted Impact |
|--------|-----------------|-----------------|
| G2: SBOM in CI + G9: release tag | D19: 5->7 | +1.0 |
| G4: contracts.py coverage + G5: ReDoS timeout + G6: resource limits | D7: 8->9, D8: 8->9 | +1.5 + 1.0 |
| G1: CODEBASE_MAP + G3: templates + G10: auto-generated API docs | D11: 7->8 | +1.0 |
| G7: run ID | D9: 6->7 | +0.5 |

**Subtotal from agent work: +5.0 -> 74.4**

To reach 75.0 requires at least one human action:
- H1: Branch protection -> D10: 7->8 (+1.0) -> **75.4**

---

## Standards Compliance Matrix

| Standard | Version | Compliance | Key Gaps |
|----------|---------|------------|----------|
| Build Standard | v2.14 | Partial | No CODEBASE_MAP, no release tags |
| Archetypes | v2.0 | Pass | All Arch 9 minimums met |
| Sprint Protocol | v3.4 | Partial | SA-1 partial (pyright), SA-10 fail (no SBOM) |
| Repository Controls | v1.3 | Partial | No branch protection, no templates, no SBOM, docs capped at 7 |
| Operational Standard | v1.4 | Partial | No performance baselines, no release process |
| Pre-Push Standard | v1.2 | Pass | Pre-commit hooks configured (ruff + pyright) |
| AI Agent Runtime | v1.8 | Partial | ToolSpec defined; no run ID, no PolicyRuntime |
| AI Service | v1.5 | N/A | Tool doesn't use AI |
| AI Resilience | v1.3 | N/A | No AI surfaces |
| AI Governance & Ethics | v1.1 | Conditional | Tool validates AI outputs; no model cards |
| BENCHMARK | v1.5 | Not implemented | No self-healing, no engineering baseline |
| Integration & Webhook | v1.1 | N/A | No integrations |
| Data Isolation | v1.1 | N/A | No multi-tenancy |
| User Trust | v1.4 | Minimal | Exit codes serve as trust signals; no override/undo UX |
| Compliance Framework | v1.0 | Fail | SBOM required, not present; SLSA L2 required, not present |

---

## Appendix: Score Change Summary

| Dimension | Previous | Current | Reason |
|-----------|----------|---------|--------|
| D7 Testing | 7 | **8** | 102 tests (up), 85% coverage (up from 70%), control-plane tests added |
| D9 Observability | 5 | **6** | Structured JSON logging added (`--log-format json`) |
| D19 Enterprise Security | 6 | **5** | Compliance Framework v1.0 now requires SBOM/SLSA L2; not present |
| D21 Agentic Workspace | 2 | **4** | Control-plane adapter: 459 LOC, ToolSpec, AuthorityBoundary, 18 tests |
| **Composite** | **67.5*** | **69.4** | **+1.9 net** |

*Previous audit reported 68.8 but weighted sum of stated scores = 67.5. This audit uses verified arithmetic.

---

## Post-Audit Sprint (Same Session)

All 12 agent-fixable gaps executed. Results:

### Gaps Resolved

| # | Gap | Status | Evidence |
|---|-----|--------|----------|
| G1 | `docs/CODEBASE_MAP.md` | DONE | Created with full source/test/CI layout |
| G2 | SBOM generation in CI | DONE | `cyclonedx-py environment` in `sbom` job, artifact uploaded |
| G3 | Issue + PR templates | DONE | `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md`, `.github/PULL_REQUEST_TEMPLATE.md` |
| G4 | contracts.py test coverage | DONE | 8 new tests (ToolSpec optional fields, AuthorityBoundary repr/sandbox/scope) |
| G5 | ReDoS timeout on regex | DONE | `_safe_findall()` with SIGALRM on Unix, text length limits on Windows |
| G6 | Resource limits on predictions | DONE | `MAX_PREDICTIONS_FILE_BYTES = 100MB`, enforced in `_read_predictions()` |
| G7 | Unique run ID in reports | DONE | `uuid.uuid4()` in `summary.run_id` |
| G8 | docker-compose `version` key | DONE | Removed deprecated `version: '3.8'` |
| G9 | Release tag v0.2.0 | PENDING | Tag after CI green (human action: push) |
| G10 | Auto-generated API docs | DONE | `pdoc` in CI `docs` job, artifact uploaded |
| G11 | Path-filtered CI triggers | DONE | `paths:` filter on push/PR for src, tests, pyproject, ci.yml, Dockerfile |
| G12 | `safety` -> `pip-audit` | DONE | Replaced in CI security job |

### Post-Sprint Verification

| Check | Result |
|-------|--------|
| `pytest -q` | 115 passed (was 102) |
| Coverage | 84% (threshold 70%) |
| `ruff check src/ tests/` | All checks passed |
| pyright | 14 errors (all in signing.py optional dep — expected) |

### Post-Sprint Score Projection

With G1-G12 resolved (once CI confirms green):

| Dimension | Pre-Sprint | Post-Sprint | Delta |
|-----------|-----------|-------------|-------|
| D7 Testing | 8 | 8 | = (new tests strengthen, no score change) |
| D8 Security | 8 | 9 | +1 (ReDoS timeout + resource limits + pip-audit) |
| D9 Observability | 6 | 7 | +1 (run ID per Agent Runtime v1.8 §7) |
| D10 CI/CD | 7 | 7 | = (path filters + SBOM, but still no branch protection) |
| D11 Documentation | 7 | 8 | +1 (CODEBASE_MAP + templates + auto-generated API docs) |
| D19 Enterprise Security | 5 | 6 | +1 (SBOM in CI, pip-audit) |
| **Composite** | **69.4** | **72.4** | **+3.0** |

### Remaining Human-Only Actions

| # | Action | Impact | How To |
|---|--------|--------|--------|
| **H1** | Enable branch protection on `main` | D10: 7->8 (+1.0) | GitHub -> Settings -> Branches -> Add rule -> `main` -> Require status checks (test, lint, security, sbom) + No force-push |
| **H2** | Publish to PyPI | D10, D20 | Add PyPI trusted publisher in `build` job; `twine upload dist/*` or use `pypa/gh-action-pypi-publish` |
| **H3** | SLSA Level 2 attestation | D19: 6->7 | Use `slsa-framework/slsa-github-generator` for provenance |
| **H4** | Security pen test | D8 validation | Test crafted ReDoS payloads, zip-slip edge cases, large file DoS |
| **H5** | Key rotation documentation | D2, D18 | Document recommended key lifetime, rotation procedure |
| **H9** | Create + push tag `v0.2.0` | D10, D19, D20 | `git tag -a v0.2.0 -m "v0.2.0"` then `git push origin v0.2.0` |

**With H1 alone: 72.4 + 1.0 = 73.4**
**With H1 + H2 + H9: ~75+**
