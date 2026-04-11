# Policy Test Bench — PII/secret leakage and policy regression tests for LLM outputs

**Archetype:** 9 — Developer Tool / CLI Utility
**Standards:** See `akiva-enterprise-products/CLAUDE.md` for current Akiva Build Standard version and full standards reference.
**Ontology ID:** TK-07
**Version:** 0.2.0

## Stack

- Language: Python 3.10+
- Test: `pytest -xvs`
- Lint: `ruff check src/ tests/`
- Type-check: `pyright src/` (14 expected errors from optional cryptography dep)
- Build: `pip install -e .`

## Verification Commands

| Command | Purpose |
| ------- | ------- |
| `pytest --cov=toolkit_policy_test_bench --cov-fail-under=70 -v` | Run tests with coverage |
| `ruff check src/ tests/` | Lint |
| `pyright src/` | Type-check (14 errors expected in signing.py) |

## Current State

- Audit Score: 69.4/100 (2026-04-04)
- Tests: 115
- Coverage: 84%

## Key Rules

- Archetype 9: single-purpose CLI tool, zero runtime dependencies
- Tests first, security fixes before features
- One task at a time, verified before moving to next

## Human-Required Actions (for score > 72)

- **H1:** Enable branch protection on `main` (GitHub Settings -> Branches)
- **H2:** Publish to PyPI with release automation
- **H3:** SLSA Level 2 attestation
- **H4:** Security pen test (regex DoS, path traversal)
- **H5:** Key rotation strategy documentation
