# toolkit-policy-test-bench: Codebase Map

Last updated: 2026-09-26. 259 tests (pytest, including parametrized cases).

## Entry points

| Entry | Path | Purpose |
|-------|------|---------|
| CLI | `src/toolkit_policy_test_bench/cli.py:main` | `toolkit-policy` command |
| Module | `src/toolkit_policy_test_bench/__main__.py` | `python -m toolkit_policy_test_bench` |
| API | `src/toolkit_policy_test_bench/__init__.py` | Public exports (`__all__`) |

## Source layout

```
src/toolkit_policy_test_bench/
  cli.py          Argument parser and command handlers; `run` verifies packs and gates on findings
  runner.py       run_suite(): reads predictions, applies suite checks, builds the report
  importers.py    garak / promptfoo / PyRIT result files -> normalized findings
  categories.py   Loads data/categories.json; maps each tool's test id to a category
  evidence.py     Evidence per control from run/import reports; markdown table
  data/           categories.json (category rules) and controls.json (category -> controls)
  presidio_pii.py Optional Presidio PII engine (`[presidio]` extra)
  judge.py        Optional LiteLLM refusal judge (`[judge]` extra)
  refusal.py      Keyword refusal heuristic for per-case `expect.refusal`
  detectors.py    Built-in PII/secret rules; compile_pattern / safe_search / safe_findall (regex timeout)
  plugins.py      DetectorRegistry: custom detectors (Python callables or JSON pattern files)
  suite.py        PolicySuite / PolicyCase models, per-case `expect` validation, suite reader
  report.py       PolicyReport model (reads envelope or legacy) and legacy JSON writer
  envelope.py     Report envelope v1 (in-toto Statement): build, canonical JSON, validate
  compare.py      compare_reports() with CompareBudget
  json_schema.py  Required/optional/extra key checks for JSON predictions
  pack.py         Suite zip create/verify/load (SHA-256 manifest, zip-slip guard)
  signing.py      Ed25519 keygen/sign/verify (optional `cryptography`)
  io.py           Path validation and file I/O helpers
  hashing.py      SHA-256 of a file
  formatting.py   JSON / table output
```

## Data flow

```
suite.json + cases.jsonl (dir or verified .zip pack)   predictions.jsonl
                     \                                   /
                      runner.run_suite()
                        - missing prediction -> fail (missing_prediction)
                        - string / regex / length checks (regex with timeout)
                        - detectors.detect_pii / detect_secrets + plugin registry
                        - json_schema.validate_json
                      -> PolicyReport -> envelope.build_envelope (policy.run, canonical JSON)
                      -> cli `run` exit code (0 pass, 4 any failure)
                      -> compare.compare_reports (baseline vs candidate budget)
```

## Tests

```
tests/
  test_fail_closed.py          Missing / null / structured predictions
  test_regex_safety.py         Regex timeouts, pattern caps, off-main-thread detection, plugin counts
  test_cli_run_gating.py       run exit codes, pack hash + signature verification before run
  test_detectors_and_schema.py Detector positives/negatives (secret formats, Luhn), JSON schema
  test_archive_plugins_and_limits.py  Zip-slip, plugins, formatting, JSON logging, edge cases
  test_io_and_cli_validation.py  I/O validation and CLI error paths
  test_cli.py                  CLI round trip, compare exit code
  test_evidence.py             Control mapping file, evidence from run and import reports, gate
  test_importers.py            Importers on real tool output (tests/fixtures/importers), garak eval reconciliation
  test_examples.py             README 5-minute example on examples/support-bot
  test_cli_patterns.py         run --patterns: custom detectors from JSON files, errors, report
  test_phone_ssn.py            Phone (NANP, E.164, context) and SSN (SSA rules) detection
  test_semantic_detectors.py   LiteLLM judge (stubbed) and Presidio (real, when installed)
  test_per_case.py             Per-case refusal, must/must-not, regex, detector overrides
  test_envelope.py             Envelope shape, canonical bytes, JSON Schema, verdict/exit agreement
  test_pack_run_compare.py     End-to-end pack -> run -> compare
  test_pack_load_twice.py      Reloading a pack
```

## CI

`.github/workflows/ci.yml`: tests on Python 3.10-3.12 with coverage >= 70%, bandit,
pip-audit, ruff, SBOM, API docs, package build.

## Dependencies

- Runtime: `regex`
- Optional: `cryptography` (signing)
- Dev: pytest, pytest-cov, ruff, pyright, cryptography

## Other entry points

- `action.yml`: composite GitHub Action wrapping `run`, `import` and `evidence`.
- `examples/support-bot/`: example suite with good and leaky predictions.
- `.github/workflows/release.yml`: on a `v*` tag, a GitHub Release with the sdist and wheel; PyPI trusted publishing when `PUBLISH_TO_PYPI` is `true` (see `RELEASING.md`).
- `schemas/report-envelope.v1.json`, `docs/report-envelope.md`: shared report format.
