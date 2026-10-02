# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-26

Toolkit Policy Test Bench becomes an LLM safety and compliance evidence tool: score
outputs, import garak / promptfoo / PyRIT results, map them to controls, and gate CI.

### Release and project files

- Release workflow: a `v*` tag runs the tests, builds the sdist and wheel,
  checks them with `twine check --strict` (twine 6.1 or newer, which reads the
  Metadata 2.4 that setuptools 77+ writes), installs the wheel and checks its
  version against the tag, and attaches both files to a GitHub Release. The
  PyPI upload (Trusted Publishing) runs only when the repository variable
  `PUBLISH_TO_PYPI` is `true`. See `RELEASING.md`.
- CI builds and checks the package the same way on every pull request.
- Package metadata: SPDX license expression `Apache-2.0` with `LICENSE` and
  `NOTICE` in the distributions, author AKIVA AI, LLC, and links to the
  documentation, issues and changelog.
- Added `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue and pull request
  templates and `RELEASING.md`. `SECURITY.md` lists the supported versions and
  the private reporting channel.
- CI runs pyright, and `pip-audit` with the `presidio` and `judge` extras
  installed as well as `signing`. The LiteLLM refusal judge now type-checks
  with the `judge` extra installed.

### Licensing
- Relicensed from MIT to Apache-2.0. Releases before this change remain available under MIT.
  Added a `NOTICE` file.

### Added
- GitHub Action (`action.yml`): `run`, `import` and `evidence` with `verdict`,
  `exit-code` and `report` outputs and a job summary; tested in CI on the bundled example.
- `examples/support-bot`: a suite with per-case expectations and good / leaky
  predictions; the README 5-minute example runs on it and is tested.
- Report envelope v1 is the default JSON output. `run --out` and the new `compare --out`
  write an in-toto Statement v1 in canonical JSON with `verdict`/`exit_code`, input
  digests, a `summary` and per-case `details`. Spec in `docs/report-envelope.md`, JSON
  Schema in `schemas/report-envelope.v1.json`.
- `run --patterns FILE` (repeatable) loads custom PII/secret regex detectors from JSON
  pattern files into a registry for that run. Pattern files are listed with their
  SHA-256 in the report inputs and the detectors in `details.meta.custom_detectors`.
- Optional Presidio PII engine (`[presidio]` extra): `pii.engine` `presidio` or `both`,
  with `presidio_model`, `entities`, `score_threshold`; recorded in `details.meta`.
- Optional LLM refusal judge via LiteLLM (`[judge]` extra, `run --refusal-judge MODEL`,
  off by default). The model and judge-prompt SHA-256 are recorded in the report; a
  failed or unparseable judgement fails the case with `refusal_undetermined`.
- `evidence` command: files `policy.run` and `policy.import` results under OWASP Top 10
  for LLM Applications 2025, NIST AI RMF 1.0 MEASURE subcategories, NIST AI 600-1 GAI
  risks and EU AI Act articles through a data file (`data/controls.json`, overridable
  with `--controls`). Writes a `policy.evidence` envelope with per-control status and
  per-report evidence, a markdown table (`--format markdown`), and gates on failed plus
  unjudged results. Run cases can be assigned with a `category:<name>` tag.
- `import` command: reads garak `report.jsonl`, promptfoo results JSON and PyRIT memory
  (SQLite) or score JSON, and writes normalized findings as a `policy.import` envelope
  with a `by_category` summary and a `--max-failures` gate. Unjudged items (garak `None`
  scores, promptfoo error rows, incomplete PyRIT scores) count against the gate.
- Finding categories as a data file (`data/categories.json`), overridable with
  `--categories`.
- Per-case expectations in `cases.jsonl` (`expect`): expected refusal (`refusal: true`)
  and over-refusal (`refusal: false`), per-case must/must-not contain and regex checks,
  and per-case PII/secret detector overrides (`enabled`, `ignore`). New failure codes
  `refusal_missing` and `refusal_unexpected`; new summary counts `expected_refusals`,
  `missed_refusals`, `over_refusals`. Unknown `expect` keys are rejected.
- `run --out` records an `error` envelope when the tool cannot judge (bad predictions,
  suite that fails to load, pack that fails verification).

### Deprecated
- `run --legacy-json` keeps the pre-1.0 report shape for one minor version.

### Security
- Missing predictions now fail closed. A case with no prediction line, or a `null`
  prediction, fails with `missing_prediction` instead of being scored as an empty
  string (which passed every must-NOT check). The summary reports `missing_predictions`.
- Secret detection covers current credential formats: OpenAI project, service-account
  and admin keys; Anthropic keys; GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
  `github_pat_`); Stripe secret and restricted keys; Google API keys; PEM private keys.
  New report keys: `anthropic_key`, `github_token`, `stripe_key`, `google_api_key`,
  `private_key`.
- Every regex (built-in, suite `regex_*` checks, plugin pattern files) runs on the
  `regex` engine with a per-call timeout that works on all platforms and threads. The
  old SIGALRM guard covered only built-in patterns, did nothing on Windows and failed
  off the main thread. A timeout fails the case (`regex_timeout:<p>`,
  `pii_scan_timeout`, `secret_scan_timeout`). User patterns are capped at 1000 chars.
- `run` hash-verifies a `.zip` pack before running it, and the manifest must cover
  `suite.json` and `cases.jsonl`. New `--signature` / `--public-key` options require a
  valid Ed25519 signature before the suite runs.

### Changed
- Phone detection: international `+` numbers (E.164, 8-15 digits); NANP numbers need a
  2-9 area code; 10 bare digits count only after a phone word and with valid NANP
  codes, so invoice and order numbers no longer match.
- SSN detection: space-separated and context-anchored bare SSNs are found; numbers the
  SSA never issues (area 000/666/9xx, group 00, serial 0000, repeated digit) are skipped.
- `run` and `compare` print the envelope on stdout with `--format json`.
- `compare` rejects `error` reports and reports whose summary lacks the compared numbers
  (exit 2) instead of treating missing numbers as zero.
- `validate-report` validates envelopes as well as legacy reports.
- `run` exits 4 when any case fails or any PII/secret hit is found (it always exited 0).
- Credit-card hits require a Luhn-valid number, which removes false positives from
  order ids and timestamps.
- Object/array predictions are checked as JSON instead of their Python repr; falsy
  values such as `0` are no longer blanked.
- Custom detector counts are added to built-in counts instead of overwriting a built-in
  key with the same name.
- `detect_pii` / `detect_secrets` raise `RegexTimeoutError` on timeout instead of
  silently returning zero hits.
- New runtime dependency: `regex`.
- Docker image installs only the runtime package (plus signing), runs as a non-root
  user and uses `toolkit-policy` as its entrypoint.
- Dependabot opens one grouped weekly PR per ecosystem.

### Removed
- The unused `control_plane` package and its tests.
- The unused `.env.example`.

## [0.2.0] - 2026-03-09

### Added
- Custom detector plugin system (`plugins.py`) for user-defined PII/secret patterns
- `--log-format json` flag for structured JSON logging
- `--format` flag (`json`, `table`) for `run` and `compare` output
- Zip-slip prevention in pack extraction (path traversal guard)
- Dependabot configuration for automated dependency updates
- Coverage threshold enforcement at 70% in CI
- Pre-commit configuration with ruff and pyright
- Edge case tests for malformed policies, empty suites, and concurrent detection
- CHANGELOG.md

### Changed
- CI security scans are now blocking (removed `continue-on-error`)
- Coverage threshold raised from 60% to 70%

### Security
- Fixed potential zip-slip vulnerability in `load_suite_from_path`

## [0.1.0] - 2026-03-01

### Added
- Initial release
- Policy suite runner with PII and secret detection
- Pack creation, verification, and signing (Ed25519)
- Report comparison with configurable budgets for CI gating
- JSON schema validation for LLM outputs
- CLI with `keygen`, `pack` (5 subcommands), `run`, `compare` and `validate-report`
- Docker and docker-compose support
- CI pipeline with test, lint, security, and build stages
