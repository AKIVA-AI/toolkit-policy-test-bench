# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- CLI with 7 subcommands
- Docker and docker-compose support
- CI pipeline with test, lint, security, and build stages
