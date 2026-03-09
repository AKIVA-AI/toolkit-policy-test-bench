"""Tests for deep hardening sprint: zip-slip, plugins, formatting, JSON logging, edge cases."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from toolkit_policy_test_bench.cli import (
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILED,
    _JSONLogFormatter,
    main,
)
from toolkit_policy_test_bench.formatting import format_output
from toolkit_policy_test_bench.pack import _safe_extract, load_suite_from_path
from toolkit_policy_test_bench.plugins import (
    DetectorPlugin,
    DetectorRegistry,
    registry,
)
from toolkit_policy_test_bench.runner import run_suite

# ============================================================================
# Zip-slip prevention tests
# ============================================================================


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    """Zip with '../escape.txt' must be rejected."""
    malicious_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../escape.txt", "pwned")

    target = tmp_path / "extract_target"
    target.mkdir()

    with zipfile.ZipFile(malicious_zip, "r") as zf:
        with pytest.raises(ValueError, match="escapes target directory"):
            _safe_extract(zf, target)


def test_safe_extract_rejects_absolute_path(tmp_path: Path) -> None:
    """Zip with absolute path member must be rejected."""
    malicious_zip = tmp_path / "abs.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("/etc/passwd", "root:x:0:0")

    target = tmp_path / "extract_target"
    target.mkdir()

    with zipfile.ZipFile(malicious_zip, "r") as zf:
        with pytest.raises(ValueError, match="escapes target directory"):
            _safe_extract(zf, target)


def test_safe_extract_allows_normal_paths(tmp_path: Path) -> None:
    """Normal zip members should extract without error."""
    normal_zip = tmp_path / "normal.zip"
    with zipfile.ZipFile(normal_zip, "w") as zf:
        zf.writestr("file.txt", "hello")
        zf.writestr("subdir/nested.txt", "world")

    target = tmp_path / "extract_target"
    target.mkdir()

    with zipfile.ZipFile(normal_zip, "r") as zf:
        _safe_extract(zf, target)

    assert (target / "file.txt").read_text() == "hello"
    assert (target / "subdir" / "nested.txt").read_text() == "world"


def test_load_suite_from_zip_with_traversal_rejected(tmp_path: Path) -> None:
    """load_suite_from_path must reject zips with path traversal."""
    malicious_zip = tmp_path / "evil_suite.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
        zf.writestr(
            "suite.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "name": "evil",
                    "description": "",
                    "created_at": "",
                    "checks": {},
                }
            ),
        )
        zf.writestr("cases.jsonl", "")

    with pytest.raises(ValueError, match="escapes target directory"):
        load_suite_from_path(malicious_zip)


# ============================================================================
# Custom detector plugin tests
# ============================================================================


class TestDetectorRegistry:
    def setup_method(self) -> None:
        self.reg = DetectorRegistry()

    def test_register_and_run_pii(self) -> None:
        def detect_mrn(text: str) -> dict[str, int]:
            import re

            return {"mrn": len(re.findall(r"MRN-\d{8}", text))}

        self.reg.register(DetectorPlugin(name="mrn", kind="pii", detect=detect_mrn))
        result = self.reg.run_pii("Patient MRN-12345678 and MRN-87654321")
        assert result == {"mrn": 2}

    def test_register_and_run_secrets(self) -> None:
        def detect_github(text: str) -> dict[str, int]:
            import re

            return {"github_token": len(re.findall(r"ghp_[A-Za-z0-9]{36}", text))}

        self.reg.register(DetectorPlugin(name="github_token", kind="secret", detect=detect_github))
        result = self.reg.run_secrets("token: ghp_" + "A" * 36)
        assert result == {"github_token": 1}

    def test_duplicate_name_rejected(self) -> None:
        plugin = DetectorPlugin(name="dup", kind="pii", detect=lambda t: {})
        self.reg.register(plugin)
        with pytest.raises(ValueError, match="already registered"):
            self.reg.register(plugin)

    def test_invalid_kind_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid detector kind"):
            DetectorPlugin(name="bad", kind="other", detect=lambda t: {})

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            DetectorPlugin(name="", kind="pii", detect=lambda t: {})

    def test_unregister(self) -> None:
        plugin = DetectorPlugin(name="temp", kind="pii", detect=lambda t: {})
        self.reg.register(plugin)
        assert self.reg.unregister("temp") is True
        assert self.reg.unregister("temp") is False
        assert len(self.reg.detectors) == 0

    def test_clear(self) -> None:
        self.reg.register(DetectorPlugin(name="a", kind="pii", detect=lambda t: {}))
        self.reg.register(DetectorPlugin(name="b", kind="secret", detect=lambda t: {}))
        self.reg.clear()
        assert len(self.reg.detectors) == 0

    def test_load_patterns_file(self, tmp_path: Path) -> None:
        patterns = {
            "detectors": [
                {"name": "internal_id", "kind": "pii", "pattern": r"INT-\d{6}"},
                {"name": "api_key_v2", "kind": "secret", "pattern": r"apk2_[A-Za-z0-9]{20}"},
            ]
        }
        pfile = tmp_path / "patterns.json"
        pfile.write_text(json.dumps(patterns), encoding="utf-8")

        count = self.reg.load_patterns_file(pfile)
        assert count == 2
        assert len(self.reg.detectors) == 2

        result = self.reg.run_pii("Found INT-123456 in text")
        assert result == {"internal_id": 1}

    def test_load_patterns_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            self.reg.load_patterns_file(Path("/nonexistent/patterns.json"))

    def test_load_patterns_file_invalid_json(self, tmp_path: Path) -> None:
        pfile = tmp_path / "bad.json"
        pfile.write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            self.reg.load_patterns_file(pfile)

    def test_load_patterns_missing_detectors_key(self, tmp_path: Path) -> None:
        pfile = tmp_path / "bad.json"
        pfile.write_text('{"other": []}', encoding="utf-8")
        with pytest.raises(ValueError, match="'detectors' array"):
            self.reg.load_patterns_file(pfile)

    def test_load_patterns_entry_missing_fields(self, tmp_path: Path) -> None:
        pfile = tmp_path / "bad.json"
        pfile.write_text('{"detectors": [{"name": "x"}]}', encoding="utf-8")
        with pytest.raises(ValueError, match="requires"):
            self.reg.load_patterns_file(pfile)


def test_global_registry_is_importable() -> None:
    """The module-level singleton registry should be importable."""
    assert isinstance(registry, DetectorRegistry)


# ============================================================================
# Plugin integration with runner
# ============================================================================


def test_runner_uses_custom_pii_plugin(tmp_path: Path) -> None:
    """Custom PII detector should be picked up by run_suite."""
    # Set up a temporary custom detector
    import re

    from toolkit_policy_test_bench.plugins import registry as r

    original = r._detectors.copy()
    try:
        r.clear()
        r.register(
            DetectorPlugin(
                name="custom_id",
                kind="pii",
                detect=lambda t: {"custom_id": len(re.findall(r"CID-\d+", t))},
            )
        )

        suite_dir = tmp_path / "suite"
        suite_dir.mkdir()
        (suite_dir / "suite.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "name": "plugin_test",
                    "description": "",
                    "created_at": "",
                    "checks": {"pii": {"enabled": True}},
                }
            ),
            encoding="utf-8",
        )
        (suite_dir / "cases.jsonl").write_text(
            json.dumps({"id": "c1", "input": "", "tags": []}) + "\n",
            encoding="utf-8",
        )

        preds = tmp_path / "preds.jsonl"
        preds.write_text(
            json.dumps({"id": "c1", "prediction": "Hello CID-999"}) + "\n",
            encoding="utf-8",
        )

        from toolkit_policy_test_bench.suite import read_suite_dir

        suite = read_suite_dir(suite_dir)
        report = run_suite(suite=suite, predictions_path=preds)

        case = report.cases[0]
        assert case["pii"]["custom_id"] == 1
        assert "pii_detected" in case["failures"]
    finally:
        r._detectors = original


# ============================================================================
# Formatting tests
# ============================================================================


def test_format_output_json() -> None:
    data = {"key": "value", "num": 42}
    result = format_output(data, "json")
    parsed = json.loads(result)
    assert parsed == data


def test_format_output_table() -> None:
    data = {"name": "test", "score": 95, "nested": {"a": 1}}
    result = format_output(data, "table")
    assert "name" in result
    assert "score" in result
    assert "95" in result


def test_format_output_table_empty() -> None:
    result = format_output({}, "table")
    assert result == "(empty)"


# ============================================================================
# JSON logging tests
# ============================================================================


def test_json_log_formatter() -> None:
    import logging

    formatter = _JSONLogFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "WARNING"
    assert parsed["message"] == "Test message"
    assert "ts" in parsed
    assert "logger" in parsed


def test_cli_json_log_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--log-format json should not break normal operation."""
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "suite": {},
                "summary": {},
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    rc = main(["--log-format", "json", "validate-report", "--report", str(report)])
    assert rc == EXIT_SUCCESS


# ============================================================================
# --format flag tests
# ============================================================================


def test_run_format_table(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """run --format table should produce table output."""
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "fmt_test",
                "description": "",
                "created_at": "",
                "checks": {},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": []}) + "\n",
        encoding="utf-8",
    )
    preds = tmp_path / "preds.jsonl"
    preds.write_text(json.dumps({"id": "c1", "prediction": "ok"}) + "\n", encoding="utf-8")

    rc = main(
        [
            "run",
            "--suite",
            str(suite_dir),
            "--predictions",
            str(preds),
            "--format",
            "table",
        ]
    )
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "suite" in out
    assert "summary" in out


def test_compare_format_table(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """compare --format table should produce table output."""
    for name, data in [
        (
            "baseline.json",
            {
                "suite": {},
                "summary": {"fail_rate": 0, "pii_total_hits": 0, "secret_total_hits": 0},
                "cases": [],
            },
        ),
        (
            "candidate.json",
            {
                "suite": {},
                "summary": {"fail_rate": 0, "pii_total_hits": 0, "secret_total_hits": 0},
                "cases": [],
            },
        ),
    ]:
        (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")

    rc = main(
        [
            "compare",
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--candidate",
            str(tmp_path / "candidate.json"),
            "--format",
            "table",
        ]
    )
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "passed" in out


# ============================================================================
# Edge case tests: malformed policies, empty suites, concurrent detection
# ============================================================================


def test_malformed_suite_json(tmp_path: Path) -> None:
    """Loading a suite with invalid JSON should raise."""
    suite_dir = tmp_path / "bad_suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text("not json", encoding="utf-8")
    (suite_dir / "cases.jsonl").write_text("", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_suite_from_path(suite_dir)


def test_empty_suite_no_cases(tmp_path: Path) -> None:
    """A suite with zero cases should produce an empty report."""
    suite_dir = tmp_path / "empty_suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "empty",
                "description": "",
                "created_at": "",
                "checks": {"pii": {"enabled": True}},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text("", encoding="utf-8")

    preds = tmp_path / "preds.jsonl"
    preds.write_text("", encoding="utf-8")

    from toolkit_policy_test_bench.suite import read_suite_dir

    suite = read_suite_dir(suite_dir)
    report = run_suite(suite=suite, predictions_path=preds)

    assert report.summary["cases"] == 0
    assert report.summary["failed_cases"] == 0
    assert report.summary["fail_rate"] == 0.0
    assert len(report.cases) == 0


def test_missing_prediction_for_case(tmp_path: Path) -> None:
    """Cases without a matching prediction should use empty string."""
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "missing_pred",
                "description": "",
                "created_at": "",
                "checks": {"must_contain": ["expected"]},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "orphan", "input": "", "tags": []}) + "\n",
        encoding="utf-8",
    )

    preds = tmp_path / "preds.jsonl"
    preds.write_text("", encoding="utf-8")

    from toolkit_policy_test_bench.suite import read_suite_dir

    suite = read_suite_dir(suite_dir)
    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is False
    assert "missing:expected" in report.cases[0]["failures"]


def test_concurrent_pii_and_secret_detection(tmp_path: Path) -> None:
    """Both PII and secret detectors should fire on same text."""
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "both",
                "description": "",
                "created_at": "",
                "checks": {
                    "pii": {"enabled": True},
                    "secrets": {"enabled": True},
                },
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": []}) + "\n",
        encoding="utf-8",
    )

    # Text containing both PII (email) and secret (AWS key)
    text_with_both = "Contact user@example.com and use AKIAIOSFODNN7EXAMPLE"
    preds = tmp_path / "preds.jsonl"
    preds.write_text(
        json.dumps({"id": "c1", "prediction": text_with_both}) + "\n", encoding="utf-8"
    )

    from toolkit_policy_test_bench.suite import read_suite_dir

    suite = read_suite_dir(suite_dir)
    report = run_suite(suite=suite, predictions_path=preds)

    case = report.cases[0]
    assert case["pii"]["email"] >= 1
    assert case["secrets"]["aws_access_key"] >= 1
    assert "pii_detected" in case["failures"]
    assert "secret_detected" in case["failures"]


def test_malformed_predictions_jsonl(tmp_path: Path) -> None:
    """Malformed JSONL predictions should raise."""
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "t",
                "description": "",
                "created_at": "",
                "checks": {},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": []}) + "\n",
        encoding="utf-8",
    )

    preds = tmp_path / "preds.jsonl"
    preds.write_text("not valid json\n", encoding="utf-8")

    from toolkit_policy_test_bench.suite import read_suite_dir

    suite = read_suite_dir(suite_dir)
    with pytest.raises(json.JSONDecodeError):
        run_suite(suite=suite, predictions_path=preds)


def test_suite_with_all_constraint_types(tmp_path: Path) -> None:
    """Suite exercising all constraint types simultaneously."""
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "all_checks",
                "description": "",
                "created_at": "",
                "checks": {
                    "must_contain": ["hello"],
                    "must_not_contain": ["forbidden"],
                    "regex_must_match": [r"\d+"],
                    "regex_must_not_match": [r"BADPATTERN"],
                    "max_output_chars": 100,
                    "case_insensitive": True,
                    "pii": {"enabled": True},
                    "secrets": {"enabled": True},
                },
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": ["comprehensive"]}) + "\n",
        encoding="utf-8",
    )

    # This prediction should pass all checks
    preds = tmp_path / "preds.jsonl"
    preds.write_text(
        json.dumps({"id": "c1", "prediction": "Hello world 42"}) + "\n",
        encoding="utf-8",
    )

    from toolkit_policy_test_bench.suite import read_suite_dir

    suite = read_suite_dir(suite_dir)
    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is True


def test_validate_report_invalid_shape(tmp_path: Path) -> None:
    """validate-report should fail for missing keys."""
    report = tmp_path / "bad_report.json"
    report.write_text('{"missing": "keys"}', encoding="utf-8")

    rc = main(["validate-report", "--report", str(report)])
    assert rc == EXIT_VALIDATION_FAILED
