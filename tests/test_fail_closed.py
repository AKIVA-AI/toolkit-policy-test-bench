"""Fail-closed behaviour of the runner: missing and structured predictions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolkit_policy_test_bench.runner import run_suite
from toolkit_policy_test_bench.suite import read_suite_dir

LEAK_ONLY_CHECKS: dict[str, Any] = {
    "must_not_contain": ["password"],
    "regex_must_not_match": [r"\bsecret\b"],
    "max_output_chars": 500,
    "pii": {"enabled": True},
    "secrets": {"enabled": True},
}


def _suite(tmp_path: Path, checks: dict[str, Any], case_ids: list[str]) -> Path:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "fail_closed",
                "description": "",
                "created_at": "",
                "checks": checks,
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        "".join(json.dumps({"id": cid, "input": "", "tags": []}) + "\n" for cid in case_ids),
        encoding="utf-8",
    )
    return suite_dir


def _preds(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    path = tmp_path / "preds.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def test_missing_prediction_fails_leak_only_suite(tmp_path: Path) -> None:
    """A case with no output must not pass a suite made only of must-NOT checks."""
    suite = read_suite_dir(_suite(tmp_path, LEAK_ONLY_CHECKS, ["present", "missing"]))
    preds = _preds(tmp_path, [{"id": "present", "prediction": "all good"}])

    report = run_suite(suite=suite, predictions_path=preds)

    by_id = {c["id"]: c for c in report.cases}
    assert by_id["present"]["passed"] is True
    assert by_id["missing"]["passed"] is False
    assert by_id["missing"]["failures"] == ["missing_prediction"]
    assert report.summary["failed_cases"] == 1
    assert report.summary["missing_predictions"] == 1


def test_null_prediction_is_treated_as_missing(tmp_path: Path) -> None:
    suite = read_suite_dir(_suite(tmp_path, LEAK_ONLY_CHECKS, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1", "prediction": None}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is False
    assert report.cases[0]["failures"] == ["missing_prediction"]


def test_prediction_line_without_prediction_key_is_missing(tmp_path: Path) -> None:
    suite = read_suite_dir(_suite(tmp_path, LEAK_ONLY_CHECKS, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1"}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["failures"] == ["missing_prediction"]


def test_explicit_empty_string_is_a_real_output(tmp_path: Path) -> None:
    """An empty string is an actual (empty) model output, not a missing one."""
    suite = read_suite_dir(_suite(tmp_path, LEAK_ONLY_CHECKS, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1", "prediction": ""}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is True
    assert report.summary["missing_predictions"] == 0


def test_dict_prediction_satisfies_json_schema(tmp_path: Path) -> None:
    checks = {"json_schema": {"required_keys": ["a"], "allow_extra_keys": True}}
    suite = read_suite_dir(_suite(tmp_path, checks, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1", "prediction": {"a": 1}}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is True
    assert report.cases[0]["json"]["valid"] is True


def test_dict_prediction_is_scanned_for_secrets(tmp_path: Path) -> None:
    suite = read_suite_dir(_suite(tmp_path, {"secrets": {"enabled": True}}, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1", "prediction": {"key": "AKIAIOSFODNN7EXAMPLE"}}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["secrets"]["aws_access_key"] == 1
    assert "secret_detected" in report.cases[0]["failures"]


def test_falsy_non_string_prediction_is_not_blanked(tmp_path: Path) -> None:
    """A numeric 0 prediction is an output and must be checked as "0", not as missing."""
    suite = read_suite_dir(_suite(tmp_path, {"must_contain": ["0"]}, ["c1"]))
    preds = _preds(tmp_path, [{"id": "c1", "prediction": 0}])

    report = run_suite(suite=suite, predictions_path=preds)

    assert report.cases[0]["passed"] is True
