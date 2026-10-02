"""ReDoS and thread-safety guards for built-in, suite and plugin regexes."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from toolkit_policy_test_bench import detectors
from toolkit_policy_test_bench.detectors import detect_pii, detect_secrets
from toolkit_policy_test_bench.plugins import DetectorPlugin, registry
from toolkit_policy_test_bench.runner import run_suite
from toolkit_policy_test_bench.suite import read_suite_dir

# Exponential backtracking: every split of the run of "a" is tried before failing.
CATASTROPHIC = "(a|aa)+$"
EVIL_TEXT = "a" * 60 + "b"


def _suite(tmp_path: Path, checks: dict[str, Any]) -> Path:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "regex_safety",
                "description": "",
                "created_at": "",
                "checks": checks,
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": []}) + "\n", encoding="utf-8"
    )
    return suite_dir


def _preds(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "preds.jsonl"
    path.write_text(json.dumps({"id": "c1", "prediction": text}) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def short_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detectors, "REGEX_TIMEOUT_SECONDS", 0.2)


@pytest.fixture
def clean_registry() -> Any:
    saved = registry.detectors
    registry.clear()
    try:
        yield registry
    finally:
        registry.clear()
        for plugin in saved:
            registry.register(plugin)


@pytest.mark.parametrize("check", ["regex_must_not_match", "regex_must_match"])
def test_suite_regex_timeout_fails_case(tmp_path: Path, short_timeout: None, check: str) -> None:
    suite = read_suite_dir(_suite(tmp_path, {check: [CATASTROPHIC]}))

    start = time.monotonic()
    report = run_suite(suite=suite, predictions_path=_preds(tmp_path, EVIL_TEXT))
    elapsed = time.monotonic() - start

    assert elapsed < 10
    case = report.cases[0]
    assert case["passed"] is False
    assert f"regex_timeout:{CATASTROPHIC}" in case["failures"]


def test_plugin_pattern_timeout_fails_case(
    tmp_path: Path, short_timeout: None, clean_registry: Any
) -> None:
    pfile = tmp_path / "patterns.json"
    pfile.write_text(
        json.dumps({"detectors": [{"name": "evil", "kind": "pii", "pattern": CATASTROPHIC}]}),
        encoding="utf-8",
    )
    clean_registry.load_patterns_file(pfile)
    suite = read_suite_dir(_suite(tmp_path, {"pii": {"enabled": True}}))

    start = time.monotonic()
    report = run_suite(suite=suite, predictions_path=_preds(tmp_path, EVIL_TEXT))

    assert time.monotonic() - start < 10
    assert report.cases[0]["passed"] is False
    assert "pii_scan_timeout" in report.cases[0]["failures"]


def test_oversized_suite_pattern_is_rejected(tmp_path: Path) -> None:
    pattern = "a" * (detectors.MAX_PATTERN_CHARS + 1)
    suite = read_suite_dir(_suite(tmp_path, {"regex_must_not_match": [pattern]}))
    with pytest.raises(ValueError, match="too long"):
        run_suite(suite=suite, predictions_path=_preds(tmp_path, "x"))


def test_invalid_suite_pattern_is_rejected(tmp_path: Path) -> None:
    suite = read_suite_dir(_suite(tmp_path, {"regex_must_match": ["(unclosed"]}))
    with pytest.raises(ValueError, match="invalid regex"):
        run_suite(suite=suite, predictions_path=_preds(tmp_path, "x"))


def test_detectors_work_off_the_main_thread() -> None:
    """Detection must not install signal handlers (which fails off the main thread)."""
    errors: list[BaseException] = []
    results: list[dict[str, int]] = []

    def worker() -> None:
        try:
            results.append(detect_pii("mail test@example.com"))
            results.append(detect_secrets("AKIAIOSFODNN7EXAMPLE"))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=30)

    assert errors == []
    assert results[0]["email"] == 1
    assert results[1]["aws_access_key"] == 1


def test_plugin_hits_add_to_builtin_counts(tmp_path: Path, clean_registry: Any) -> None:
    """A plugin reusing a built-in name must not overwrite (hide) the built-in count."""
    clean_registry.register(
        DetectorPlugin(name="email-extra", kind="pii", detect=lambda t: {"email": 1})
    )
    suite = read_suite_dir(_suite(tmp_path, {"pii": {"enabled": True}}))

    report = run_suite(
        suite=suite, predictions_path=_preds(tmp_path, "a@example.com b@example.com")
    )

    assert report.cases[0]["pii"]["email"] == 3
    assert report.summary["pii_total_hits"] == 3
