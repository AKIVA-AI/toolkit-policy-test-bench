"""`run --patterns FILE` loads custom regex detectors from the CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from toolkit_policy_test_bench.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, EXIT_VALIDATION_FAILED, main
from toolkit_policy_test_bench.plugins import registry


def _setup(tmp_path: Path, checks: dict[str, Any], pred: str) -> tuple[Path, Path]:
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "suite.json").write_text(json.dumps({"name": "p", "checks": checks}), "utf-8")
    (suite / "cases.jsonl").write_text(json.dumps({"id": "c"}) + "\n", "utf-8")
    preds = tmp_path / "preds.jsonl"
    preds.write_text(json.dumps({"id": "c", "prediction": pred}) + "\n", "utf-8")
    return suite, preds


def _patterns(tmp_path: Path, name: str, detectors: list[dict[str, str]]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"detectors": detectors}), "utf-8")
    return path


def _run(tmp_path: Path, suite: Path, preds: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    out = tmp_path / "r.json"
    rc = main(
        ["run", "--suite", str(suite), "--predictions", str(preds), "--out", str(out), *extra]
    )
    return rc, json.loads(out.read_text("utf-8"))


def test_patterns_file_adds_detectors_and_is_recorded(tmp_path: Path) -> None:
    suite, preds = _setup(
        tmp_path,
        {"pii": {"enabled": True}, "secrets": {"enabled": True}},
        "Patient MRN-12345678, internal token ACME-SECRET-abcdef",
    )
    pii = _patterns(tmp_path, "pii.json", [{"name": "mrn", "kind": "pii", "pattern": r"MRN-\d{8}"}])
    sec = _patterns(
        tmp_path,
        "secrets.json",
        [{"name": "acme_token", "kind": "secret", "pattern": r"ACME-SECRET-[a-f0-9]{6}"}],
    )

    rc, env = _run(tmp_path, suite, preds, "--patterns", str(pii), "--patterns", str(sec))

    assert rc == EXIT_VALIDATION_FAILED
    pred = env["predicate"]
    case = pred["details"]["cases"][0]
    assert case["pii"]["mrn"] == 1
    assert case["secrets"]["acme_token"] == 1
    assert case["failures"] == ["pii_detected", "secret_detected"]
    inputs = {i["name"]: i["digest"]["sha256"] for i in pred["inputs"]}
    assert inputs["pii.json"] == hashlib.sha256(pii.read_bytes()).hexdigest()
    assert inputs["secrets.json"] == hashlib.sha256(sec.read_bytes()).hexdigest()
    assert pred["details"]["meta"]["custom_detectors"] == [
        {"name": "mrn", "kind": "pii", "pattern": r"MRN-\d{8}", "file": "pii.json"},
        {
            "name": "acme_token",
            "kind": "secret",
            "pattern": r"ACME-SECRET-[a-f0-9]{6}",
            "file": "secrets.json",
        },
    ]
    # The CLI uses its own registry; the process-wide one is untouched.
    assert registry.detectors == []


def test_patterns_do_nothing_when_detection_is_off(tmp_path: Path) -> None:
    suite, preds = _setup(tmp_path, {}, "MRN-12345678")
    pats = _patterns(tmp_path, "p.json", [{"name": "mrn", "kind": "pii", "pattern": r"MRN-\d{8}"}])
    rc, _ = _run(tmp_path, suite, preds, "--patterns", str(pats))
    assert rc == EXIT_SUCCESS


def test_bad_pattern_files_are_errors(tmp_path: Path) -> None:
    suite, preds = _setup(tmp_path, {"pii": {"enabled": True}}, "x")
    cases = {
        "invalid_regex.json": [{"name": "a", "kind": "pii", "pattern": "("}],
        "bad_kind.json": [{"name": "a", "kind": "phi", "pattern": "x"}],
        "missing_field.json": [{"name": "a", "pattern": "x"}],
    }
    for name, detectors in cases.items():
        rc, env = _run(
            tmp_path, suite, preds, "--patterns", str(_patterns(tmp_path, name, detectors))
        )
        assert rc == EXIT_CLI_ERROR, name
        assert env["predicate"]["verdict"] == "error"

    dup1 = _patterns(tmp_path, "d1.json", [{"name": "same", "kind": "pii", "pattern": "x"}])
    dup2 = _patterns(tmp_path, "d2.json", [{"name": "same", "kind": "pii", "pattern": "y"}])
    rc, _ = _run(tmp_path, suite, preds, "--patterns", str(dup1), "--patterns", str(dup2))
    assert rc == EXIT_CLI_ERROR

    rc, _ = _run(tmp_path, suite, preds, "--patterns", str(tmp_path / "missing.json"))
    assert rc == EXIT_CLI_ERROR
