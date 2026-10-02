"""Report envelope v1 (in-toto Statement v1) is the default JSON output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from toolkit_policy_test_bench.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILED,
    main,
)
from toolkit_policy_test_bench.envelope import (
    build_envelope,
    canonical_bytes,
    validate_envelope,
)
from toolkit_policy_test_bench.pack import create_pack

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _suite(tmp_path: Path) -> Path:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "env",
                "checks": {"must_not_contain": ["password"], "secrets": {"enabled": True}},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "hi", "tags": ["t"]}) + "\n", encoding="utf-8"
    )
    return suite_dir


def _preds(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "preds.jsonl"
    path.write_text(json.dumps({"id": "c1", "prediction": text}) + "\n", encoding="utf-8")
    return path


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_bytes().decode("utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- envelope primitives ------------------------------------------------------------


def test_canonical_bytes_are_sorted_compact_with_trailing_newline() -> None:
    assert canonical_bytes({"b": 1, "a": [1, {"d": 2, "c": "é"}]}) == (
        '{"a":[1,{"c":"é","d":2}],"b":1}\n'.encode()
    )


def test_build_envelope_rejects_verdict_exit_code_mismatch() -> None:
    subject = [{"name": "x", "digest": {"sha256": "0" * 64}}]
    with pytest.raises(ValueError):
        build_envelope(kind="policy.run", verdict="pass", exit_code=4, subject=subject)
    with pytest.raises(ValueError):
        build_envelope(kind="policy.run", verdict="error", exit_code=0, subject=subject)
    with pytest.raises(ValueError):
        build_envelope(kind="policy.run", verdict="maybe", exit_code=1, subject=subject)


def test_schema_rejects_error_verdict_with_exit_zero() -> None:
    env = build_envelope(
        kind="policy.run",
        verdict="fail",
        exit_code=4,
        subject=[{"name": "x", "digest": {"sha256": "0" * 64}}],
    )
    jsonschema.validate(env, _schema())
    env["predicate"]["verdict"] = "error"
    env["predicate"]["exit_code"] = 0
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(env, _schema())
    assert "verdict_exit_code_mismatch" in validate_envelope(env)


# --- run -----------------------------------------------------------------------------


def test_run_out_writes_canonical_schema_valid_envelope(tmp_path: Path) -> None:
    suite = _suite(tmp_path)
    preds = _preds(tmp_path, "all good")
    out = tmp_path / "report.json"

    rc = main(["run", "--suite", str(suite), "--predictions", str(preds), "--out", str(out)])

    assert rc == EXIT_SUCCESS
    raw = out.read_bytes()
    env = json.loads(raw)
    assert raw == canonical_bytes(env)  # canonical form, so the SHA-256 is stable
    jsonschema.validate(env, _schema())
    assert validate_envelope(env) == []
    assert env["_type"] == "https://in-toto.io/Statement/v1"
    assert env["predicateType"] == (
        "https://github.com/AKIVA-AI/toolkit-policy-test-bench/report/v1"
    )
    pred = env["predicate"]
    assert pred["tool"]["name"] == "toolkit-policy-test-bench"
    assert pred["kind"] == "policy.run"
    assert (pred["verdict"], pred["exit_code"]) == ("pass", 0)
    # The predictions file is what was evaluated; its digest is the file's SHA-256.
    assert env["subject"] == [{"name": "preds.jsonl", "digest": {"sha256": _sha(preds)}}]
    input_digests = {i["name"]: i["digest"]["sha256"] for i in pred["inputs"]}
    assert input_digests["suite.json"] == _sha(suite / "suite.json")
    assert input_digests["cases.jsonl"] == _sha(suite / "cases.jsonl")
    assert pred["summary"]["cases"] == 1
    assert pred["summary"]["failed_cases"] == 0
    assert pred["details"]["cases"][0]["id"] == "c1"
    assert pred["details"]["suite"]["name"] == "env"


def test_run_fail_verdict_matches_exit_code(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--suite",
            str(_suite(tmp_path)),
            "--predictions",
            str(_preds(tmp_path, "the password is hunter2")),
            "--out",
            str(out),
        ]
    )
    assert rc == EXIT_VALIDATION_FAILED
    pred = _load(out)["predicate"]
    assert (pred["verdict"], pred["exit_code"]) == ("fail", EXIT_VALIDATION_FAILED)
    assert pred["summary"]["failed_cases"] == 1


def test_run_pack_input_is_the_zip_digest(tmp_path: Path) -> None:
    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--suite",
            str(pack),
            "--predictions",
            str(_preds(tmp_path, "ok")),
            "--out",
            str(out),
        ]
    )
    assert rc == EXIT_SUCCESS
    inputs = _load(out)["predicate"]["inputs"]
    assert {"name": "suite.zip", "digest": {"sha256": _sha(pack)}} in inputs


def test_run_tampered_pack_writes_error_envelope(tmp_path: Path) -> None:
    import zipfile

    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(pack) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "cases.jsonl":
                data = data.replace(b"hi", b"HI")
            dst.writestr(item, data)
    out = tmp_path / "report.json"

    rc = main(
        [
            "run",
            "--suite",
            str(tampered),
            "--predictions",
            str(_preds(tmp_path, "ok")),
            "--out",
            str(out),
        ]
    )

    assert rc == EXIT_VALIDATION_FAILED
    env = _load(out)
    jsonschema.validate(env, _schema())
    assert (env["predicate"]["verdict"], env["predicate"]["exit_code"]) == (
        "error",
        EXIT_VALIDATION_FAILED,
    )
    assert "pack" in env["predicate"]["details"]["error"]


def test_run_bad_predictions_writes_error_envelope(tmp_path: Path) -> None:
    preds = tmp_path / "preds.jsonl"
    preds.write_text("{not json\n", encoding="utf-8")
    out = tmp_path / "report.json"

    rc = main(
        ["run", "--suite", str(_suite(tmp_path)), "--predictions", str(preds), "--out", str(out)]
    )

    assert rc == EXIT_CLI_ERROR
    pred = _load(out)["predicate"]
    assert (pred["verdict"], pred["exit_code"]) == ("error", EXIT_CLI_ERROR)
    assert pred["summary"] == {}


def test_run_legacy_json_flag_keeps_old_shape(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--suite",
            str(_suite(tmp_path)),
            "--predictions",
            str(_preds(tmp_path, "ok")),
            "--out",
            str(out),
            "--legacy-json",
        ]
    )
    assert rc == EXIT_SUCCESS
    obj = _load(out)
    assert set(obj) == {"suite", "summary", "cases"}


def test_run_stdout_json_is_the_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        ["run", "--suite", str(_suite(tmp_path)), "--predictions", str(_preds(tmp_path, "ok"))]
    )
    assert rc == EXIT_SUCCESS
    env = json.loads(capsys.readouterr().out)
    assert env["predicate"]["kind"] == "policy.run"


# --- validate-report and compare accept envelopes -------------------------------------


def _run_to(tmp_path: Path, name: str, text: str) -> Path:
    sub = tmp_path / name
    sub.mkdir()
    out = sub / "report.json"
    main(
        [
            "run",
            "--suite",
            str(_suite(sub)),
            "--predictions",
            str(_preds(sub, text)),
            "--out",
            str(out),
        ]
    )
    return out


def test_validate_report_accepts_envelope_and_rejects_mismatch(tmp_path: Path) -> None:
    report = _run_to(tmp_path, "a", "ok")
    assert main(["validate-report", "--report", str(report)]) == EXIT_SUCCESS

    env = _load(report)
    env["predicate"]["exit_code"] = 4  # verdict stays "pass"
    bad = tmp_path / "bad.json"
    bad.write_bytes(canonical_bytes(env))
    assert main(["validate-report", "--report", str(bad)]) == EXIT_VALIDATION_FAILED


def test_compare_reads_envelopes_and_writes_compare_envelope(tmp_path: Path) -> None:
    baseline = _run_to(tmp_path, "base", "ok")
    candidate = _run_to(tmp_path, "cand", "the password is x")
    out = tmp_path / "compare.json"

    rc = main(
        ["compare", "--baseline", str(baseline), "--candidate", str(candidate), "--out", str(out)]
    )

    assert rc == EXIT_VALIDATION_FAILED
    env = _load(out)
    jsonschema.validate(env, _schema())
    pred = env["predicate"]
    assert pred["kind"] == "policy.compare"
    assert (pred["verdict"], pred["exit_code"]) == ("fail", EXIT_VALIDATION_FAILED)
    assert pred["summary"]["failures"] == ["fail_rate_regression"]
    assert env["subject"] == [{"name": "report.json", "digest": {"sha256": _sha(candidate)}}]
    assert [i["digest"]["sha256"] for i in pred["inputs"]] == [_sha(baseline), _sha(candidate)]


def test_compare_refuses_an_error_report(tmp_path: Path) -> None:
    """An error report has no results, so it must never compare as clean."""
    baseline = _run_to(tmp_path, "base", "ok")
    preds = tmp_path / "bad.jsonl"
    preds.write_text("{not json\n", encoding="utf-8")
    errored = tmp_path / "errored.json"
    main(
        [
            "run",
            "--suite",
            str(baseline.parent / "suite"),
            "--predictions",
            str(preds),
            "--out",
            str(errored),
        ]
    )
    assert _load(errored)["predicate"]["verdict"] == "error"

    rc = main(["compare", "--baseline", str(baseline), "--candidate", str(errored)])

    assert rc == EXIT_CLI_ERROR


def test_compare_refuses_summary_without_compared_numbers(tmp_path: Path) -> None:
    baseline = _run_to(tmp_path, "base", "ok")
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"suite": {}, "summary": {}, "cases": []}), encoding="utf-8")
    assert main(["compare", "--baseline", str(baseline), "--candidate", str(bare)]) == (
        EXIT_CLI_ERROR
    )
