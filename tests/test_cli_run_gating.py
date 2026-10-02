"""`toolkit-policy run` gates on findings and verifies packs before running."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from toolkit_policy_test_bench.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILED,
    main,
)
from toolkit_policy_test_bench.pack import create_pack


def _suite(tmp_path: Path, checks: dict[str, Any] | None = None) -> Path:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "gating",
                "description": "",
                "created_at": "",
                "checks": checks
                if checks is not None
                else {"must_not_contain": ["password"], "pii": {"enabled": True}},
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        json.dumps({"id": "c1", "input": "", "tags": []}) + "\n", encoding="utf-8"
    )
    return suite_dir


def _preds(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    path = tmp_path / "preds.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def _run(suite: Path, preds: Path, *extra: str) -> int:
    return main(["run", "--suite", str(suite), "--predictions", str(preds), *extra])


def test_run_exits_zero_when_all_cases_pass(tmp_path: Path) -> None:
    rc = _run(_suite(tmp_path), _preds(tmp_path, [{"id": "c1", "prediction": "fine"}]))
    assert rc == EXIT_SUCCESS


def test_run_exits_nonzero_on_failed_case_and_still_writes_report(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    rc = _run(
        _suite(tmp_path),
        _preds(tmp_path, [{"id": "c1", "prediction": "the password is x"}]),
        "--out",
        str(out),
    )
    assert rc == EXIT_VALIDATION_FAILED
    assert json.loads(out.read_text(encoding="utf-8"))["predicate"]["summary"]["failed_cases"] == 1


def test_run_exits_nonzero_on_pii(tmp_path: Path) -> None:
    rc = _run(_suite(tmp_path), _preds(tmp_path, [{"id": "c1", "prediction": "a@example.com"}]))
    assert rc == EXIT_VALIDATION_FAILED


def test_run_exits_nonzero_on_missing_prediction(tmp_path: Path) -> None:
    rc = _run(_suite(tmp_path), _preds(tmp_path, []))
    assert rc == EXIT_VALIDATION_FAILED


def _tamper(pack: Path, member: str, content: str) -> None:
    with zipfile.ZipFile(pack) as zf:
        entries = {n: zf.read(n) for n in zf.namelist()}
    entries[member] = content.encode("utf-8")
    with zipfile.ZipFile(pack, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def test_run_verifies_pack_before_running(tmp_path: Path) -> None:
    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    preds = _preds(tmp_path, [{"id": "c1", "prediction": "fine"}])
    assert _run(pack, preds) == EXIT_SUCCESS

    # Loosen the checks inside the pack without updating the manifest.
    _tamper(pack, "suite.json", json.dumps({"name": "gating", "checks": {}}))
    out = tmp_path / "report.json"
    rc = _run(pack, preds, "--out", str(out))

    assert rc == EXIT_VALIDATION_FAILED
    # Nothing ran: the report records an error verdict and no case results.
    predicate = json.loads(out.read_text(encoding="utf-8"))["predicate"]
    assert predicate["verdict"] == "error"
    assert predicate["summary"] == {}
    assert "cases" not in predicate["details"]


def test_run_rejects_pack_without_manifest(tmp_path: Path) -> None:
    pack = tmp_path / "suite.zip"
    suite_dir = _suite(tmp_path)
    with zipfile.ZipFile(pack, "w") as zf:
        zf.write(suite_dir / "suite.json", arcname="suite.json")
        zf.write(suite_dir / "cases.jsonl", arcname="cases.jsonl")

    rc = _run(pack, _preds(tmp_path, [{"id": "c1", "prediction": "fine"}]))
    assert rc == EXIT_VALIDATION_FAILED


def test_run_signature_flags_must_be_paired(tmp_path: Path) -> None:
    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    rc = _run(
        pack,
        _preds(tmp_path, [{"id": "c1", "prediction": "fine"}]),
        "--signature",
        str(tmp_path / "sig.json"),
    )
    assert rc == EXIT_CLI_ERROR


def test_run_verifies_signature_when_given(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    preds = _preds(tmp_path, [{"id": "c1", "prediction": "fine"}])

    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    other_priv, other_pub = tmp_path / "priv2.pem", tmp_path / "pub2.pem"
    sig = tmp_path / "sig.json"
    assert main(["keygen", "--private-key", str(priv), "--public-key", str(pub)]) == 0
    assert main(["keygen", "--private-key", str(other_priv), "--public-key", str(other_pub)]) == 0
    assert (
        main(["pack", "sign", "--suite", str(pack), "--private-key", str(priv), "--out", str(sig)])
        == 0
    )

    ok = _run(pack, preds, "--signature", str(sig), "--public-key", str(pub))
    wrong_key = _run(pack, preds, "--signature", str(sig), "--public-key", str(other_pub))

    assert ok == EXIT_SUCCESS
    assert wrong_key == EXIT_VALIDATION_FAILED


def test_run_rejects_manifest_that_omits_suite_files(tmp_path: Path) -> None:
    """A manifest listing no files must not let a rewritten suite through."""
    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=_suite(tmp_path), out_zip=pack)
    _tamper(pack, "manifest.json", json.dumps({"version": 1, "files": {}}))

    rc = _run(pack, _preds(tmp_path, [{"id": "c1", "prediction": "fine"}]))
    assert rc == EXIT_VALIDATION_FAILED
