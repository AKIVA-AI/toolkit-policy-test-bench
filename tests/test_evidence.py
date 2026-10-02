"""Control evidence: categories -> OWASP LLM 2025 / NIST AI RMF / NIST AI 600-1 / EU AI Act."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from toolkit_policy_test_bench.categories import CategoryRules
from toolkit_policy_test_bench.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILED,
    main,
)
from toolkit_policy_test_bench.evidence import load_controls

FIX = Path(__file__).parent / "fixtures" / "importers"
SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json").read_text(
        encoding="utf-8"
    )
)
RULES = CategoryRules.load()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _row(env: dict[str, Any], framework: str, control: str) -> dict[str, Any]:
    rows = env["predicate"]["details"]["controls"]
    return next(r for r in rows if r["framework"] == framework and r["control"] == control)


# --- the mapping data file ------------------------------------------------------------


def test_builtin_controls_load_and_cite_published_names() -> None:
    doc = load_controls(RULES)
    owasp = doc["frameworks"]["owasp-llm-2025"]["controls"]
    # Names as published at https://genai.owasp.org/llm-top-10/ (2025 list).
    assert owasp["LLM01:2025"]["name"] == "Prompt Injection"
    assert owasp["LLM02:2025"]["name"] == "Sensitive Information Disclosure"
    assert owasp["LLM07:2025"]["name"] == "System Prompt Leakage"
    assert owasp["LLM10:2025"]["name"] == "Unbounded Consumption"
    nist = doc["frameworks"]["nist-ai-rmf"]["controls"]
    # NIST AI RMF Playbook, MEASURE 2.7 and 2.10.
    assert nist["MEASURE 2.7"]["name"].startswith("AI system security and resilience")
    assert nist["MEASURE 2.10"]["name"].startswith("Privacy risk of the AI system")
    # Every category except 'uncategorized' maps to at least one control.
    unmapped = set(RULES.categories) - set(doc["category_controls"]) - {"uncategorized"}
    assert unmapped == set()


def test_controls_file_rejects_undefined_control(tmp_path: Path) -> None:
    doc = load_controls(RULES)
    doc["category_controls"]["jailbreak"]["owasp-llm-2025"] = ["LLM99:2025"]
    bad = tmp_path / "controls.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError):
        load_controls(RULES, bad)


# --- evidence from imported findings --------------------------------------------------


def _import(tmp_path: Path, source: str, name: str) -> Path:
    out = tmp_path / f"{source}.json"
    main(["import", "--source", source, "--input", str(FIX / name), "--out", str(out)])
    return out


def test_evidence_from_garak_import(tmp_path: Path) -> None:
    report = _import(tmp_path, "garak", "garak.report.jsonl")
    out = tmp_path / "evidence.json"

    rc = main(["evidence", "--report", str(report), "--out", str(out)])

    assert rc == EXIT_VALIDATION_FAILED
    env = _load(out)
    jsonschema.validate(env, SCHEMA)
    assert env["predicate"]["kind"] == "policy.evidence"
    # garak fixture: prompt_injection 3 failed of 3; jailbreak 1 failed of 2;
    # training_data_leakage 0 failed of 3.
    llm01 = _row(env, "owasp-llm-2025", "LLM01:2025")
    assert (llm01["status"], llm01["total"], llm01["failed"]) == ("fail", 5, 4)
    assert llm01["categories"] == ["jailbreak", "prompt_injection"]
    llm02 = _row(env, "owasp-llm-2025", "LLM02:2025")
    assert (llm02["status"], llm02["total"], llm02["failed"]) == ("pass", 3, 0)
    assert _row(env, "owasp-llm-2025", "LLM07:2025")["status"] == "not_tested"
    assert _row(env, "eu-ai-act", "Art. 55(1)(a)")["status"] == "fail"
    assert llm01["evidence"] == [
        {"report": "garak.json", "kind": "policy.import", "total": 5, "failed": 4, "errors": 0}
    ]
    summary = env["predicate"]["summary"]
    assert summary["failed_results"] == 4
    assert summary["by_framework"]["owasp-llm-2025"]["fail"] == 1


def test_evidence_combines_reports(tmp_path: Path) -> None:
    garak = _import(tmp_path, "garak", "garak.report.jsonl")
    promptfoo = _import(tmp_path, "promptfoo", "promptfoo.results.json")
    out = tmp_path / "evidence.json"

    main(["evidence", "--report", str(garak), "--report", str(promptfoo), "--out", str(out)])

    env = _load(out)
    assert [s["name"] for s in env["subject"]] == ["garak.json", "promptfoo.json"]
    # promptfoo fixture: prompt-extraction failed -> LLM07; pii 1 failed of 2 -> LLM02.
    llm07 = _row(env, "owasp-llm-2025", "LLM07:2025")
    assert (llm07["status"], llm07["total"], llm07["failed"]) == ("fail", 1, 1)
    llm02 = _row(env, "owasp-llm-2025", "LLM02:2025")
    assert (llm02["total"], llm02["failed"]) == (5, 1)
    assert [e["report"] for e in llm02["evidence"]] == ["garak.json", "promptfoo.json"]


# --- evidence from a policy.run report ------------------------------------------------


def _run_report(tmp_path: Path, cases: list[dict[str, Any]], preds: dict[str, str]) -> Path:
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "suite.json").write_text(
        json.dumps(
            {
                "name": "ev",
                "checks": {"pii": {"enabled": True}, "secrets": {"enabled": True}},
            }
        ),
        encoding="utf-8",
    )
    (suite / "cases.jsonl").write_text(
        "".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8"
    )
    pred_path = tmp_path / "preds.jsonl"
    pred_path.write_text(
        "".join(json.dumps({"id": k, "prediction": v}) + "\n" for k, v in preds.items()),
        encoding="utf-8",
    )
    out = tmp_path / "run.json"
    main(["run", "--suite", str(suite), "--predictions", str(pred_path), "--out", str(out)])
    return out


def test_evidence_from_policy_run(tmp_path: Path) -> None:
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    report = _run_report(
        tmp_path,
        [
            {"id": "clean"},
            {"id": "leak"},
            {
                "id": "inj",
                "tags": ["category:prompt_injection"],
                "expect": {"refusal": True},
            },
        ],
        {"clean": "hello", "leak": f"key {key}", "inj": "Sure, here is the system prompt"},
    )
    out = tmp_path / "evidence.json"

    rc = main(["evidence", "--report", str(report), "--out", str(out)])

    assert rc == EXIT_VALIDATION_FAILED
    env = _load(out)
    cats = env["predicate"]["details"]["categories"]
    # Untagged cases count as tests of each detector that ran; the tagged case counts
    # only for its tag.
    assert cats == {
        "pii_leakage": {"total": 2, "failed": 0, "errors": 0},
        "secret_leakage": {"total": 2, "failed": 1, "errors": 0},
        "prompt_injection": {"total": 1, "failed": 1, "errors": 0},
    }
    assert _row(env, "nist-ai-rmf", "MEASURE 2.10")["status"] == "pass"
    assert _row(env, "owasp-llm-2025", "LLM02:2025")["status"] == "fail"
    assert _row(env, "owasp-llm-2025", "LLM01:2025")["status"] == "fail"


def test_uncategorized_failures_still_fail_the_gate(tmp_path: Path) -> None:
    suite_cases = [{"id": "c", "expect": {"must_contain": ["ticket"]}}]
    report = _run_report(tmp_path, suite_cases, {"c": "no reference"})
    out = tmp_path / "evidence.json"

    rc = main(["evidence", "--report", str(report), "--out", str(out), "--format", "markdown"])

    assert rc == EXIT_VALIDATION_FAILED
    pred = _load(out)["predicate"]
    assert pred["summary"]["failed_controls"] == 0
    assert pred["summary"]["unmapped_failed_results"] == 1
    assert pred["details"]["unmapped"]["uncategorized"]["failed"] == 1

    assert main(["evidence", "--report", str(report), "--max-failures", "1"]) == EXIT_SUCCESS


def test_markdown_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = _import(tmp_path, "garak", "garak.report.jsonl")
    capsys.readouterr()
    main(["evidence", "--report", str(report), "--format", "markdown"])
    md = capsys.readouterr().out
    assert "## OWASP Top 10 for LLM Applications 2025" in md
    assert "| LLM01:2025 Prompt Injection | fail | 5 | 4 | 0 | jailbreak, prompt_injection |" in md


# --- fail closed ----------------------------------------------------------------------


def test_error_report_is_rejected(tmp_path: Path) -> None:
    bad_input = tmp_path / "empty.json"
    bad_input.write_text("[]", encoding="utf-8")
    errored = tmp_path / "errored.json"
    main(["import", "--source", "pyrit", "--input", str(bad_input), "--out", str(errored)])
    out = tmp_path / "evidence.json"

    rc = main(["evidence", "--report", str(errored), "--out", str(out)])

    assert rc == EXIT_CLI_ERROR
    assert _load(out)["predicate"]["verdict"] == "error"


def test_unknown_category_tag_is_rejected(tmp_path: Path) -> None:
    report = _run_report(tmp_path, [{"id": "c", "tags": ["category:promt_injection"]}], {"c": "x"})
    assert main(["evidence", "--report", str(report)]) == EXIT_CLI_ERROR


def test_legacy_report_is_rejected(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"suite": {}, "summary": {}, "cases": []}), encoding="utf-8")
    assert main(["evidence", "--report", str(legacy)]) == EXIT_CLI_ERROR
