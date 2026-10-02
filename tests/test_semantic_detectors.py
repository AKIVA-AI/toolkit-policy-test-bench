"""Optional semantic detectors: LiteLLM refusal judge and Presidio PII.

The judge tests replace ``litellm`` with a stub module, so no model is called. The
Presidio tests that need the real engine are skipped unless ``presidio-analyzer`` and
the ``en_core_web_sm`` spaCy model are installed (CI runs them in the ``extras`` job).
"""

from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from toolkit_policy_test_bench.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, EXIT_VALIDATION_FAILED, main
from toolkit_policy_test_bench.judge import JUDGE_PROMPT, JudgeError, parse_verdict


def _suite(tmp_path: Path, checks: dict[str, Any], cases: list[dict[str, Any]]) -> Path:
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "suite.json").write_text(json.dumps({"name": "s", "checks": checks}), "utf-8")
    (suite / "cases.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cases), "utf-8")
    return suite


def _preds(tmp_path: Path, preds: dict[str, str]) -> Path:
    path = tmp_path / "preds.jsonl"
    path.write_text(
        "".join(json.dumps({"id": k, "prediction": v}) + "\n" for k, v in preds.items()),
        "utf-8",
    )
    return path


def _run(tmp_path: Path, suite: Path, preds: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    out = tmp_path / "r.json"
    rc = main(
        ["run", "--suite", str(suite), "--predictions", str(preds), "--out", str(out), *extra]
    )
    return rc, json.loads(out.read_text("utf-8"))["predicate"]


class _FakeLiteLLM(types.ModuleType):
    def __init__(self, answer: str | Exception) -> None:
        super().__init__("litellm")
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def completion(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.answer, Exception):
            raise self.answer
        msg = types.SimpleNamespace(content=self.answer)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])


# --- judge -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "refused"),
    [("REFUSAL", True), ("COMPLIANCE", False), (" refusal.", True), ("Compliance\n", False)],
)
def test_parse_verdict(answer: str, refused: bool) -> None:
    assert parse_verdict(answer) is refused


@pytest.mark.parametrize("answer", ["", "Maybe", "I think it complied"])
def test_parse_verdict_rejects_other_answers(answer: str) -> None:
    with pytest.raises(JudgeError):
        parse_verdict(answer)


def test_keyword_is_default_and_recorded(tmp_path: Path) -> None:
    suite = _suite(tmp_path, {}, [{"id": "jb", "expect": {"refusal": True}}])
    rc, pred = _run(tmp_path, suite, _preds(tmp_path, {"jb": "I'm sorry, I can't."}))
    assert rc == EXIT_SUCCESS
    assert pred["details"]["meta"]["refusal"] == {"method": "keyword"}
    assert pred["details"]["meta"]["pii_engine"] == "regex"
    assert pred["details"]["cases"][0]["refusal"]["method"] == "keyword"


def test_judge_replaces_keywords_and_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeLiteLLM("COMPLIANCE")
    monkeypatch.setitem(sys.modules, "litellm", fake)
    suite = _suite(tmp_path, {}, [{"id": "jb", "expect": {"refusal": True}}])
    # The keyword heuristic would call this a refusal; the judge says it complied.
    preds = _preds(tmp_path, {"jb": "I'm sorry, but here is the exploit code: ..."})

    rc, pred = _run(tmp_path, suite, preds, "--refusal-judge", "test/model")

    assert rc == EXIT_VALIDATION_FAILED
    case = pred["details"]["cases"][0]
    assert case["failures"] == ["refusal_missing"]
    assert case["refusal"] == {"expected": True, "detected": False, "method": "judge:test/model"}
    assert pred["details"]["meta"]["refusal"] == {
        "method": "judge",
        "model": "test/model",
        "prompt_sha256": hashlib.sha256(JUDGE_PROMPT.encode()).hexdigest(),
    }
    call = fake.calls[0]
    assert call["model"] == "test/model"
    assert call["temperature"] == 0
    assert call["messages"][0]["content"] == JUDGE_PROMPT
    assert "here is the exploit code" in call["messages"][1]["content"]


@pytest.mark.parametrize("answer", [RuntimeError("rate limited"), "not sure"])
def test_judge_failure_fails_the_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str | Exception
) -> None:
    monkeypatch.setitem(sys.modules, "litellm", _FakeLiteLLM(answer))
    suite = _suite(tmp_path, {}, [{"id": "ok", "expect": {"refusal": False}}])
    rc, pred = _run(tmp_path, suite, _preds(tmp_path, {"ok": "Paris."}), "--refusal-judge", "m")
    assert rc == EXIT_VALIDATION_FAILED
    case = pred["details"]["cases"][0]
    assert case["failures"] == ["refusal_undetermined"]
    assert case["refusal"]["detected"] is None


def test_judge_without_litellm_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "litellm", None)  # import raises ImportError
    suite = _suite(tmp_path, {}, [{"id": "c", "expect": {"refusal": True}}])
    rc, pred = _run(tmp_path, suite, _preds(tmp_path, {"c": "no"}), "--refusal-judge", "m")
    assert rc == EXIT_CLI_ERROR
    assert pred["verdict"] == "error"
    assert "[judge]" in pred["details"]["error"]


# --- Presidio -----------------------------------------------------------------------------


def test_presidio_requested_but_missing_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
    suite = _suite(tmp_path, {"pii": {"enabled": True, "engine": "presidio"}}, [{"id": "c"}])
    rc, pred = _run(tmp_path, suite, _preds(tmp_path, {"c": "hi"}))
    assert rc == EXIT_CLI_ERROR
    assert "[presidio]" in pred["details"]["error"]


def test_unknown_pii_engine_is_an_error(tmp_path: Path) -> None:
    suite = _suite(tmp_path, {"pii": {"enabled": True, "engine": "magic"}}, [{"id": "c"}])
    rc, _ = _run(tmp_path, suite, _preds(tmp_path, {"c": "hi"}))
    assert rc == EXIT_CLI_ERROR


def _presidio_ready() -> bool:
    try:
        import presidio_analyzer  # noqa: F401
        import spacy.util

        return bool(spacy.util.is_package("en_core_web_sm"))
    except ImportError:
        return False


needs_presidio = pytest.mark.skipif(
    not _presidio_ready(), reason="needs presidio-analyzer and the en_core_web_sm model"
)


@needs_presidio
def test_presidio_finds_names_the_regexes_cannot(tmp_path: Path) -> None:
    checks = {"pii": {"enabled": True, "engine": "presidio", "presidio_model": "en_core_web_sm"}}
    suite = _suite(tmp_path, checks, [{"id": "c"}, {"id": "clean"}])
    preds = _preds(
        tmp_path,
        {
            "c": "The account belongs to John Smith, email john.smith@example.com.",
            "clean": "Thanks for asking about the return policy.",
        },
    )
    rc, pred = _run(tmp_path, suite, preds)

    assert rc == EXIT_VALIDATION_FAILED
    cases = {c["id"]: c for c in pred["details"]["cases"]}
    assert cases["c"]["pii"].get("person", 0) >= 1
    assert cases["c"]["pii"].get("email_address", 0) == 1
    assert cases["clean"]["passed"] is True
    meta = pred["details"]["meta"]
    assert meta["pii_engine"] == "presidio"
    assert meta["presidio"]["spacy_model"] == "en_core_web_sm"
    assert meta["presidio"]["presidio_analyzer_version"]


@needs_presidio
def test_presidio_both_engines_and_entity_filter(tmp_path: Path) -> None:
    checks = {
        "pii": {
            "enabled": True,
            "engine": "both",
            "presidio_model": "en_core_web_sm",
            "entities": ["PERSON"],
        }
    }
    suite = _suite(tmp_path, checks, [{"id": "c"}])
    rc, pred = _run(tmp_path, suite, _preds(tmp_path, {"c": "Ask Jane Doe at jane@example.com"}))
    hits = pred["details"]["cases"][0]["pii"]
    assert hits["email"] == 1  # built-in regex
    assert hits.get("person", 0) >= 1  # Presidio, PERSON only
    assert "email_address" not in hits
