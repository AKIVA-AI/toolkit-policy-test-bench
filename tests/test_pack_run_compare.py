from __future__ import annotations

import json
from pathlib import Path

from toolkit_policy_test_bench.compare import CompareBudget, compare_reports
from toolkit_policy_test_bench.pack import create_pack, load_suite_from_path
from toolkit_policy_test_bench.runner import run_suite


def test_pack_run_and_compare(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "demo",
                "description": "demo suite",
                "created_at": "2025-12-14T00:00:00Z",
                "checks": {
                    "pii": {"enabled": True},
                    "secrets": {"enabled": True},
                    "must_not_contain": ["password"],
                    "json_schema": {
                        "required_keys": ["status"],
                        "optional_keys": [],
                        "allow_extra_keys": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    (suite_dir / "cases.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"id": "c1", "input": {"messages": []}, "tags": ["t"]}),
                json.dumps({"id": "c2", "input": {"messages": []}, "tags": ["t"]}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    pack = tmp_path / "suite.zip"
    create_pack(suite_dir=suite_dir, out_zip=pack)
    suite = load_suite_from_path(pack)

    good = tmp_path / "good.jsonl"
    good.write_text(
        "\n".join(
            [
                json.dumps({"id": "c1", "prediction": json.dumps({"status": "ok"})}),
                json.dumps({"id": "c2", "prediction": json.dumps({"status": "ok"})}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bad = tmp_path / "bad.jsonl"
    bad.write_text(
        "\n".join(
            [
                json.dumps({"id": "c1", "prediction": "email me at test@example.com"}),
                json.dumps({"id": "c2", "prediction": "password is hunter2"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    baseline = run_suite(suite=suite, predictions_path=good)
    candidate = run_suite(suite=suite, predictions_path=bad)

    result = compare_reports(
        baseline=baseline,
        candidate=candidate,
        budget=CompareBudget(
            max_fail_rate_increase_pct=0.0,
            max_pii_hits_increase=0,
            max_secret_hits_increase=0,
        ),
    )
    assert result["passed"] is False

