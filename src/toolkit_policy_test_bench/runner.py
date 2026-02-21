from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .detectors import detect_pii, detect_secrets
from .json_schema import JSONSchema, parse_json_from_prediction, parse_json_schema, validate_json
from .report import PolicyReport
from .suite import PolicySuite


def _read_predictions(path: Path) -> dict[str, str]:
    preds: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        preds[str(obj["id"])] = str(obj.get("prediction") or "")
    return preds


def _lower_if(text: str, enabled: bool) -> str:
    return text.lower() if enabled else text


def run_suite(*, suite: PolicySuite, predictions_path: Path) -> PolicyReport:
    predictions = _read_predictions(predictions_path)
    cfg = suite.checks

    max_output_chars = int(cfg.get("max_output_chars", 0)) if cfg.get("max_output_chars") else 0
    must_contain = [str(x) for x in cfg.get("must_contain", [])]
    must_not_contain = [str(x) for x in cfg.get("must_not_contain", [])]
    regex_must_match = [str(x) for x in cfg.get("regex_must_match", [])]
    regex_must_not_match = [str(x) for x in cfg.get("regex_must_not_match", [])]
    case_insensitive = bool(cfg.get("case_insensitive", True))

    schema: JSONSchema | None = None
    if cfg.get("json_schema"):
        schema = parse_json_schema(dict(cfg.get("json_schema") or {}))

    enable_pii = bool((cfg.get("pii") or {}).get("enabled", False))
    enable_secrets = bool((cfg.get("secrets") or {}).get("enabled", False))

    case_results: list[dict[str, Any]] = []
    total = 0
    failed = 0
    pii_total = 0
    secret_total = 0

    for case in suite.cases:
        pred = predictions.get(case.id, "")

        failures: list[str] = []
        pred_cmp = _lower_if(pred, case_insensitive)

        for s in must_contain:
            if _lower_if(s, case_insensitive) not in pred_cmp:
                failures.append(f"missing:{s}")

        for s in must_not_contain:
            if _lower_if(s, case_insensitive) in pred_cmp:
                failures.append(f"forbidden:{s}")

        for pat in regex_must_match:
            if not re.search(pat, pred):
                failures.append(f"regex_missing:{pat}")

        for pat in regex_must_not_match:
            if re.search(pat, pred):
                failures.append(f"regex_forbidden:{pat}")

        if max_output_chars and len(pred) > max_output_chars:
            failures.append("too_long")

        pii_hits: dict[str, int] = {}
        secret_hits: dict[str, int] = {}

        if enable_pii:
            pii_hits = detect_pii(pred)
            pii_total += sum(pii_hits.values())
            if sum(pii_hits.values()) > 0:
                failures.append("pii_detected")

        if enable_secrets:
            secret_hits = detect_secrets(pred)
            secret_total += sum(secret_hits.values())
            if sum(secret_hits.values()) > 0:
                failures.append("secret_detected")

        json_check = {"enabled": schema is not None, "valid": None, "reasons": []}
        if schema is not None:
            ok, obj = parse_json_from_prediction(pred)
            if not ok:
                json_check = {"enabled": True, "valid": False, "reasons": ["invalid_json"]}
                failures.append("invalid_json")
            else:
                valid, reasons = validate_json(obj, schema)
                json_check = {"enabled": True, "valid": valid, "reasons": reasons}
                if not valid:
                    failures.append("json_schema_failed")

        passed = not failures
        if not passed:
            failed += 1

        case_results.append(
            {
                "id": case.id,
                "tags": list(case.tags),
                "passed": passed,
                "failures": failures,
                "pii": pii_hits,
                "secrets": secret_hits,
                "json": json_check,
            }
        )
        total += 1

    fail_rate = (failed / total) if total else 0.0
    summary = {
        "cases": total,
        "failed_cases": failed,
        "fail_rate": fail_rate,
        "pii_total_hits": pii_total,
        "secret_total_hits": secret_total,
    }
    return PolicyReport(suite=suite.to_dict(), summary=summary, cases=case_results)
