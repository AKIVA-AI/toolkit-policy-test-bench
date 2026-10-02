"""Evidence summary per control, built from ``policy.run`` and ``policy.import`` reports.

Results are grouped by finding category, then attributed to every control the
category maps to in ``data/controls.json`` (a data file, not code). A control is
``fail`` when any mapped result failed or could not be judged, ``pass`` when it
was exercised with no failures, and ``not_tested`` otherwise. Results whose
category maps to no control are reported under ``unmapped`` and still count
against the gate, so nothing is dropped.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from .categories import UNCATEGORIZED, CategoryRules

CATEGORY_TAG = "category:"
SUPPORTED_KINDS = ("policy.run", "policy.import")


def _zero() -> dict[str, int]:
    return {"total": 0, "failed": 0, "errors": 0}


def _add(into: dict[str, int], other: dict[str, int]) -> None:
    for k in ("total", "failed", "errors"):
        into[k] += int(other.get(k, 0))


def load_controls(rules: CategoryRules, path: Path | None = None) -> dict[str, Any]:
    """Load and validate the control mapping against the known categories."""
    where = str(path) if path else "built-in controls.json"
    text = (
        path.read_text(encoding="utf-8")
        if path
        else resources.files("toolkit_policy_test_bench")
        .joinpath("data/controls.json")
        .read_text(encoding="utf-8")
    )
    try:
        doc: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{where}: not JSON: {exc}") from exc
    frameworks = doc.get("frameworks") if isinstance(doc, dict) else None
    mapping = doc.get("category_controls") if isinstance(doc, dict) else None
    if not isinstance(frameworks, dict) or not isinstance(mapping, dict):
        raise ValueError(f"{where}: needs 'frameworks' and 'category_controls' objects")
    for cat, per_fw in mapping.items():
        if cat not in rules.categories:
            raise ValueError(f"{where}: unknown category {cat!r} in category_controls")
        for fw, ids in (per_fw or {}).items():
            known = (frameworks.get(fw) or {}).get("controls") or {}
            for cid in ids:
                if cid not in known:
                    raise ValueError(f"{where}: {cat} -> {fw} {cid!r} is not a defined control")
    return doc


def _run_case_categories(case: dict[str, Any], rules: CategoryRules) -> dict[str, str]:
    """Category -> 'pass'/'fail' for one ``policy.run`` case result.

    A ``category:<name>`` tag assigns the whole case to that category. Otherwise the
    case counts as a test of each detector that ran on it (PII, secrets, refusal)
    and each failure code is categorized through the ``policy-test-bench`` rules.
    """
    tags = [
        str(t)[len(CATEGORY_TAG) :]
        for t in case.get("tags") or []
        if str(t).startswith(CATEGORY_TAG)
    ]
    for t in tags:
        if t not in rules.categories:
            raise ValueError(f"case {case.get('id')!r}: unknown category tag {t!r}")
    status = "pass" if case.get("passed") is True else "fail"
    if tags:
        return {t: status for t in tags}
    out: dict[str, str] = {}
    exercised = []
    if case.get("pii"):
        exercised.append("pii_detected")
    if case.get("secrets"):
        exercised.append("secret_detected")
    if "refusal" in case:
        exercised.append("refusal_missing")
    for code in exercised:
        out[rules.categorize("policy-test-bench", [code])] = "pass"
    for failure in case.get("failures") or []:
        code = str(failure).split(":", 1)[0]
        out[rules.categorize("policy-test-bench", [code])] = "fail"
    return out


def categories_from_report(env: dict[str, Any], rules: CategoryRules) -> dict[str, dict[str, int]]:
    """Per-category ``{total, failed, errors}`` for one report envelope."""
    pred = env.get("predicate") or {}
    kind = pred.get("kind")
    if pred.get("verdict") == "error":
        raise ValueError(f"{kind} report ended in an error and has no results")
    out: dict[str, dict[str, int]] = {}
    if kind == "policy.import":
        by_cat = (pred.get("summary") or {}).get("by_category")
        if not isinstance(by_cat, dict):
            raise ValueError("policy.import report has no summary.by_category")
        for cat, counts in by_cat.items():
            _add(out.setdefault(str(cat), _zero()), counts)
        return out
    if kind == "policy.run":
        cases = (pred.get("details") or {}).get("cases")
        if not isinstance(cases, list):
            raise ValueError("policy.run report has no details.cases")
        for case in cases:
            for cat, status in _run_case_categories(case, rules).items():
                c = out.setdefault(cat, _zero())
                c["total"] += 1
                if status == "fail":
                    c["failed"] += 1
        return out
    raise ValueError(f"unsupported report kind {kind!r}; expected one of {SUPPORTED_KINDS}")


def build_evidence(
    reports: list[tuple[dict[str, Any], dict[str, Any]]],
    controls: dict[str, Any],
    rules: CategoryRules,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(summary, details)`` for an evidence envelope.

    ``reports`` pairs each report's ``{name, digest}`` reference with its envelope.
    """
    mapping: dict[str, dict[str, list[str]]] = controls["category_controls"]
    frameworks: dict[str, Any] = controls["frameworks"]

    per_report: list[dict[str, Any]] = []
    totals: dict[str, dict[str, int]] = {}
    for ref, env in reports:
        cats = categories_from_report(env, rules)
        per_report.append({"report": ref, "kind": env["predicate"]["kind"], "categories": cats})
        for cat, counts in cats.items():
            _add(totals.setdefault(cat, _zero()), counts)

    control_rows: list[dict[str, Any]] = []
    for fw_id, fw in frameworks.items():
        for cid, meta in (fw.get("controls") or {}).items():
            cats = sorted(
                c for c, per_fw in mapping.items() if cid in (per_fw or {}).get(fw_id, [])
            )
            agg = _zero()
            sources = []
            for rep in per_report:
                hit = _zero()
                for cat in cats:
                    if cat in rep["categories"]:
                        _add(hit, rep["categories"][cat])
                if hit["total"]:
                    _add(agg, hit)
                    sources.append({"report": rep["report"]["name"], "kind": rep["kind"], **hit})
            if agg["total"] == 0:
                status = "not_tested"
            elif agg["failed"] or agg["errors"]:
                status = "fail"
            else:
                status = "pass"
            control_rows.append(
                {
                    "framework": fw_id,
                    "control": cid,
                    "name": (meta or {}).get("name", ""),
                    "categories": cats,
                    "status": status,
                    **agg,
                    "evidence": sources,
                }
            )

    unmapped = {
        cat: counts
        for cat, counts in sorted(totals.items())
        if cat == UNCATEGORIZED or not any((mapping.get(cat) or {}).values())
    }
    failed_results = sum(c["failed"] + c["errors"] for c in totals.values())
    summary = {
        "reports": len(reports),
        "controls": len(control_rows),
        "tested_controls": sum(1 for r in control_rows if r["status"] != "not_tested"),
        "failed_controls": sum(1 for r in control_rows if r["status"] == "fail"),
        "not_tested_controls": sum(1 for r in control_rows if r["status"] == "not_tested"),
        "failed_results": failed_results,
        "unmapped_failed_results": sum(c["failed"] + c["errors"] for c in unmapped.values()),
        "by_framework": {
            fw: {
                s: sum(1 for r in control_rows if r["framework"] == fw and r["status"] == s)
                for s in ("pass", "fail", "not_tested")
            }
            for fw in frameworks
        },
    }
    details = {
        "disclaimer": controls.get("disclaimer", ""),
        "frameworks": {
            fw: {"title": v.get("title", ""), "source": v.get("source", "")}
            for fw, v in frameworks.items()
        },
        "controls": control_rows,
        "categories": dict(sorted(totals.items())),
        "unmapped": unmapped,
        "reports": [{"report": r["report"], "kind": r["kind"]} for r in per_report],
    }
    return summary, details


def to_markdown(summary: dict[str, Any], details: dict[str, Any]) -> str:
    """Human-readable evidence table, one section per framework."""
    lines = ["# Control evidence", ""]
    lines.append(
        f"{summary['reports']} report(s); {summary['tested_controls']} of "
        f"{summary['controls']} controls exercised, {summary['failed_controls']} failing."
    )
    lines += ["", f"> {details['disclaimer']}", ""]
    for fw, meta in details["frameworks"].items():
        lines += [f"## {meta['title']}", "", f"Source: {meta['source']}", ""]
        lines += ["| Control | Status | Tested | Failed | Errors | Categories |"]
        lines += ["| ------- | ------ | -----: | -----: | -----: | ---------- |"]
        for row in details["controls"]:
            if row["framework"] != fw:
                continue
            label = f"{row['control']} {row['name']}".strip()
            lines.append(
                f"| {label} | {row['status']} | {row['total']} | {row['failed']} | "
                f"{row['errors']} | {', '.join(row['categories'])} |"
            )
        lines.append("")
    if details["unmapped"]:
        lines += ["## Results with no mapped control", ""]
        for cat, c in details["unmapped"].items():
            lines.append(
                f"- `{cat}`: {c['total']} tested, {c['failed']} failed, {c['errors']} errors"
            )
        lines.append("")
    return "\n".join(lines)
