from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .envelope import STATEMENT_TYPE


@dataclass(frozen=True)
class PolicyReport:
    suite: dict[str, Any]
    summary: dict[str, Any]
    cases: list[dict[str, Any]]
    # How the run was judged (PII engine, refusal classifier). Envelope only.
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"suite": self.suite, "summary": self.summary, "cases": self.cases}

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PolicyReport:
        """Load a report from a ``policy.run`` envelope or the legacy report shape."""
        if obj.get("_type") == STATEMENT_TYPE:
            pred = obj.get("predicate") or {}
            details = pred.get("details") or {}
            return PolicyReport(
                suite=dict(details.get("suite") or {}),
                summary=dict(pred.get("summary") or {}),
                cases=list(details.get("cases") or []),
            )
        return PolicyReport(
            suite=dict(obj.get("suite") or {}),
            summary=dict(obj.get("summary") or {}),
            cases=list(obj.get("cases") or []),
        )


def write_report_json(report: PolicyReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
