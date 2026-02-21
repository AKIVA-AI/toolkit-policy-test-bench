from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyCase:
    id: str
    input: Any
    tags: list[str]


@dataclass(frozen=True)
class PolicySuite:
    schema_version: int
    name: str
    description: str
    created_at: str
    checks: dict[str, Any]
    cases: list[PolicyCase]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "checks": dict(self.checks),
            "cases_count": len(self.cases),
        }


def read_suite_dir(suite_dir: Path) -> PolicySuite:
    meta = json.loads((suite_dir / "suite.json").read_text(encoding="utf-8"))
    schema_version = int(meta.get("schema_version", 1))
    name = str(meta.get("name", "unnamed"))
    description = str(meta.get("description", ""))
    created_at = str(meta.get("created_at", ""))
    checks = dict(meta.get("checks") or {})

    cases: list[PolicyCase] = []
    for line in (suite_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        cases.append(
            PolicyCase(
                id=str(obj["id"]),
                input=obj.get("input"),
                tags=[str(x) for x in obj.get("tags", [])],
            )
        )

    return PolicySuite(
        schema_version=schema_version,
        name=name,
        description=description,
        created_at=created_at,
        checks=checks,
        cases=cases,
    )
