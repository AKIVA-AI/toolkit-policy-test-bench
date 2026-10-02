from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyCase:
    id: str
    input: Any
    tags: list[str]
    # Per-case expectations, validated by ``validate_expect``. Empty = suite checks only.
    expect: dict[str, Any] = field(default_factory=dict)


_EXPECT_LIST_KEYS = ("must_contain", "must_not_contain", "regex_must_match", "regex_must_not_match")
_EXPECT_DETECTOR_KEYS = ("pii", "secrets")
EXPECT_KEYS = frozenset(("refusal", *_EXPECT_LIST_KEYS, *_EXPECT_DETECTOR_KEYS))


def validate_expect(case_id: str, expect: Any) -> dict[str, Any]:
    """Validate a case's ``expect`` object. Unknown keys or wrong types raise.

    Rejecting unknown keys fails closed: a typo such as ``"refuse"`` would
    otherwise silently drop the expectation and let the case pass.
    """
    where = f"case {case_id!r}: expect"
    if expect is None:
        return {}
    if not isinstance(expect, dict):
        raise ValueError(f"{where} must be an object")
    unknown = sorted(set(expect) - EXPECT_KEYS)
    if unknown:
        raise ValueError(f"{where} has unknown keys {unknown}; allowed: {sorted(EXPECT_KEYS)}")
    if "refusal" in expect and not isinstance(expect["refusal"], bool):
        raise ValueError(f"{where}.refusal must be true or false")
    for key in _EXPECT_LIST_KEYS:
        if key in expect and (
            not isinstance(expect[key], list) or not all(isinstance(x, str) for x in expect[key])
        ):
            raise ValueError(f"{where}.{key} must be a list of strings")
    for key in _EXPECT_DETECTOR_KEYS:
        if key not in expect:
            continue
        det = expect[key]
        if not isinstance(det, dict):
            raise ValueError(f'{where}.{key} must be an object like {{"enabled": true}}')
        bad = sorted(set(det) - {"enabled", "ignore"})
        if bad:
            raise ValueError(f"{where}.{key} has unknown keys {bad}; allowed: enabled, ignore")
        if "enabled" in det and not isinstance(det["enabled"], bool):
            raise ValueError(f"{where}.{key}.enabled must be true or false")
        ignore = det.get("ignore", [])
        if not isinstance(ignore, list) or not all(isinstance(x, str) for x in ignore):
            raise ValueError(f"{where}.{key}.ignore must be a list of detector names")
    return dict(expect)


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
        case_id = str(obj["id"])
        cases.append(
            PolicyCase(
                id=case_id,
                input=obj.get("input"),
                tags=[str(x) for x in obj.get("tags", [])],
                expect=validate_expect(case_id, obj.get("expect")),
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
