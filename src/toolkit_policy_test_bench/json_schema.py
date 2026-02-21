from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class JSONSchema:
    required_keys: list[str]
    optional_keys: list[str]
    allow_extra_keys: bool = True


def parse_json_schema(obj: dict[str, Any]) -> JSONSchema:
    if not isinstance(obj, dict):
        raise ValueError("invalid:schema_not_object")
    return JSONSchema(
        required_keys=[str(x) for x in obj.get("required_keys", [])],
        optional_keys=[str(x) for x in obj.get("optional_keys", [])],
        allow_extra_keys=bool(obj.get("allow_extra_keys", True)),
    )


def parse_json_from_prediction(prediction: Any) -> tuple[bool, Any]:
    if isinstance(prediction, dict):
        return True, prediction
    if not isinstance(prediction, str):
        return False, None
    try:
        return True, json.loads(prediction)
    except Exception:  # noqa: BLE001
        return False, None


def validate_json(obj: Any, schema: JSONSchema) -> tuple[bool, list[str]]:
    if not isinstance(obj, dict):
        return False, ["not_object"]

    ok = True
    reasons: list[str] = []

    for k in schema.required_keys:
        if k not in obj:
            ok = False
            reasons.append(f"missing_key:{k}")

    if not schema.allow_extra_keys:
        allowed = set(schema.required_keys).union(schema.optional_keys)
        extras = [k for k in obj.keys() if k not in allowed]
        if extras:
            ok = False
            reasons.append("extra_keys:" + ",".join(sorted(extras)))

    return ok, reasons
