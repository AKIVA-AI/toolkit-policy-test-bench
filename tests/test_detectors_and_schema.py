from __future__ import annotations

import pytest

from toolkit_policy_test_bench.detectors import detect_pii, detect_secrets
from toolkit_policy_test_bench.json_schema import (
    JSONSchema,
    parse_json_from_prediction,
    parse_json_schema,
    validate_json,
)


def test_detect_pii_email_and_phone() -> None:
    hits = detect_pii("Contact me at test@example.com or (555) 123-4567.")
    assert hits["email"] == 1
    assert hits["phone"] == 1


def test_detect_secrets_key_patterns() -> None:
    hits = detect_secrets("Here is a key: sk-1234567890abcdefghijklmnop and AKIA1234567890ABCDEF")
    assert hits["openai_like_key"] == 1
    assert hits["aws_access_key"] == 1


def test_parse_json_from_prediction() -> None:
    ok, obj = parse_json_from_prediction('{"a": 1}')
    assert ok is True
    assert obj["a"] == 1

    ok2, obj2 = parse_json_from_prediction("{not json")
    assert ok2 is False
    assert obj2 is None


def test_parse_json_schema_requires_dict() -> None:
    with pytest.raises(ValueError):
        parse_json_schema("nope")  # type: ignore[arg-type]


def test_validate_json() -> None:
    schema = JSONSchema(required_keys=["a"], optional_keys=["b"], allow_extra_keys=False)
    ok, reasons = validate_json({"a": 1, "b": 2}, schema)
    assert ok is True
    assert reasons == []

    ok2, reasons2 = validate_json({"b": 2}, schema)
    assert ok2 is False
    assert "missing_key:a" in reasons2

