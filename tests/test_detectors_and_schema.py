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


# ---------------------------------------------------------------------------
# Current credential formats. Fixtures are assembled from parts so that no
# complete token-shaped literal is committed to the repository.
# ---------------------------------------------------------------------------

_ALNUM = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"


def _k(*parts: str) -> str:
    return "".join(parts)


@pytest.mark.parametrize(
    ("text", "key"),
    [
        (_k("sk-", "proj-", _ALNUM, "_-", _ALNUM), "openai_like_key"),
        (_k("sk-", "svcacct-", _ALNUM, _ALNUM), "openai_like_key"),
        (_k("sk-", _ALNUM, "0123456789abcdef"), "openai_like_key"),
        (_k("sk-", "ant-", "api03-", _ALNUM, "-", _ALNUM, "AA"), "anthropic_key"),
        (_k("gh", "p_", _ALNUM, "0123"), "github_token"),
        (_k("gh", "s_", _ALNUM, "0123"), "github_token"),
        (_k("github", "_pat_", "11ABCDEFG0", "abcdefghijkl_", _ALNUM, _ALNUM), "github_token"),
        (_k("sk", "_live_", _ALNUM), "stripe_key"),
        (_k("rk", "_live_", _ALNUM), "stripe_key"),
        (_k("AI", "za", "Sy", _ALNUM[:30], "-_0"), "google_api_key"),
        (_k("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIE...\n"), "private_key"),
        (_k("-----BEGIN ", "PRIVATE KEY-----\nMC4C...\n"), "private_key"),
        (_k("-----BEGIN ", "OPENSSH PRIVATE KEY-----\nb3Bl...\n"), "private_key"),
        (_k("-----BEGIN ", "EC PRIVATE KEY-----\nMHcC...\n"), "private_key"),
    ],
)
def test_detect_secrets_current_formats(text: str, key: str) -> None:
    hits = detect_secrets(f"leaked: {text} end")
    assert hits[key] == 1, hits
    assert sum(hits.values()) == 1, hits


@pytest.mark.parametrize(
    "text",
    [
        "the task-management board and risk-assessment notes",
        _k("sk-", "proj-", "short"),
        _k("sk-", "ant-", "tiny"),
        _k("gh", "p_", "tooShort123"),
        _k("sk", "_live_", "abc"),
        _k("AI", "za", "Short"),
        _k("-----BEGIN ", "PUBLIC KEY-----\nMCow...\n"),
        _k("-----BEGIN ", "CERTIFICATE-----\nMIIB...\n"),
        "ask-me-anything and skip_live_updates",
    ],
)
def test_detect_secrets_negative(text: str) -> None:
    hits = detect_secrets(text)
    assert sum(hits.values()) == 0, hits


# ---------------------------------------------------------------------------
# Credit cards: only Luhn-valid 13-19 digit numbers count.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "card 4111 1111 1111 1111 on file",
        "card 4242-4242-4242-4242 on file",
        "amex 378282246310005",
    ],
)
def test_detect_pii_luhn_valid_card(text: str) -> None:
    assert detect_pii(text)["credit_card"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "order 1234567890123456 shipped",
        "created_at_ms=1700000000000",
        "trace 9876543210987654 at 1712345678901",
        "card 4111 1111 1111 1112 rejected",
    ],
)
def test_detect_pii_rejects_non_luhn_digit_runs(text: str) -> None:
    assert detect_pii(text)["credit_card"] == 0
