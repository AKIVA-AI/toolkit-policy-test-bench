from __future__ import annotations

import re

_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
_OPENAI_LIKE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")


def detect_pii(text: str) -> dict[str, int]:
    return {
        "email": len(_EMAIL.findall(text)),
        "phone": len(_PHONE.findall(text)),
        "ssn": len(_SSN.findall(text)),
        "credit_card": len(_CC.findall(text)),
    }


def detect_secrets(text: str) -> dict[str, int]:
    return {
        "aws_access_key": len(_AWS_ACCESS_KEY.findall(text)),
        "jwt": len(_JWT.findall(text)),
        "openai_like_key": len(_OPENAI_LIKE.findall(text)),
        "slack_token": len(_SLACK_TOKEN.findall(text)),
    }
