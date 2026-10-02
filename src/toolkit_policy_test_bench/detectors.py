"""Built-in PII and secret detectors plus the regex safety helpers.

Every regex in this package (built-in detectors, suite ``regex_*`` checks and
plugin pattern files) runs through the third-party ``regex`` engine with a
per-call timeout. The timeout is enforced by the engine itself, so it works on
every platform and in any thread (no signals are used). A timeout raises
:class:`RegexTimeoutError`; callers treat it as a failed check (fail closed).
"""

from __future__ import annotations

import logging
from typing import Any

import regex

logger = logging.getLogger(__name__)

# Per-call timeout for every regex operation (seconds). Guards against ReDoS.
REGEX_TIMEOUT_SECONDS: float = 5.0

# Longest user-supplied pattern accepted (suite checks and plugin pattern files).
MAX_PATTERN_CHARS: int = 1000


class RegexTimeoutError(TimeoutError):
    """Raised when a regex operation exceeds its timeout (possible ReDoS)."""


def compile_pattern(pattern: str) -> regex.Pattern[str]:
    """Compile a user-supplied pattern, enforcing the size cap.

    Raises:
        ValueError: if the pattern is longer than ``MAX_PATTERN_CHARS`` or invalid.
    """
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(
            f"regex pattern too long: {len(pattern)} chars (limit {MAX_PATTERN_CHARS})"
        )
    try:
        return regex.compile(pattern)
    except regex.error as exc:
        raise ValueError(f"invalid regex {pattern[:50]!r}: {exc}") from exc


def _resolve_timeout(timeout: float | None) -> float:
    return REGEX_TIMEOUT_SECONDS if timeout is None else timeout


def _on_timeout(pattern: regex.Pattern[str], text: str, timeout: float) -> RegexTimeoutError:
    logger.warning(
        "Regex timed out after %.2fs on pattern %r (text length: %d)",
        timeout,
        pattern.pattern[:50],
        len(text),
    )
    return RegexTimeoutError(f"regex timed out after {timeout}s: {pattern.pattern[:50]!r}")


def safe_findall(pattern: regex.Pattern[str], text: str, timeout: float | None = None) -> list[Any]:
    """``findall`` with a timeout. Raises :class:`RegexTimeoutError` on timeout."""
    limit = _resolve_timeout(timeout)
    try:
        return pattern.findall(text, timeout=limit)
    except TimeoutError as exc:
        raise _on_timeout(pattern, text, limit) from exc


def _finditer(pattern: regex.Pattern[str], text: str, timeout: float | None = None) -> list[Any]:
    """``finditer`` materialized with a timeout. Raises :class:`RegexTimeoutError`."""
    limit = _resolve_timeout(timeout)
    try:
        return list(pattern.finditer(text, timeout=limit))
    except TimeoutError as exc:
        raise _on_timeout(pattern, text, limit) from exc


def safe_search(pattern: regex.Pattern[str], text: str, timeout: float | None = None) -> bool:
    """``search`` with a timeout. Raises :class:`RegexTimeoutError` on timeout."""
    limit = _resolve_timeout(timeout)
    try:
        return pattern.search(text, timeout=limit) is not None
    except TimeoutError as exc:
        raise _on_timeout(pattern, text, limit) from exc


_EMAIL = regex.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_CC = regex.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Phone numbers.
# International (E.164 style): "+", country code, then digit groups. 8-15 digits in all
# (ITU-T E.164 allows at most 15).
_PHONE_INTL = regex.compile(r"(?<![\w+])\+[1-9]\d{0,3}(?:[ .\-]?\(?\d{1,4}\)?){1,6}(?!\d)")
# NANP with separators or parentheses: NXX-NXX-XXXX, area code must start with 2-9.
_PHONE_NANP_FORMATTED = regex.compile(
    r"(?<![\d\w])(?:\(\s*[2-9]\d{2}\s*\)\s*|[2-9]\d{2}[-.\s])\d{3}[-.\s]\d{4}(?!\d)"
)
# NANP as 10 bare digits: area and exchange codes must both start with 2-9, and a
# phone word must appear just before it (bare 10-digit runs are usually ids).
_PHONE_NANP_BARE = regex.compile(r"(?<![\d\w])[2-9]\d{2}[2-9]\d{6}(?!\d)")
_PHONE_CONTEXT = regex.compile(
    r"(?i)\b(?:phone|tel|telephone|call|mobile|cell|fax|sms|text|whatsapp|contact)\b"
)
_CONTEXT_WINDOW = 30

# US SSNs: 3-2-4 digits with the same separator (dash or space), or 9 bare digits
# right after an SSN word.
_SSN_SEPARATED = regex.compile(r"(?<![\d\w])(\d{3})([- ])(\d{2})\2(\d{4})(?!\d)")
_SSN_BARE = regex.compile(r"(?<![\d\w])(\d{3})(\d{2})(\d{4})(?!\d)")
_SSN_CONTEXT = regex.compile(r"(?i)\b(?:ssn|ssns|ss#|social\s+security)")


def _has_context(pattern: regex.Pattern[str], text: str, start: int, timeout: float | None) -> bool:
    window = text[max(0, start - _CONTEXT_WINDOW) : start]
    return safe_search(pattern, window, timeout)


def _count_phones(text: str, timeout: float | None) -> int:
    count = 0
    masked = list(text)
    for m in _finditer(_PHONE_INTL, text, timeout):
        digits = sum(ch.isdigit() for ch in m.group())
        if 8 <= digits <= 15:
            count += 1
            masked[m.start() : m.end()] = " " * (m.end() - m.start())
    rest = "".join(masked)
    for m in _finditer(_PHONE_NANP_FORMATTED, rest, timeout):
        count += 1
        masked[m.start() : m.end()] = " " * (m.end() - m.start())
    rest = "".join(masked)
    for m in _finditer(_PHONE_NANP_BARE, rest, timeout):
        if _has_context(_PHONE_CONTEXT, rest, m.start(), timeout):
            count += 1
    return count


def _ssn_valid(area: str, group: str, serial: str) -> bool:
    """SSA never assigns area 000, 666 or 900-999, group 00 or serial 0000."""
    if area in ("000", "666") or area[0] == "9" or group == "00" or serial == "0000":
        return False
    return len(set(area + group + serial)) > 1  # all-same-digit numbers are not real SSNs


def _count_ssns(text: str, timeout: float | None) -> int:
    count = 0
    for m in _finditer(_SSN_SEPARATED, text, timeout):
        if _ssn_valid(m.group(1), m.group(3), m.group(4)):
            count += 1
    for m in _finditer(_SSN_BARE, text, timeout):
        if _ssn_valid(m.group(1), m.group(2), m.group(3)) and _has_context(
            _SSN_CONTEXT, text, m.start(), timeout
        ):
            count += 1
    return count


# Secret patterns. Several token formats may end in "-" or "_", so their end is
# guarded with "not followed by a token character" instead of \b.
_KEY_END = r"(?![A-Za-z0-9_-])"
_AWS_ACCESS_KEY = regex.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT = regex.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
# OpenAI: legacy "sk-<alnum>" plus project, service-account and admin keys.
_OPENAI_LIKE = regex.compile(
    r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}" + _KEY_END + r"|[A-Za-z0-9]{20,}\b)"
)
_ANTHROPIC_KEY = regex.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}" + _KEY_END)
_GITHUB_TOKEN = regex.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}\b|github_pat_[A-Za-z0-9_]{22,255}" + _KEY_END + r")"
)
_STRIPE_KEY = regex.compile(r"\b(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{16,}\b")
_GOOGLE_API_KEY = regex.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}" + _KEY_END)
_PRIVATE_KEY = regex.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_SLACK_TOKEN = regex.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _is_card_number(candidate: str) -> bool:
    """A 13-19 digit run is reported as a card only if it passes the Luhn check.

    This drops most order ids, timestamps and other long numbers.
    """
    digits = "".join(ch for ch in candidate if ch.isdigit())
    return 13 <= len(digits) <= 19 and _luhn_ok(digits)


def detect_pii(text: str, timeout: float | None = None) -> dict[str, int]:
    """Count built-in PII matches. Raises :class:`RegexTimeoutError` on timeout."""
    return {
        "email": len(safe_findall(_EMAIL, text, timeout)),
        "phone": _count_phones(text, timeout),
        "ssn": _count_ssns(text, timeout),
        "credit_card": sum(1 for m in safe_findall(_CC, text, timeout) if _is_card_number(m)),
    }


def detect_secrets(text: str, timeout: float | None = None) -> dict[str, int]:
    """Count built-in secret matches. Raises :class:`RegexTimeoutError` on timeout."""
    return {
        "aws_access_key": len(safe_findall(_AWS_ACCESS_KEY, text, timeout)),
        "jwt": len(safe_findall(_JWT, text, timeout)),
        "openai_like_key": len(safe_findall(_OPENAI_LIKE, text, timeout)),
        "anthropic_key": len(safe_findall(_ANTHROPIC_KEY, text, timeout)),
        "github_token": len(safe_findall(_GITHUB_TOKEN, text, timeout)),
        "stripe_key": len(safe_findall(_STRIPE_KEY, text, timeout)),
        "google_api_key": len(safe_findall(_GOOGLE_API_KEY, text, timeout)),
        "private_key": len(safe_findall(_PRIVATE_KEY, text, timeout)),
        "slack_token": len(safe_findall(_SLACK_TOKEN, text, timeout)),
    }
