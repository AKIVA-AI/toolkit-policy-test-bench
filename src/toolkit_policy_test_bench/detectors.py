from __future__ import annotations

import logging
import re
import signal
from typing import Any

logger = logging.getLogger(__name__)

# Default timeout for regex operations (seconds). Prevents ReDoS on crafted input.
REGEX_TIMEOUT_SECONDS: float = 5.0

_HAS_SIGALRM = hasattr(signal, "SIGALRM")

_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
_OPENAI_LIKE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")


class RegexTimeoutError(Exception):
    """Raised when a regex operation exceeds the timeout."""


def _alarm_handler(_signum: int, _frame: Any) -> None:
    raise RegexTimeoutError("Regex operation timed out (possible ReDoS)")


def _safe_findall(pattern: re.Pattern[str], text: str, timeout: float) -> list[str]:
    """Run regex findall with a timeout guard.

    On Unix, uses SIGALRM for real timeout enforcement.
    On Windows (no SIGALRM), runs without OS-level timeout but still enforces
    a text length limit as the primary ReDoS mitigation.
    """
    if _HAS_SIGALRM:
        sigalrm = signal.Signals(14)  # SIGALRM = 14 on all POSIX
        old_handler = signal.signal(sigalrm, _alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)  # type: ignore[attr-defined]
        try:
            return pattern.findall(text)
        except RegexTimeoutError:
            logger.warning(
                "Regex timed out after %.1fs on pattern %s (text length: %d)",
                timeout,
                pattern.pattern[:50],
                len(text),
            )
            return []
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)  # type: ignore[attr-defined]
            signal.signal(sigalrm, old_handler)
    else:
        # Windows: no SIGALRM — rely on text length limits (enforced in runner)
        return pattern.findall(text)


def detect_pii(text: str, timeout: float = REGEX_TIMEOUT_SECONDS) -> dict[str, int]:
    return {
        "email": len(_safe_findall(_EMAIL, text, timeout)),
        "phone": len(_safe_findall(_PHONE, text, timeout)),
        "ssn": len(_safe_findall(_SSN, text, timeout)),
        "credit_card": len(_safe_findall(_CC, text, timeout)),
    }


def detect_secrets(text: str, timeout: float = REGEX_TIMEOUT_SECONDS) -> dict[str, int]:
    return {
        "aws_access_key": len(_safe_findall(_AWS_ACCESS_KEY, text, timeout)),
        "jwt": len(_safe_findall(_JWT, text, timeout)),
        "openai_like_key": len(_safe_findall(_OPENAI_LIKE, text, timeout)),
        "slack_token": len(_safe_findall(_SLACK_TOKEN, text, timeout)),
    }
