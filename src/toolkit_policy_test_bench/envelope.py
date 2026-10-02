"""Report envelope v1: an in-toto Statement v1 wrapping each machine-readable result.

The envelope is the shared report format of the toolkit family (see
``docs/report-envelope.md`` and ``schemas/report-envelope.v1.json``). A report
file is canonical JSON (UTF-8, sorted keys, no insignificant whitespace, one
trailing newline) so its SHA-256 is stable and it can be signed with standard
attestation tooling.

Verdicts map to the CLI exit codes: ``pass`` = 0, ``fail`` = 4, and ``error``
(the tool could not judge: bad input or a failed integrity check) = 2, 3 or 4.
An ``error`` report is never ``pass``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/AKIVA-AI/toolkit-policy-test-bench/report/v1"
TOOL_NAME = "toolkit-policy-test-bench"
VERDICTS = ("pass", "fail", "error")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_ref(path: Path, name: str | None = None) -> dict[str, Any]:
    """A ``{name, digest: {sha256}}`` reference to a file on disk."""
    return {"name": name or path.name, "digest": {"sha256": sha256_bytes(path.read_bytes())}}


def utc_now() -> str:
    """RFC 3339 UTC timestamp with second precision, e.g. ``2026-09-26T18:00:00Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_version() -> str:
    from . import __version__

    return __version__


def build_envelope(
    *,
    kind: str,
    verdict: str,
    exit_code: int,
    subject: list[dict[str, Any]],
    inputs: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build an in-toto Statement v1 report envelope.

    Raises:
        ValueError: if the verdict is unknown or disagrees with ``exit_code``
            (``pass`` requires 0; ``fail`` and ``error`` require non-zero).
    """
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}; expected one of {VERDICTS}")
    if (verdict == "pass") != (exit_code == 0):
        raise ValueError(f"verdict {verdict!r} disagrees with exit code {exit_code}")
    if not subject:
        raise ValueError("an envelope needs at least one subject")
    return {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "tool": {"name": TOOL_NAME, "version": _tool_version()},
            "kind": kind,
            "created_at": created_at or utc_now(),
            "verdict": verdict,
            "exit_code": int(exit_code),
            "inputs": list(inputs or []),
            "summary": dict(summary or {}),
            "details": dict(details or {}),
        },
    }


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON: UTF-8, sorted keys, compact separators, trailing newline."""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8") + b"\n"


def write_envelope(envelope: dict[str, Any], path: Path) -> None:
    """Write an envelope as canonical JSON (bytes, so no newline translation)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(envelope))


def is_envelope(obj: Any) -> bool:
    return isinstance(obj, dict) and obj.get("_type") == STATEMENT_TYPE


def validate_envelope(obj: Any) -> list[str]:
    """Structural check of an envelope. Returns a list of problems (empty = valid).

    Mirrors the required fields of ``schemas/report-envelope.v1.json`` without a
    JSON Schema dependency.
    """
    problems: list[str] = []
    if not isinstance(obj, dict):
        return ["not_an_object"]
    if obj.get("_type") != STATEMENT_TYPE:
        problems.append("bad_type")
    subject = obj.get("subject")
    if not isinstance(subject, list) or not subject:
        problems.append("missing_subject")
    else:
        for item in subject:
            digest = item.get("digest") if isinstance(item, dict) else None
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                problems.append("bad_subject_name")
            if not isinstance(digest, dict) or not digest:
                problems.append("bad_subject_digest")
    if not isinstance(obj.get("predicateType"), str):
        problems.append("missing_predicate_type")
    pred = obj.get("predicate")
    if not isinstance(pred, dict):
        return problems + ["missing_predicate"]
    tool = pred.get("tool")
    if not isinstance(tool, dict) or not tool.get("name") or not tool.get("version"):
        problems.append("bad_tool")
    for key in ("kind", "created_at"):
        if not isinstance(pred.get(key), str) or not pred.get(key):
            problems.append(f"missing_{key}")
    verdict = pred.get("verdict")
    exit_code = pred.get("exit_code")
    if verdict not in VERDICTS:
        problems.append("bad_verdict")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        problems.append("bad_exit_code")
    elif verdict in VERDICTS and (verdict == "pass") != (exit_code == 0):
        problems.append("verdict_exit_code_mismatch")
    if not isinstance(pred.get("inputs"), list):
        problems.append("bad_inputs")
    for key in ("summary", "details"):
        if not isinstance(pred.get(key), dict):
            problems.append(f"bad_{key}")
    return problems
