"""Output formatting for CLI (json and table modes)."""

from __future__ import annotations

import json
from typing import Any


def _table_from_dict(data: dict[str, Any], indent: int = 0) -> str:
    """Render a dict as an aligned key-value table."""
    if not data:
        return "(empty)"
    lines: list[str] = []
    prefix = " " * indent
    max_key = max(len(str(k)) for k in data)
    for key, val in data.items():
        if isinstance(val, dict):
            lines.append(f"{prefix}{str(key):<{max_key}}:")
            lines.append(_table_from_dict(val, indent=indent + 2))
        elif isinstance(val, list):
            lines.append(f"{prefix}{str(key):<{max_key}}  {len(val)} items")
        else:
            lines.append(f"{prefix}{str(key):<{max_key}}  {val}")
    return "\n".join(lines)


def format_output(data: Any, fmt: str = "json") -> str:
    """Format data for CLI output.

    Args:
        data: Data to format (typically a dict).
        fmt: Output format — ``"json"`` (default) or ``"table"``.

    Returns:
        Formatted string.
    """
    if fmt == "table" and isinstance(data, dict):
        return _table_from_dict(data)
    return json.dumps(data, indent=2, sort_keys=True)
