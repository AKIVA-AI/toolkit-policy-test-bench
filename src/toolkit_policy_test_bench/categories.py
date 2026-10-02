"""Finding categories: data-driven mapping from each tool's test ids to one category.

The rules live in ``data/categories.json`` (a data file, not code), so a new
garak probe or promptfoo plugin needs a JSON edit, not a release. Users can
pass their own file with ``--categories``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

UNCATEGORIZED = "uncategorized"


def _default_text() -> str:
    return (
        resources.files("toolkit_policy_test_bench")
        .joinpath("data/categories.json")
        .read_text(encoding="utf-8")
    )


@dataclass(frozen=True)
class CategoryRules:
    categories: dict[str, str]
    rules: dict[str, list[tuple[str, str]]]

    @staticmethod
    def load(path: Path | None = None) -> CategoryRules:
        text = path.read_text(encoding="utf-8") if path else _default_text()
        where = str(path) if path else "built-in categories.json"
        try:
            doc: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{where}: not JSON: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("categories"), dict):
            raise ValueError(f"{where}: needs a 'categories' object")
        categories = {str(k): str(v) for k, v in doc["categories"].items()}
        categories.setdefault(UNCATEGORIZED, "No rule matched.")
        rules: dict[str, list[tuple[str, str]]] = {}
        for source, spec in (doc.get("sources") or {}).items():
            parsed: list[tuple[str, str]] = []
            for i, rule in enumerate((spec or {}).get("rules") or []):
                match, cat = rule.get("match"), rule.get("category")
                if not isinstance(match, str) or not match or cat not in categories:
                    raise ValueError(
                        f"{where}: sources.{source}.rules[{i}] needs 'match' and a known 'category'"
                    )
                parsed.append((match, cat))
            rules[str(source)] = parsed
        return CategoryRules(categories=categories, rules=rules)

    def categorize(self, source: str, keys: list[str]) -> str:
        """Category of the first rule (in file order) that matches any of ``keys``."""
        for match, cat in self.rules.get(source, []):
            for key in keys:
                if match.endswith("*"):
                    if key.startswith(match[:-1]):
                        return cat
                elif key == match:
                    return cat
        return UNCATEGORIZED
