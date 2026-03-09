"""Custom detector plugin system.

Users can register custom PII or secret detectors as Python callables or
YAML/JSON pattern files. Registered detectors are invoked alongside the
built-in ones during suite runs.

Usage (programmatic)::

    from toolkit_policy_test_bench.plugins import registry, DetectorPlugin

    def my_detector(text: str) -> dict[str, int]:
        import re
        return {"internal_id": len(re.findall(r"INT-\\d{6}", text))}

    registry.register(DetectorPlugin(
        name="internal_id",
        kind="pii",
        detect=my_detector,
    ))

Usage (pattern file)::

    registry.load_patterns_file(Path("custom_patterns.json"))

Pattern file format (JSON or YAML)::

    {
        "detectors": [
            {
                "name": "medical_record",
                "kind": "pii",
                "pattern": "MRN-\\\\d{8}"
            }
        ]
    }
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectorPlugin:
    """A single custom detector.

    Attributes:
        name: Unique detector name (used as key in results dict).
        kind: Either ``"pii"`` or ``"secret"``.
        detect: Callable that takes text and returns ``{name: count}``.
    """

    name: str
    kind: str  # "pii" or "secret"
    detect: Callable[[str], dict[str, int]]

    def __post_init__(self) -> None:
        if self.kind not in ("pii", "secret"):
            raise ValueError(f"Invalid detector kind: {self.kind!r} (must be 'pii' or 'secret')")
        if not self.name:
            raise ValueError("Detector name must not be empty")


def _make_regex_detector(name: str, pattern: str) -> Callable[[str], dict[str, int]]:
    """Create a regex-based detector function from a pattern string."""
    compiled = re.compile(pattern)

    def _detect(text: str) -> dict[str, int]:
        return {name: len(compiled.findall(text))}

    return _detect


@dataclass
class DetectorRegistry:
    """Registry of custom detector plugins."""

    _detectors: list[DetectorPlugin] = field(default_factory=list)

    @property
    def detectors(self) -> list[DetectorPlugin]:
        return list(self._detectors)

    def register(self, plugin: DetectorPlugin) -> None:
        """Register a custom detector plugin.

        Raises:
            ValueError: If a detector with the same name already exists.
        """
        for existing in self._detectors:
            if existing.name == plugin.name:
                raise ValueError(f"Detector already registered: {plugin.name!r}")
        self._detectors.append(plugin)
        logger.info(f"Registered custom detector: {plugin.name} (kind={plugin.kind})")

    def unregister(self, name: str) -> bool:
        """Remove a detector by name. Returns True if found and removed."""
        before = len(self._detectors)
        self._detectors = [d for d in self._detectors if d.name != name]
        removed = len(self._detectors) < before
        if removed:
            logger.info(f"Unregistered custom detector: {name}")
        return removed

    def clear(self) -> None:
        """Remove all registered detectors."""
        self._detectors.clear()

    def load_patterns_file(self, path: Path) -> int:
        """Load detector patterns from a JSON file.

        Args:
            path: Path to JSON file with ``detectors`` array.

        Returns:
            Number of detectors loaded.

        Raises:
            FileNotFoundError: If file does not exist.
            ValueError: If file format is invalid.
        """
        resolved = path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Pattern file not found: {resolved}")

        content = resolved.read_text(encoding="utf-8")
        try:
            data: Any = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {resolved}: {exc}") from exc

        if not isinstance(data, dict) or "detectors" not in data:
            raise ValueError(f"Pattern file must contain a 'detectors' array: {resolved}")

        detectors_list = data["detectors"]
        if not isinstance(detectors_list, list):
            raise ValueError(f"'detectors' must be an array: {resolved}")

        count = 0
        for entry in detectors_list:
            if not isinstance(entry, dict):
                raise ValueError(f"Each detector entry must be an object: {entry!r}")
            name = str(entry.get("name", ""))
            kind = str(entry.get("kind", ""))
            pattern = str(entry.get("pattern", ""))

            if not name or not kind or not pattern:
                raise ValueError(
                    f"Detector entry requires 'name', 'kind', and 'pattern': {entry!r}"
                )

            detect_fn = _make_regex_detector(name, pattern)
            self.register(DetectorPlugin(name=name, kind=kind, detect=detect_fn))
            count += 1

        logger.info(f"Loaded {count} detectors from {resolved}")
        return count

    def run_pii(self, text: str) -> dict[str, int]:
        """Run all registered PII detectors. Returns merged results."""
        results: dict[str, int] = {}
        for d in self._detectors:
            if d.kind == "pii":
                results.update(d.detect(text))
        return results

    def run_secrets(self, text: str) -> dict[str, int]:
        """Run all registered secret detectors. Returns merged results."""
        results: dict[str, int] = {}
        for d in self._detectors:
            if d.kind == "secret":
                results.update(d.detect(text))
        return results


# Module-level singleton registry
registry = DetectorRegistry()
