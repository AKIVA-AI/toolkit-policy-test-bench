"""Optional PII detection with Microsoft Presidio (``pip install '...[presidio]'``).

Enabled per suite with ``"pii": {"enabled": true, "engine": "presidio"}`` (or
``"both"`` to run the built-in regexes as well). Presidio adds named-entity
recognition (names, locations, dates), checksums and context words on top of
patterns. It needs a spaCy model; the default is ``en_core_web_lg`` (Presidio's own
default), and ``"presidio_model": "en_core_web_sm"`` is a lighter choice.

Requesting Presidio when it is not installed is an error, never a silent fallback
to the regex engine.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

PII_ENGINES = ("regex", "presidio", "both")
DEFAULT_MODEL = "en_core_web_lg"
DEFAULT_SCORE_THRESHOLD = 0.5

_INSTALL_HINT = "pip install 'toolkit-policy-test-bench[presidio]'"


def presidio_settings(pii_cfg: dict[str, Any]) -> dict[str, Any]:
    """Validated Presidio options from a suite's ``pii`` block."""
    entities = pii_cfg.get("entities")
    if entities is not None and (
        not isinstance(entities, list) or not all(isinstance(e, str) for e in entities)
    ):
        raise ValueError("pii.entities must be a list of Presidio entity names")
    threshold = pii_cfg.get("score_threshold", DEFAULT_SCORE_THRESHOLD)
    if not isinstance(threshold, (int, float)) or not 0 <= float(threshold) <= 1:
        raise ValueError("pii.score_threshold must be a number between 0 and 1")
    return {
        "model": str(pii_cfg.get("presidio_model") or DEFAULT_MODEL),
        "language": str(pii_cfg.get("language") or "en"),
        "entities": list(entities) if entities else None,
        "score_threshold": float(threshold),
    }


def make_presidio_detector(
    settings: dict[str, Any],
) -> tuple[Callable[[str], dict[str, int]], dict[str, Any]]:
    """Build a ``text -> {entity_type: count}`` detector and its report metadata.

    Raises:
        ValueError: when Presidio or the spaCy model is not installed.
    """
    try:
        from importlib.metadata import version

        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise ValueError(f"pii.engine 'presidio' needs Presidio: {_INSTALL_HINT}") from exc

    model, language = settings["model"], settings["language"]
    try:
        import spacy.util

        if not spacy.util.is_package(model):
            raise OSError(f"spaCy model {model!r} is not installed")
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": model}],
            }
        )
        engine = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=[language])
    except (OSError, ImportError) as exc:
        raise ValueError(
            f"Presidio could not load spaCy model {model!r} ({exc}); "
            f"install it with: python -m spacy download {model}"
        ) from exc

    entities = settings["entities"]
    threshold = settings["score_threshold"]

    def detect(text: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in engine.analyze(
            text=text, language=language, entities=entities, score_threshold=threshold
        ):
            key = str(r.entity_type).lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    meta = {
        "presidio_analyzer_version": version("presidio-analyzer"),
        "spacy_model": model,
        "language": language,
        "entities": entities,
        "score_threshold": threshold,
    }
    return detect, meta
