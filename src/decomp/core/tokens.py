"""Token estimation, calibrated against provider-reported usage.

We never ship a tokenizer. The estimator is a byte-ratio model whose divisor is
refined from real `input_tokens` the providers report, stored in meta.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Project

# Claude 4.7+ use a tokenizer producing more tokens per byte than the old ~4.0.
DEFAULT_CHARS_PER_TOKEN = 3.1
META_KEY = "tokens.chars_per_token"


def estimate(text: str, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN) -> int:
    if not text:
        return 0
    return max(1, round(len(text) / chars_per_token))


def estimate_for(project: "Project", text: str) -> int:
    return estimate(text, ratio_for(project))


def ratio_for(project: "Project") -> float:
    raw = project.db.meta_get(META_KEY)
    try:
        return float(raw) if raw else DEFAULT_CHARS_PER_TOKEN
    except (TypeError, ValueError):
        return DEFAULT_CHARS_PER_TOKEN


def calibrate(project: "Project", sent_chars: int, reported_tokens: int) -> float:
    """Blend a new observation into the running chars-per-token estimate."""
    if reported_tokens <= 0 or sent_chars <= 0:
        return ratio_for(project)
    observed = sent_chars / reported_tokens
    current = ratio_for(project)
    blended = round(current * 0.7 + observed * 0.3, 4)
    # Guard against nonsense from calls dominated by a cached prefix.
    if 1.0 < blended < 8.0:
        project.db.meta_set(META_KEY, blended)
        return blended
    return current
