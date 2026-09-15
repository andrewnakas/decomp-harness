"""Difficulty: a cheap 0-1 score used to route a function to a model tier.

Every term is something the harness already measured. The score decides which
model sees the packet and whether it can be batched, so being roughly right
matters more than being precise; a wrong call costs one retry, not a session.
"""

from __future__ import annotations

from typing import Any

# Weight, and the value at which that term is considered saturated.
TERMS: dict[str, tuple[float, float]] = {
    "lifted_lines": (0.30, 400.0),
    "stores": (0.15, 24.0),
    "callees": (0.15, 8.0),
    "loops": (0.10, 4.0),
    "gate2_suspects": (0.10, 8.0),
    "float_ops": (0.05, 20.0),
}
VECTOR_PENALTY = 0.15      # hand-checked lane arithmetic; the audio project's
                           # single biggest risk in any estimate


def score(fn: dict[str, Any], census: dict[str, Any] | None = None) -> float:
    """0 is a thunk, 1 is a vector kernel with a data-dependent write set."""
    census = census or {}
    total = 0.0
    values = {
        "lifted_lines": fn.get("lifted_lines") or census.get("lines") or 0,
        "stores": census.get("stores") or 0,
        "callees": fn.get("callee_count") or 0,
        "loops": census.get("loops") or 0,
        "gate2_suspects": fn.get("gate2_suspects") or 0,
        "float_ops": census.get("float_ops") or 0,
    }
    for term, (weight, saturation) in TERMS.items():
        value = float(values.get(term) or 0)
        total += weight * min(1.0, value / saturation)

    if fn.get("vmx128"):
        total += VECTOR_PENALTY
    return round(min(1.0, total), 3)


def tier_for(difficulty: float, vmx: bool = False, attempts: int = 0,
             thresholds: tuple[float, float] = (0.35, 0.70)) -> str:
    """Which model tier should see this: small, mid, or strong.

    Vector work and anything that has already failed goes straight to the strong
    model: a retry costs more than the difference in price.
    """
    low, high = thresholds
    if vmx or attempts >= 2:
        return "strong"
    if difficulty >= high:
        return "strong"
    if difficulty >= low:
        return "mid"
    return "small"


def batchable(fn: dict[str, Any], difficulty: float, max_lines: int = 40) -> bool:
    """Small, scalar, ungated functions can share one call."""
    if fn.get("vmx128") or fn.get("gate"):
        return False
    if difficulty >= 0.35:
        return False
    return (fn.get("lifted_lines") or 0) <= max_lines
