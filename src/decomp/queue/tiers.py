"""Tiers: what kind of work a function is, so the queue can order by kind first.

Carried over from the audio project's vocabulary, because its meanings were
earned. A tier is not a difficulty score; it says which pile a function belongs
in, and difficulty orders within the pile.
"""

from __future__ import annotations

from typing import Any

# Order matters: the first matching rule wins, most specific first.
TIER_LEGACY = "L"      # already hooked elsewhere; not ours to port
TIER_GATE2 = "E"       # write set not enumerable
TIER_UNVERIFIABLE = "F"  # timebase, or nothing observable at all
TIER_GATE1 = "D"       # reaches something unreplayable
TIER_UNCALLED = "U"    # never observed running
TIER_VECTOR = "C"      # vector kernels: hand arithmetic, highest risk
TIER_LEAF = "A"        # no guest callees: the cheapest real wins
TIER_DEFAULT = "B"

TIER_ORDER = (TIER_LEAF, TIER_DEFAULT, TIER_VECTOR, TIER_UNCALLED,
              TIER_GATE1, TIER_UNVERIFIABLE, TIER_GATE2, TIER_LEGACY)

TIER_LABELS = {
    TIER_LEAF: "leaf",
    TIER_DEFAULT: "ordinary",
    TIER_VECTOR: "vector",
    TIER_UNCALLED: "uncalled",
    TIER_GATE1: "gate1",
    TIER_UNVERIFIABLE: "unverifiable",
    TIER_GATE2: "gate2",
    TIER_LEGACY: "legacy",
}


def assign(fn: dict[str, Any], legacy: set[int] | None = None,
           have_profiles: bool = True) -> str:
    """Which pile does this function belong in?

    `have_profiles` says whether any execution trace has been imported. Without
    one, "never observed running" is not a claim the harness can make, so the
    uncalled tier is skipped entirely rather than swallowing the whole corpus.
    """
    addr = fn.get("addr")
    if legacy and addr in legacy:
        return TIER_LEGACY

    gate = fn.get("gate")
    if gate == "gate2":
        return TIER_GATE2
    if gate == "gate3":
        return TIER_UNVERIFIABLE
    if gate == "gate4":
        # Nothing in memory to compare. Verifiable only if a caller reads a
        # register the oracle can be told to watch; otherwise it is dead weight.
        return TIER_UNVERIFIABLE if not fn.get("hot") else TIER_LEAF
    if gate == "gate1":
        return TIER_GATE1

    calls = (fn.get("calls_boot") or 0) + (fn.get("calls_play") or 0) + (fn.get("calls_map") or 0)
    if have_profiles and not calls and fn.get("hot") in (None, 0):
        # Observed not to run. Porting it proves nothing, because no session
        # will exercise it: the audio project's REQUEUE passed every gate and
        # sat uncalled through two sessions.
        return TIER_UNCALLED
    if fn.get("vmx128"):
        return TIER_VECTOR
    if fn.get("is_leaf"):
        return TIER_LEAF
    return TIER_DEFAULT


def sort_key(tier: str) -> int:
    try:
        return TIER_ORDER.index(tier)
    except ValueError:
        return len(TIER_ORDER)
