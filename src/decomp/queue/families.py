"""Families: group functions that look alike, so one insight serves many.

Compilers emit the same shapes repeatedly. Working a family together means the
second and third members arrive with a verified sibling already in the packet,
which is both cheaper and more accurate than meeting each one cold.

MinHash over opcode n-grams, in pure Python. It is approximate on purpose: a
wrong grouping costs a slightly less useful hint, never a wrong answer.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

RE_MNEMONIC = re.compile(r"^\s*//\s*([a-z][a-z0-9_.]*)")

# Registers and immediates are exactly what differs between siblings, so the
# signature keeps only the opcode sequence.
NGRAM = 3
NUM_HASHES = 32
BAND_SIZE = 4          # bands of 4 => two functions collide when a quarter of
                       # their shingles match, which groups variants without
                       # collapsing unrelated code


@dataclass
class Family:
    id: int
    members: list[int] = field(default_factory=list)
    signature: str = ""

    @property
    def size(self) -> int:
        return len(self.members)


def opcodes(body: str) -> list[str]:
    """The mnemonic sequence, which is what makes two functions siblings."""
    out = []
    for line in body.splitlines():
        m = RE_MNEMONIC.match(line)
        if m:
            out.append(m.group(1))
    return out


def shingles(ops: list[str], n: int = NGRAM) -> set[str]:
    if len(ops) < n:
        return {" ".join(ops)} if ops else set()
    return {" ".join(ops[i : i + n]) for i in range(len(ops) - n + 1)}


def minhash(items: set[str], num_hashes: int = NUM_HASHES) -> tuple[int, ...]:
    """Signature whose collision probability approximates Jaccard similarity."""
    if not items:
        return tuple([0] * num_hashes)
    signature = [0xFFFFFFFFFFFFFFFF] * num_hashes
    for item in items:
        base = int.from_bytes(hashlib.blake2b(item.encode(), digest_size=8).digest(), "big")
        for i in range(num_hashes):
            # Cheap independent-ish hash family: mix the base with the index.
            h = (base * (2 * i + 1) + i * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
            if h < signature[i]:
                signature[i] = h
    return tuple(signature)


def jaccard(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    if not a or not b:
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def cluster(bodies: dict[int, str], band_size: int = BAND_SIZE,
            min_ops: int = 6) -> dict[int, int]:
    """Group addresses into families. Returns addr -> family id.

    Banded LSH: two functions land in the same family when any band of their
    signatures matches exactly. Functions too small to have a shape get no
    family, because grouping thunks by accident helps nobody.
    """
    signatures: dict[int, tuple[int, ...]] = {}
    for addr, body in bodies.items():
        ops = opcodes(body)
        if len(ops) < min_ops:
            continue
        signatures[addr] = minhash(shingles(ops))

    buckets: dict[tuple, set[int]] = defaultdict(set)
    for addr, sig in signatures.items():
        for band_index in range(0, len(sig), band_size):
            band = sig[band_index : band_index + band_size]
            buckets[(band_index, band)].add(addr)

    # Union-find over the bucket collisions.
    parent: dict[int, int] = {a: a for a in signatures}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            # Lowest address wins, so family membership is stable across runs.
            parent[max(rx, ry)] = min(rx, ry)

    for members in buckets.values():
        if len(members) < 2:
            continue
        ordered = sorted(members)
        for other in ordered[1:]:
            union(ordered[0], other)

    roots: dict[int, int] = {}
    families: dict[int, int] = {}
    next_id = 1
    for addr in sorted(signatures):
        root = find(addr)
        if root not in roots:
            roots[root] = next_id
            next_id += 1
        families[addr] = roots[root]
    return families


def summarize(families: dict[int, int]) -> list[Family]:
    grouped: dict[int, list[int]] = defaultdict(list)
    for addr, fid in families.items():
        grouped[fid].append(addr)
    return sorted(
        (Family(id=fid, members=sorted(members)) for fid, members in grouped.items()),
        key=lambda f: (-f.size, f.id),
    )
