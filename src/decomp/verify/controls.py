"""Negative controls: proof that the oracle can still fail.

A session in which everything passes is indistinguishable from a session in
which nothing was actually compared. The only way to tell them apart is to arm a
port that is deliberately wrong and require it to be caught.

The audio project learned the sharper version of this the hard way. One control
script's anchor text matched twice, so the mutation aborted and the file was
never changed; the "control" then passed as an unmodified port, and the run
looked validated. So a control is not trusted unless the harness can confirm the
mutation is present in what was built.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from pathlib import Path

# Each mutation changes observable behaviour in a different way, so a control
# cannot pass by accident of which comparison the oracle happens to run.
MUTATIONS = (
    ("offset", re.compile(r"(REX_STORE_\w+\s*\(\s*[^,]+?)\+\s*(\d+)"), "shift a store offset"),
    ("value", re.compile(r"(REX_STORE_U32\s*\([^,]+,\s*)([A-Za-z_][\w.]*)\s*\)"),
     "perturb a stored value"),
    ("result", re.compile(r"(ctx\.r3\.(?:u32|u64|s32|s64)\s*=\s*)(\w+)"),
     "perturb the return value"),
)


@dataclass
class Control:
    addr: int
    kind: str
    description: str
    source_path: Path
    mutated_path: Path
    applied: bool = False
    original_line: str = ""
    mutated_line: str = ""

    def brief(self) -> str:
        state = "applied" if self.applied else "NOT APPLIED"
        return f"control\tsub_{self.addr:08X}\t{self.kind}\t{state}\t{self.description}"


@dataclass
class ControlOutcome:
    controls: list[Control] = field(default_factory=list)
    caught: list[int] = field(default_factory=list)
    missed: list[int] = field(default_factory=list)

    @property
    def armed(self) -> int:
        return sum(1 for c in self.controls if c.applied)

    @property
    def ok(self) -> bool:
        """Every applied control must have been caught, and there must be one."""
        return bool(self.armed) and not self.missed

    def why(self) -> str:
        if not self.controls:
            return "no controls were armed, so this session proves nothing"
        if not self.armed:
            return (
                "no mutation could be applied to any control, so the 'controls' "
                "are unmodified ports and would pass regardless"
            )
        if self.missed:
            names = " ".join(f"sub_{a:08X}" for a in self.missed[:4])
            return f"{len(self.missed)} control(s) were not caught: {names}"
        return f"{self.armed} control(s) armed and all caught"

    def brief(self) -> str:
        lines = [c.brief() for c in self.controls]
        lines.append(("ok" if self.ok else "UNTRUSTED") + f"\t{self.why()}")
        return "\n".join(lines)


def mutate(source: str, seed: int | None = None) -> tuple[str, str, str, str] | None:
    """Introduce one behavioural change into a port body.

    Returns (kind, mutated source, original line, mutated line), or None when no
    mutation site was found - which the caller must treat as a failed control,
    not as a passing one.
    """
    rng = random.Random(seed)
    candidates = []
    for kind, pattern, description in MUTATIONS:
        for m in pattern.finditer(source):
            candidates.append((kind, pattern, description, m))
    if not candidates:
        return None

    kind, pattern, description, match = candidates[rng.randrange(len(candidates))]
    start, end = match.span()
    original = match.group(0)

    if kind == "offset":
        shifted = int(match.group(2)) + 2
        replacement = f"{match.group(1)}+ {shifted}"
    elif kind == "value":
        replacement = f"{match.group(1)}({match.group(2)} ^ 1u))"
    else:
        replacement = f"{match.group(1)}({match.group(2)} + 1)"

    mutated = source[:start] + replacement + source[end:]
    return kind, mutated, original, replacement


def build_controls(ports: list[tuple[int, Path]], out_dir: Path, count: int = 2,
                   seed: int | None = None) -> list[Control]:
    """Make deliberately wrong copies of verified ports."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    chosen = list(ports)
    rng.shuffle(chosen)

    controls: list[Control] = []
    for addr, path in chosen:
        if len(controls) >= count:
            break
        if not path.is_file():
            continue
        source = path.read_text()
        result = mutate(source, seed=seed)
        mutated_path = out_dir / f"control_{addr:08X}.inc"
        if result is None:
            # Recorded as a control that could not be applied. Silence here is
            # exactly how a control passes without testing anything.
            controls.append(Control(
                addr=addr, kind="none",
                description="no mutation site found in this port",
                source_path=path, mutated_path=mutated_path, applied=False,
            ))
            continue
        kind, mutated, original, replacement = result
        mutated_path.write_text(mutated)
        controls.append(Control(
            addr=addr, kind=kind,
            description=f"{original.strip()[:40]} -> {replacement.strip()[:40]}",
            source_path=path, mutated_path=mutated_path, applied=True,
            original_line=original, mutated_line=replacement,
        ))
    return controls


def confirm_applied(control: Control) -> bool:
    """Is the mutation actually present in the file that will be built?"""
    if not control.applied or not control.mutated_path.is_file():
        return False
    text = control.mutated_path.read_text()
    return control.mutated_line in text and text != control.source_path.read_text()


def evaluate(controls: list[Control], diverged: set[int]) -> ControlOutcome:
    """A control passes the check by being caught."""
    outcome = ControlOutcome(controls=controls)
    for c in controls:
        if not c.applied:
            continue
        if c.addr in diverged:
            outcome.caught.append(c.addr)
        else:
            outcome.missed.append(c.addr)
    return outcome
