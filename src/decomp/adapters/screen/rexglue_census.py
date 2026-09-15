"""Static gate screening over lifted C++.

Adapted from the audio project's census. What was a set of hardcoded regexes is
now a rules table, so the same screener serves any statically recompiled target
by swapping the patterns rather than the code.

The one judgment it encodes: a gate is often a property of one path, not of a
whole function. A function whose rare branch takes a lock is still comparable on
every call that does not take it, which is how nine gate-1 ports in the audio
project became partially verified rather than abandoned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import GateResult, GateScreener, StoreSite

if TYPE_CHECKING:
    from ...core.config import Project

RULES_VERSION = "1"

DEFAULT_RULES: dict[str, Any] = {
    # Constructs that cannot be replayed against rewound memory.
    "gate1_patterns": {
        "indirect call": r"REX_CALL_INDIRECT|REX_INDIRECT_CALL",
        "global lock": r"REX_ENTER_GLOBAL_LOCK|REX_LEAVE_GLOBAL_LOCK",
        "allocation": r"__imp__(?:Rtl(?:Allocate|Free)Heap|Ex(?:Allocate|Free)\w*|NtAllocate\w*)",
        "synchronisation": r"__imp__(?:Rtl(?:Enter|Leave)CriticalSection|KeSetEvent|NtWaitFor\w*)",
        "object release": r"__imp__(?:ObDereferenceObject|NtClose)",
    },
    "gate3_patterns": {
        "time base": r"REX_QUERY_TIMEBASE|__builtin_ppc_mftb",
        "clock import": r"__imp__(?:KeQuery\w*Time\w*|NtQuerySystemTime)",
    },
    # Stores whose address the harness must be able to predict.
    "store_pattern": r"\bREX_(?:MM_)?STORE_(U8|U16|U32|U64|F32|F64|V128|VL|VR)\b\s*\(",
    "load_pattern": r"\bREX_(?:MM_)?LOAD_(U8|U16|U32|U64|F32|F64|V128|VL|VR)\b\s*\(",
    "base_reg_pattern": r"ctx\.(r\d+)\.(?:u32|u64|s32|s64)",
    "stack_regs": ["r1"],
    "entry_regs": ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
    "label_pattern": r"^\s*(loc_[0-9A-Fa-f]{8}):",
    "goto_pattern": r"\bgoto\s+(loc_[0-9A-Fa-f]{8})\s*;",
}

STORE_WIDTHS = {
    "U8": 1, "U16": 2, "U32": 4, "U64": 8,
    "F32": 4, "F64": 8, "V128": 16, "VL": 16, "VR": 16,
}


@dataclass
class CensusRules:
    gate1: dict[str, re.Pattern] = field(default_factory=dict)
    gate3: dict[str, re.Pattern] = field(default_factory=dict)
    store: re.Pattern | None = None
    load: re.Pattern | None = None
    base_reg: re.Pattern | None = None
    label: re.Pattern | None = None
    goto: re.Pattern | None = None
    stack_regs: tuple[str, ...] = ("r1",)
    entry_regs: tuple[str, ...] = ()

    @classmethod
    def load_from(cls, data: dict[str, Any] | None = None) -> CensusRules:
        merged = {**DEFAULT_RULES, **(data or {})}
        return cls(
            gate1={k: re.compile(v) for k, v in merged["gate1_patterns"].items()},
            gate3={k: re.compile(v) for k, v in merged["gate3_patterns"].items()},
            store=re.compile(merged["store_pattern"]),
            load=re.compile(merged["load_pattern"]),
            base_reg=re.compile(merged["base_reg_pattern"]),
            label=re.compile(merged["label_pattern"]),
            goto=re.compile(merged["goto_pattern"]),
            stack_regs=tuple(merged["stack_regs"]),
            entry_regs=tuple(merged["entry_regs"]),
        )


class RexGlueCensus(GateScreener):
    id = "rexglue_census"
    rules_version = RULES_VERSION

    def __init__(self, rules: CensusRules | None = None,
                 window_budget_bytes: int = 32768, window_budget_spans: int = 32):
        self.rules = rules or CensusRules.load_from()
        self.budget_bytes = window_budget_bytes
        self.budget_spans = window_budget_spans

    # -------------------------------------------------------------- screen
    def screen(self, addr: int, body: str) -> GateResult:
        result = GateResult(addr=addr)
        if not body:
            result.gate = "gate2"
            result.reasons.append("no body available")
            return result

        lines = body.splitlines()
        assigned: dict[str, int] = {}     # register -> line it was last written
        # register -> (base register, offset) when it was loaded from memory.
        # A window whose base was loaded has to say where from, or the oracle
        # rewinds the wrong address.
        loaded_from: dict[str, tuple[str, int]] = {}
        loop_ranges = self._loop_ranges(lines)
        gate1_hits: list[str] = []
        gate3_hits: list[str] = []
        loads = 0

        for n, line in enumerate(lines):
            for why, pattern in self.rules.gate1.items():
                if pattern.search(line):
                    gate1_hits.append(f"{why} at line {n}")
            for why, pattern in self.rules.gate3.items():
                if pattern.search(line):
                    gate3_hits.append(f"{why} at line {n}")

            if self.rules.load and self.rules.load.search(line):
                loads += 1

            store = self.rules.store.search(line) if self.rules.store else None
            if store:
                site = self._classify_store(n, line, store.group(1), assigned,
                                            loop_ranges)
                site.derived_from = loaded_from.get(site.base_ref)
                result.stores.append(site)

            # Track register writes so a later store base can be called derived,
            # and remember simple loads so the derivation can be reproduced.
            load = self._simple_load(line)
            for reg in self._assigned_registers(line):
                assigned[reg] = n
                if load and load[0] == reg:
                    loaded_from[reg] = (load[1], load[2])
                else:
                    loaded_from.pop(reg, None)

        result.census = {
            "lines": len(lines),
            "stores": len(result.stores),
            "loads": loads,
            "loops": len(loop_ranges),
            "gate1_hits": gate1_hits,
            "gate3_hits": gate3_hits,
        }

        # Order matters: a nondeterministic function cannot be compared even if
        # its writes are perfectly enumerable, so gate 3 outranks gate 2.
        if gate3_hits:
            result.gate = "gate3"
            result.reasons = gate3_hits[:3]
            return result
        if gate1_hits:
            result.gate = "gate1"
            result.reasons = gate1_hits[:3]
            return result

        # A base computed during the call is a *suspicion*, not a verdict. A
        # pointer loaded from [r3+0x30] is still enumerable, because the window
        # builder can read that word before the call runs. The audio project's
        # census reported these as a count for exactly this reason: screening
        # gate 2 automatically would have failed its own verified functions,
        # including the command-queue producer that went on to compare 6,706
        # calls with zero divergence.
        derived = [s for s in result.stores if s.base == "derived"]
        loop_bound = [s for s in result.stores if s.base == "loop"]
        unknown = [s for s in result.stores if s.base == "unknown"]
        result.census["gate2_suspects"] = len(derived)

        if loop_bound:
            result.gate = "gate2"
            result.reasons = [
                f"{len(loop_bound)} store(s) inside a loop, so the write set is "
                f"data-dependent (first at line {loop_bound[0].line})"
            ]
            return result
        if unknown:
            result.gate = "gate2"
            result.reasons = [
                f"{len(unknown)} store(s) with an unrecognised base "
                f"(first at line {unknown[0].line})"
            ]
            return result

        span_bytes = sum(s.size for s in result.stores)
        if len(result.stores) > self.budget_spans:
            result.gate = "gate2"
            result.reasons = [f"{len(result.stores)} spans exceeds budget {self.budget_spans}"]
            return result
        if span_bytes > self.budget_bytes:
            result.gate = "gate2"
            result.reasons = [f"{span_bytes} bytes exceeds budget {self.budget_bytes}"]
            return result

        if not result.stores:
            # Nothing observable in memory. Not fatal: the oracle can compare
            # named result registers instead, which is how gate 4 was retired.
            result.gate = "gate4"
            result.reasons = ["no stores; compare result registers instead"]
            return result

        result.suggested_windows = []
        for s in result.stores:
            window = {
                "base": s.base_ref or "r3",
                "offset": s.offset,
                "len": s.size,
                "line": s.line,
                "needs_deref": s.base == "derived",
            }
            if s.derived_from:
                # Say exactly how to reach the base: load from this register at
                # this offset, then apply the window offset. Leaving it implicit
                # invites a window rooted at the wrong address.
                window["base"] = s.derived_from[0]
                window["deref"] = [s.derived_from[1]]
            result.suggested_windows.append(window)
        if derived:
            result.reasons.append(
                f"{len(derived)} window base(s) must be read before the call"
            )
        return result

    # ------------------------------------------------------------ internals
    def _loop_ranges(self, lines: list[str]) -> list[tuple[int, int]]:
        """Line ranges enclosed by a backward branch: the bodies of loops.

        A store inside one runs an unknown number of times, so its addresses
        cannot be enumerated from the entry state.
        """
        label_line: dict[str, int] = {}
        ranges: list[tuple[int, int]] = []
        for n, line in enumerate(lines):
            if self.rules.label:
                m = self.rules.label.match(line)
                if m:
                    label_line[m.group(1)] = n
            if self.rules.goto:
                m = self.rules.goto.search(line)
                if m:
                    head = label_line.get(m.group(1))
                    if head is not None and head <= n:
                        ranges.append((head, n))
        return ranges

    def _simple_load(self, line: str) -> tuple[str, str, int] | None:
        """Match `ctx.rD.u64 = REX_LOAD_U32(ctx.rB.u32 + K);` -> (rD, rB, K)."""
        m = re.search(
            r"ctx\.(r\d+)\.\w+\s*=\s*REX_(?:MM_)?LOAD_\w+\s*\(\s*"
            r"ctx\.(r\d+)\.\w+\s*(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)",
            line,
        )
        if not m:
            return None
        offset = int(m.group(3), 0) if m.group(3) else 0
        return m.group(1), m.group(2), offset

    def _assigned_registers(self, line: str) -> list[str]:
        out = []
        for m in re.finditer(r"ctx\.(r\d+)\.(?:u32|u64|s32|s64)\s*=", line):
            out.append(m.group(1))
        return out

    def _classify_store(self, line_no: int, line: str, width_key: str,
                        assigned: dict[str, int],
                        loop_ranges: list[tuple[int, int]]) -> StoreSite:
        """Where does this store's address come from?

        entry    an argument register never written before this point
        stack    the frame pointer; never windowed, never compared
        derived  computed from something loaded during the call
        loop     inside a backward branch, so the count is data-dependent
        """
        size = STORE_WIDTHS.get(width_key, 4)
        regs = self.rules.base_reg.findall(line) if self.rules.base_reg else []
        base_ref = regs[0] if regs else ""
        offset = _literal_offset(line)

        if base_ref in self.rules.stack_regs:
            base = "stack"
        elif not base_ref:
            base = "global" if "0x" in line else "unknown"
        elif base_ref in assigned:
            base = "derived"
        elif base_ref in self.rules.entry_regs:
            base = "entry"
        else:
            base = "unknown"

        if base != "stack" and _within_loop(line_no, loop_ranges):
            # A store under a backward branch runs an unknown number of times,
            # so the bytes it touches are not knowable before the call.
            base = "loop"

        return StoreSite(
            line=line_no, mnemonic=width_key, base=base, base_ref=base_ref,
            offset=offset, size=size,
        )


def _literal_offset(line: str) -> int | None:
    m = re.search(r"\.u(?:32|64)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)", line)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            return None
    return None


def _within_loop(line_no: int, loop_ranges: list[tuple[int, int]]) -> bool:
    return any(head <= line_no <= tail for head, tail in loop_ranges)


def from_project(project: Project) -> RexGlueCensus:
    rules_path = project.get("screen.rules_file")
    data = None
    if rules_path and Path(rules_path).is_file():
        import tomllib

        data = tomllib.loads(Path(rules_path).read_text())
    return RexGlueCensus(
        rules=CensusRules.load_from(data),
        window_budget_bytes=project.get("oracle.window_budget_bytes", 32768),
        window_budget_spans=project.get("oracle.window_budget_spans", 32),
    )
