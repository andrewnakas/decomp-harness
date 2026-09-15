"""Structural checks on a model's answer, before anything expensive happens.

A lint pass costs milliseconds; a build costs seconds to minutes, and a session
costs minutes plus a play-through. Catching a malformed answer here is the
cheapest correction in the loop, and several of these checks exist because the
corresponding mistake reached a session once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..llm.schemas import PortAnswer

# Calling an import directly skips the context threading the runtime needs.
RE_DIRECT_IMPORT = re.compile(r"\b__imp__\w+\s*\(")
# The harness generates all of this; a model that writes it is not following the
# contract, and the duplicate would not compile.
RE_SCAFFOLDING = re.compile(
    r"^\s*(?:#include\b|namespace\s+\w+|DEFINE_REX_FUNC\b|REX_FUNC\s*\(|"
    r"SKATE3_PORT\b|bool\s+Windows\s*\()",
    re.MULTILINE,
)
RE_STORE = re.compile(r"\bREX_(?:MM_)?STORE_\w+\s*\(")
RE_GUEST_CALL = re.compile(r"\bGuestCall\s*\(")
RE_SUB_CALL = re.compile(r"\bsub_[0-9A-Fa-f]{8}\s*\(")
RE_BALANCED = re.compile(r"[{}]")
# The body assigning a register the caller will read.
RE_RESULT_WRITE = re.compile(r"\bctx\.(r3|f1|v1)\.\w+\s*=")
# Registers a PowerPC function receives its arguments in.
ENTRY_REGISTERS = frozenset(f"r{n}" for n in range(3, 11))


@dataclass
class LintIssue:
    check: str
    message: str
    severity: str = "error"     # error blocks the build; warn is advisory

    def line(self) -> str:
        return f"{self.severity}\t{self.check}\t{self.message}"


@dataclass
class LintResult:
    addr: int
    issues: list[LintIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "error"]

    def brief(self) -> str:
        if self.ok and not self.issues:
            return f"sub_{self.addr:08X}\tlint ok"
        return "\n".join(i.line() for i in self.issues)

    def feedback(self) -> str:
        """What to send back on a retry: the failures, nothing else."""
        return "\n".join(f"- {i.check}: {i.message}" for i in self.errors)


def check(answer: PortAnswer, expected_addr: int | None = None,
          budget_bytes: int = 32768, budget_spans: int = 32) -> LintResult:
    """Validate one answer. Returns every problem, not just the first."""
    from ..core.db import parse_addr

    issues: list[LintIssue] = []
    try:
        addr = parse_addr(answer.addr)
    except ValueError:
        addr = expected_addr or 0
        issues.append(LintIssue("addr", f"'{answer.addr}' is not an address"))

    if expected_addr is not None and addr != expected_addr:
        issues.append(LintIssue(
            "addr",
            f"answered for sub_{addr:08X} but the packet asked about "
            f"sub_{expected_addr:08X}",
        ))

    code = answer.code or ""
    if not code.strip():
        issues.append(LintIssue("code", "empty body"))

    if RE_SCAFFOLDING.search(code):
        issues.append(LintIssue(
            "scaffolding",
            "the body must contain statements only: the harness writes the "
            "includes, the namespace, the signature and the registration macro",
        ))

    if RE_DIRECT_IMPORT.search(code):
        issues.append(LintIssue(
            "direct_import",
            "an import is called directly; route it through GuestCall so the "
            "context is threaded",
        ))

    opens = code.count("{")
    closes = code.count("}")
    if opens != closes:
        issues.append(LintIssue(
            "braces", f"unbalanced braces: {opens} open, {closes} close"
        ))

    if RE_SUB_CALL.search(code) and not RE_GUEST_CALL.search(code):
        issues.append(LintIssue(
            "guest_call",
            "a guest function is called directly; use GuestCall(ctx, base, sub_X)",
            severity="warn",
        ))

    # The two ways an answer can prove nothing at all.
    writes = RE_STORE.search(code)
    if not answer.blocked:
        if not answer.windows and not answer.result_registers:
            issues.append(LintIssue(
                "vacuous",
                "no windows and no result registers, so a comparison would "
                "check nothing; declare what the caller reads, or set `blocked`",
            ))
        if writes and not answer.windows:
            issues.append(LintIssue(
                "undeclared_writes",
                "the body writes guest memory but declares no windows; an "
                "undeclared write is never rewound and reaches the running program",
            ))

    if answer.blocked and not answer.note.strip():
        issues.append(LintIssue(
            "blocked_unexplained", "`blocked` is set without saying why in `note`"
        ))

    total = sum(w.length for w in answer.windows)
    if len(answer.windows) > budget_spans:
        issues.append(LintIssue(
            "window_spans",
            f"{len(answer.windows)} spans exceeds the budget of {budget_spans}",
        ))
    if total > budget_bytes:
        issues.append(LintIssue(
            "window_bytes",
            f"{total} bytes of windows exceeds the budget of {budget_bytes}",
        ))
    for w in answer.windows:
        if w.length <= 0:
            issues.append(LintIssue("window_length", f"window at {w.base} has length {w.length}"))
        if not w.base:
            issues.append(LintIssue("window_base", "a window has no base register"))
            continue
        # A window has to start from something the oracle can evaluate before
        # the call. Anything else is a register the body itself computed, and
        # the oracle would rewind whatever address happened to be there.
        base = w.base.lower()
        if base not in ENTRY_REGISTERS and base != "r1":
            issues.append(LintIssue(
                "window_base",
                f"window base '{w.base}' is not an argument register; windows "
                f"must start from r3-r10, following `deref` to reach a pointer",
            ))
        elif base != "r3" and code and f"ctx.{base}." not in code:
            # A register the body never reads is not a base it can have meant.
            # One live answer declared a window on r7 in a function that only
            # ever touches r3, which would have rewound an unrelated address.
            issues.append(LintIssue(
                "window_base_unused",
                f"window base '{w.base}' is never read by the body, so it cannot "
                f"be where that write lands",
            ))

    # The mistake this catches: copying a hint like [r3+4]+336 as a window at
    # r3+336, which rewinds the command record instead of the object it points
    # to, so the real writes reach the running program unreverted.
    hinted_deref = {w.base.lower() for w in answer.windows if w.deref}
    if code and not hinted_deref:
        loads_pointer = re.search(
            r"=\s*REX_(?:MM_)?LOAD_U32\s*\(\s*ctx\.r\d+\.u32", code
        )
        writes_through_local = re.search(r"REX_(?:MM_)?STORE_\w+\s*\(\s*(?!ctx\.)\w+", code)
        if loads_pointer and writes_through_local and answer.windows:
            issues.append(LintIssue(
                "window_deref",
                "the body loads a pointer and writes through it, but no window "
                "declares a `deref`; a window rooted at the argument register "
                "would rewind the wrong address",
            ))

    # A return value nobody compares is a comparison that cannot fail.
    if not answer.blocked and RE_RESULT_WRITE.search(code) and not answer.result_registers:
        issues.append(LintIssue(
            "result_undeclared",
            "the body assigns a result register but declares none in "
            "`result_registers`, so the returned value would never be compared",
        ))

    for f in answer.fields:
        if f.offset < 0 or f.size <= 0:
            issues.append(LintIssue(
                "field", f"{f.struct}.{f.name} has offset {f.offset} size {f.size}"
            ))

    if len(answer.note) > 300:
        issues.append(LintIssue("note_length", "note exceeds 300 characters",
                                severity="warn"))

    return LintResult(addr=addr, issues=issues)
