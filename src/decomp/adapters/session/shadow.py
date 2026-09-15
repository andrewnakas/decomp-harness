"""A shadow session against a recompilation, and how to read its log."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import FunctionVerdict, SessionRun, SessionRunner, SessionSummary

if TYPE_CHECKING:
    from ...core.config import Project
    from ...core.remote import Transport

# The log lines a shadow harness emits. Patterns live here rather than in the
# pipeline so a different harness only needs a different adapter.
RE_CLEAN = re.compile(
    r"\bsub_([0-9A-Fa-f]{8})\b.*?\b(?:clean|verified|no divergence)\b"
    r".*?(?:(\d+)\s+(?:comparable\s+)?calls?)?",
    re.IGNORECASE,
)
RE_DIVERGE = re.compile(
    r"\bsub_([0-9A-Fa-f]{8})\b.*?\bdiverge\w*\b(?P<detail>.*)$", re.IGNORECASE
)
RE_COUNTS = re.compile(
    r"\bsub_([0-9A-Fa-f]{8})\b[^\n]*?compared[=: ]+(\d+)[^\n]*?skipped[=: ]+(\d+)",
    re.IGNORECASE,
)
RE_OVERFLOW = re.compile(r"\bsub_([0-9A-Fa-f]{8})\b.*?\boverflow\b", re.IGNORECASE)
RE_TOTAL = re.compile(r"\b(\d+)\s+total calls\b", re.IGNORECASE)


class ShadowSession(SessionRunner):
    id = "shadow"

    def __init__(self, command: str, log_path: str, flags: list[str] | None = None,
                 required_flags: list[str] | None = None, env: dict | None = None):
        self.command = command
        self.log_path = log_path
        self.flags = flags or []
        self.required_flags = required_flags or []
        self.env = env or {}

    def build_command(self, label: str, profile: str, duration_s: int) -> str:
        parts = [self.command, *self.required_flags, *self.flags]
        parts.append(f"--profile={profile}" if "{profile}" not in self.command else "")
        command = " ".join(p for p in parts if p)
        return command.replace("{label}", label).replace("{profile}", profile) \
                      .replace("{duration}", str(duration_s))

    def run(self, transport: Transport, label: str, profile: str,
            armed: list[int], duration_s: int = 120) -> SessionRun:
        command = self.build_command(label, profile, duration_s)
        log = self.log_path.replace("{label}", label)
        # A session is long and the program may ignore a polite signal, so the
        # command is expected to bound itself; the timeout is a backstop.
        result = transport.run(command, timeout=duration_s + 300)
        raw = ""
        if transport.exists(log):
            fetched = transport.run(f"cat {log}", timeout=120)
            raw = fetched.stdout if fetched.ok else ""
        else:
            raw = result.stdout + "\n" + result.stderr

        total = 0
        m = RE_TOTAL.search(raw)
        if m:
            total = int(m.group(1))

        return SessionRun(
            label=label, host=transport.name, profile=profile, log_path=log,
            ok=result.ok or bool(raw), duration_s=result.duration_s,
            calls_total=total, raw=raw,
            error="" if result.ok else result.tail(6),
        )

    def summarize(self, run: SessionRun) -> SessionSummary:
        return parse_log(run.raw)


def parse_log(text: str) -> SessionSummary:
    """Turn a session log into one verdict per function.

    A function that was armed and never compared is reported as such rather than
    quietly omitted: the audio project once shipped a clean session in which one
    consumer had produced a record that was never consumed, and only the
    milestone counts revealed it.
    """
    verdicts: dict[int, FunctionVerdict] = {}
    notes: list[str] = []
    total = 0

    def entry(addr: int) -> FunctionVerdict:
        return verdicts.setdefault(addr, FunctionVerdict(addr=addr, result="uncalled"))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = RE_TOTAL.search(stripped)
        if m:
            total = max(total, int(m.group(1)))

        m = RE_COUNTS.search(stripped)
        if m:
            v = entry(int(m.group(1), 16))
            v.compared = int(m.group(2))
            v.skipped = int(m.group(3))
            if v.result == "uncalled" and v.compared:
                v.result = "verified"

        m = RE_DIVERGE.search(stripped)
        if m:
            v = entry(int(m.group(1), 16))
            v.result = "diverged"
            v.divergence = (m.group("detail") or stripped).strip()[:300]
            continue

        m = RE_OVERFLOW.search(stripped)
        if m:
            v = entry(int(m.group(1), 16))
            v.result = "overflow"
            continue

        m = RE_CLEAN.search(stripped)
        if m:
            v = entry(int(m.group(1), 16))
            if v.result != "diverged":
                v.result = "verified"
                if m.group(2):
                    v.compared = max(v.compared, int(m.group(2)))

    # A comparison that never ran proves nothing, whatever the log called it.
    for v in verdicts.values():
        if v.result == "verified" and v.compared == 0:
            v.result = "uncalled"
            notes.append(f"sub_{v.addr:08X} reported clean but compared nothing")

    return SessionSummary(
        verdicts=sorted(verdicts.values(), key=lambda v: v.addr),
        calls_total=total, notes=notes,
    )


def from_project(project: Project) -> ShadowSession:
    cfg = project.get("session", {}) or {}
    command = cfg.get("command")
    if not command:
        raise KeyError(
            "set session.command in decomp.toml: how to launch the program with "
            "the shadow harness armed"
        )
    return ShadowSession(
        command=command,
        log_path=cfg.get("log_path", "session-{label}.log"),
        flags=cfg.get("flags", []),
        required_flags=cfg.get("required_flags", []),
        env=cfg.get("env", {}),
    )
