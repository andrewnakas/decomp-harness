"""`decomp lint`: re-check written ports without building anything.

The harness generates the port files, so it can read them back. Worth running
after editing one by hand, and cheap enough to run over all of them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.db import addr_str

if TYPE_CHECKING:
    from ..core.config import Project

RE_NATIVE = re.compile(r"REX_FUNC\(Native\)\s*\{(?P<body>.*?)\n\}", re.DOTALL)
RE_MASK = re.compile(r"SKATE3_PORT\([0-9A-Fa-f]{8},\s*\w+,\s*(?P<mask>[^)]+)\)")
RE_REGISTER = re.compile(r"kReturn(R3|F1)|(?:Gpr|Fpr|Vr)\((\d+)\)")


@dataclass
class LintReport:
    checked: int = 0
    failures: list[tuple[int, str]] = field(default_factory=list)
    unreadable: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures and not self.unreadable

    def brief(self) -> str:
        lines = []
        for addr, detail in self.unreadable:
            lines.append(f"{addr_str(addr)}\tunreadable\t{detail}")
        for addr, detail in self.failures:
            lines.append(f"{addr_str(addr)}\n{detail}")
        lines.append(
            f"--\t{self.checked} checked\t{len(self.failures)} failing"
            + (f"\t{len(self.unreadable)} unreadable" if self.unreadable else "")
        )
        return "\n".join(lines)


def run(project: Project, addrs: list[int] | None = None) -> LintReport:
    from ..llm.schemas import PortAnswer
    from ..port import lint as lint_mod

    sql = "SELECT addr, path, windows_json, result_mask FROM port WHERE path IS NOT NULL"
    params: list = []
    if addrs:
        placeholders = ",".join("?" for _ in addrs)
        sql += f" AND addr IN ({placeholders})"
        params.extend(addrs)

    report = LintReport()
    for row in project.db.query(sql, tuple(params)):
        path = Path(row["path"])
        if not path.is_file():
            report.unreadable.append((row["addr"], f"{path.name} is gone"))
            continue
        text = path.read_text(errors="replace")
        body = RE_NATIVE.search(text)
        if not body:
            report.unreadable.append(
                (row["addr"], "no REX_FUNC(Native) body in the file")
            )
            continue

        try:
            windows = json.loads(row["windows_json"] or "[]")
        except (json.JSONDecodeError, TypeError):
            windows = []

        answer = PortAnswer(
            addr=f"{row['addr']:08X}",
            code=body.group("body").strip(),
            windows=windows,
            result_registers=_registers(text),
        )
        result = lint_mod.check(
            answer, expected_addr=row["addr"],
            budget_bytes=project.get("oracle.window_budget_bytes", 32768),
            budget_spans=project.get("oracle.window_budget_spans", 32),
        )
        report.checked += 1
        if not result.ok:
            report.failures.append((row["addr"], result.feedback()))
    return report


def _registers(text: str) -> list[str]:
    """Which registers the file says the caller reads."""
    mask = RE_MASK.search(text)
    if not mask:
        return []
    out = []
    for named, numbered in RE_REGISTER.findall(mask.group("mask")):
        if named == "R3":
            out.append("r3")
        elif named == "F1":
            out.append("f1")
        elif numbered:
            out.append(f"r{numbered}")
    return out
