"""`decomp status`: where the project stands, in a dozen lines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class StatusResult:
    target: dict[str, Any] | None
    functions: int
    corpus: int
    by_status: list[tuple[str, int]] = field(default_factory=list)
    by_tier: list[tuple[str, int]] = field(default_factory=list)
    subsystems: list[tuple[str, int, int]] = field(default_factory=list)
    last_build: dict[str, Any] | None = None
    last_session: dict[str, Any] | None = None
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_cost: float = 0.0

    def brief(self) -> str:
        lines = []
        if self.target:
            t = self.target
            base = t.get("base_addr") or 0
            lines.append(f"target\t{t.get('name')}\t{t.get('platform')}\t0x{base:08X}")
        else:
            lines.append("target\t(none)\trun `decomp import`")
        lines.append(f"functions\t{self.functions}\tcorpus\t{self.corpus}")
        if self.by_status:
            lines.append("status\t" + " ".join(f"{s}={n}" for s, n in self.by_status))
        if self.by_tier:
            lines.append("tiers\t" + " ".join(f"{s}={n}" for s, n in self.by_tier))
        for name, size, chosen in self.subsystems:
            mark = "*" if chosen else " "
            lines.append(f"subsystem{mark}\t{name}\t{size}")
        if self.last_build:
            b = self.last_build
            lines.append(
                f"build\t#{b['id']}\t{b.get('host')}\t"
                f"{'ok' if b.get('ok') else 'FAILED'}\tsyms={b.get('found_syms')}"
            )
        if self.last_session:
            s = self.last_session
            trust = "trusted" if s.get("trusted") else "UNTRUSTED (no failing control)"
            lines.append(f"session\t#{s['id']}\t{s.get('profile')}\t{trust}")
        lines.append(
            f"llm\t{self.llm_calls} calls\t{self.llm_tokens} tokens\t${self.llm_cost:.4f}"
        )
        return "\n".join(lines)


def run(project: Project) -> StatusResult:
    db = project.db
    return StatusResult(
        target=project.target_row(),
        functions=db.scalar("SELECT COUNT(*) FROM function", (), 0),
        corpus=db.scalar("SELECT COUNT(*) FROM function WHERE in_corpus=1", (), 0),
        by_status=[
            (r["status"] or "?", r["n"])
            for r in db.query(
                "SELECT status, COUNT(*) AS n FROM function WHERE in_corpus=1 "
                "GROUP BY status ORDER BY n DESC"
            )
        ],
        by_tier=[
            (r["tier"] or "?", r["n"])
            for r in db.query(
                "SELECT tier, COUNT(*) AS n FROM function WHERE in_corpus=1 AND tier IS NOT NULL "
                "GROUP BY tier ORDER BY tier"
            )
        ],
        subsystems=[
            (r["name"], r["size"] or 0, r["chosen"] or 0)
            for r in db.query("SELECT name, size, chosen FROM subsystem ORDER BY chosen DESC, id")
        ],
        last_build=db.one("SELECT * FROM build ORDER BY id DESC LIMIT 1"),
        last_session=db.one("SELECT * FROM session ORDER BY id DESC LIMIT 1"),
        llm_calls=db.scalar("SELECT COUNT(*) FROM llm_call", (), 0),
        llm_tokens=db.scalar(
            "SELECT COALESCE(SUM(input_tokens + output_tokens),0) FROM llm_call", (), 0
        ),
        llm_cost=db.scalar("SELECT COALESCE(SUM(cost_usd),0) FROM llm_call", (), 0.0) or 0.0,
    )
