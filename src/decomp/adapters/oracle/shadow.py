"""The shadow oracle: run both bodies against the same state and compare.

Implemented on top of the session runner, which owns the details of launching
the program. This module is the part that satisfies the oracle contract, so a
byte-match or emulator oracle can be swapped in without the pipeline noticing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import DIVERGED, Oracle, OraclePlan, OracleRun, OracleVerdict

if TYPE_CHECKING:
    from ...core.config import Project


class ShadowOracle(Oracle):
    id = "rexglue_shadow"
    kind = "shadow"

    def __init__(self, project: Project, controls: int = 2):
        self.project = project
        self.controls = controls

    def prepare(self, candidates: list[int]) -> OraclePlan:
        verified = [
            r["addr"]
            for r in self.project.db.query(
                "SELECT addr FROM port WHERE status IN ('verified','promoted') "
                "AND path IS NOT NULL LIMIT ?", (self.controls,)
            )
        ]
        plan = OraclePlan(candidates=list(candidates), controls=verified)
        if not verified:
            plan.notes.append(
                "no verified port to mutate into a control yet, so this run "
                "cannot demonstrate that it is able to fail"
            )
        return plan

    def run(self, plan: OraclePlan, transport, **options: Any) -> OracleRun:
        from ...pipeline.session import run as run_session

        result = run_session(
            self.project,
            profile=options.get("profile", "play"),
            host=transport.name if transport else "",
            duration_s=options.get("duration_s", 120),
            controls=len(plan.controls) or self.controls,
        )
        return OracleRun(
            id=str(result.session_id or ""),
            ok=result.ok,
            host=result.host,
            log_path=result.log_path,
            detail={"armed": result.armed, "calls": result.calls_total},
            error=result.refused,
        )

    def verdicts(self, run: OracleRun) -> list[OracleVerdict]:
        from ...adapters.session.shadow import parse_log

        if not run.log_path:
            return []
        try:
            text = open(run.log_path, errors="replace").read()
        except OSError:
            return []
        return [
            OracleVerdict(
                addr=v.addr, result=v.result, compared=v.compared,
                skipped=v.skipped, detail=v.divergence,
            )
            for v in parse_log(text).verdicts
        ]

    def divergence_fragment(self, verdict: OracleVerdict, max_tokens: int = 400) -> str:
        """The disagreement alone.

        A retry that re-sends the packet pays for it twice; what the author
        needs is the address that differed and what each side produced.
        """
        if verdict.result != DIVERGED:
            return ""
        lines = [f"{verdict.compared} call(s) compared before the disagreement."]
        if verdict.detail:
            lines.append(verdict.detail.strip()[: max_tokens * 3])
        if verdict.skipped:
            lines.append(
                f"{verdict.skipped} call(s) were skipped, so the window builder "
                f"declined them; that may be where the difference lives."
            )
        return "\n".join(lines)


def from_project(project: Project) -> ShadowOracle:
    return ShadowOracle(project, controls=project.get("oracle.controls", 2))
