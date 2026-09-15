"""`decomp loop`: one round of the whole cycle.

Take work from the queue, draft or port it, lint it, build it, run a session,
read the verdicts, promote what earned it. Every stage is resumable on its own,
so a killed round costs the round and not the project.

The loop stops at the first stage that refuses. A refusal is information: a
build that did not produce the symbols, or a session with no failing control,
means the rest of the round would be measuring nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class RoundResult:
    round: int
    picked: int = 0
    drafted: int = 0
    ported: int = 0
    blocked: int = 0
    failed: int = 0
    verified: int = 0
    promoted: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    stopped_at: str = ""
    why: str = ""
    stages: list[str] = field(default_factory=list)

    def brief(self) -> str:
        lines = [f"round {self.round}"]
        lines.extend(f"  {s}" for s in self.stages)
        if self.stopped_at:
            lines.append(f"  stopped at {self.stopped_at}: {self.why}")
        lines.append(
            f"  picked={self.picked} drafted={self.drafted} ported={self.ported} "
            f"blocked={self.blocked} failed={self.failed}"
        )
        if self.verified or self.promoted:
            lines.append(f"  verified={self.verified} promoted={self.promoted}")
        lines.append(f"  {self.tokens} tokens\t${self.cost_usd:.4f}")
        if self.ported or self.drafted:
            written = self.ported + self.drafted
            lines.append(f"  per written port\t{self.tokens // max(1, written)} tokens")
        return "\n".join(lines)


@dataclass
class LoopResult:
    rounds: list[RoundResult] = field(default_factory=list)

    @property
    def tokens(self) -> int:
        return sum(r.tokens for r in self.rounds)

    @property
    def cost(self) -> float:
        return sum(r.cost_usd for r in self.rounds)

    @property
    def verified(self) -> int:
        return sum(r.verified for r in self.rounds)

    def brief(self) -> str:
        lines = [r.brief() for r in self.rounds]
        written = sum(r.ported + r.drafted for r in self.rounds)
        lines.append(
            f"--\t{len(self.rounds)} round(s)\twritten={written}"
            f"\tverified={self.verified}\t{self.tokens} tokens\t${self.cost:.4f}"
        )
        return "\n".join(lines)


def run(project: Project, n: int = 8, rounds: int = 1, tier: str = "",
        subsystem: str = "", provider: str = "", host: str = "",
        profile: str = "play", duration_s: int = 120, controls: int = 2,
        verify_only: bool = False, no_session: bool = False,
        port_only: bool = False, max_cost_usd: float = 0.0,
        on_round=None) -> LoopResult:
    """Run the cycle `rounds` times, stopping early on a refusal.

    `port_only` authors and lints without building or running anything, which is
    what an unattended run does when there is no machine to verify on. Those
    ports are recorded as written, never as verified, because nothing has
    checked them.
    """
    from . import build as build_stage
    from . import port as port_stage
    from . import promote as promote_stage
    from . import queue as queue_stage
    from . import session as session_stage
    from . import verify as verify_stage

    result = LoopResult()

    for index in range(1, rounds + 1):
        round_result = RoundResult(round=index)

        # --- pick ----------------------------------------------------------
        picks = queue_stage.next_items(project, tier=tier, limit=n,
                                       subsystem=subsystem)
        round_result.picked = len(picks.items)
        if not picks.items:
            round_result.stopped_at = "queue"
            round_result.why = "nothing open to work on"
            result.rounds.append(round_result)
            if on_round is not None:
                on_round(round_result)
            break
        round_result.stages.append(
            f"queue\tpicked {len(picks.items)} of {picks.total_open} open"
        )

        # --- port ----------------------------------------------------------
        ports = port_stage.port_many(
            project, [i.addr for i in picks.items], provider_name=provider or None
        )
        round_result.drafted = sum(
            1 for o in ports.outcomes if o.ok and o.model == "mechanical"
        )
        round_result.ported = ports.written - round_result.drafted
        round_result.blocked = ports.blocked
        round_result.failed = ports.failed
        round_result.tokens = ports.tokens
        round_result.cost_usd = ports.cost
        round_result.stages.append(
            f"port\twritten={ports.written} (mechanical={round_result.drafted}) "
            f"blocked={ports.blocked} failed={ports.failed}\t{ports.tokens} tokens"
        )

        if max_cost_usd and result.cost + round_result.cost_usd > max_cost_usd:
            round_result.stopped_at = "budget"
            round_result.why = f"would exceed ${max_cost_usd:.2f}"
            result.rounds.append(round_result)
            break

        if not ports.written:
            round_result.stopped_at = "port"
            round_result.why = "nothing was written, so there is nothing to build"
            result.rounds.append(round_result)
            if on_round is not None:
                on_round(round_result)
            break

        if port_only:
            round_result.stages.append(
                "build\tskipped: authoring only, so nothing is verified"
            )
            result.rounds.append(round_result)
            if on_round is not None:
                on_round(round_result)
            continue

        # --- build ---------------------------------------------------------
        # A stage that is not configured yet is a stop with an instruction, not
        # a traceback: the loop should say what to set and leave the written
        # ports in place for when it is set.
        try:
            built = build_stage.run(project, host=host)
        except (KeyError, ValueError, FileNotFoundError) as exc:
            round_result.stopped_at = "build"
            round_result.why = str(exc).strip("'")
            result.rounds.append(round_result)
            break
        round_result.stages.append(built.brief().splitlines()[0])
        if not built.ok:
            round_result.stopped_at = "build"
            round_result.why = built.why
            result.rounds.append(round_result)
            break

        if no_session:
            round_result.stopped_at = "session"
            round_result.why = "skipped by request"
            result.rounds.append(round_result)
            continue

        # --- session -------------------------------------------------------
        try:
            ran = session_stage.run(project, profile=profile, host=host,
                                    duration_s=duration_s, controls=controls)
        except (KeyError, ValueError, FileNotFoundError) as exc:
            round_result.stopped_at = "session"
            round_result.why = str(exc).strip("'")
            result.rounds.append(round_result)
            break
        round_result.stages.append(ran.brief().splitlines()[0])
        if not ran.ok:
            round_result.stopped_at = "session"
            round_result.why = ran.refused or "the session did not complete"
            result.rounds.append(round_result)
            break

        # --- verify and promote --------------------------------------------
        verified = verify_stage.run(project, session_id=ran.session_id)
        round_result.verified = verified.by_result.get("verified", 0)
        round_result.stages.append(verified.brief().splitlines()[0])
        if not verified.trusted:
            round_result.stopped_at = "verify"
            round_result.why = verified.control_summary
            result.rounds.append(round_result)
            break

        promoted = promote_stage.run(project)
        round_result.promoted = promoted.promoted
        round_result.stages.append(
            f"promote\tpromoted={promoted.promoted} held={promoted.held}"
        )
        result.rounds.append(round_result)
        if on_round is not None:
            on_round(round_result)

    return result
