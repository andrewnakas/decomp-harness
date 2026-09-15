"""`decomp auto`: keep going without being watched.

An unattended run needs reasons to stop that are not "the money ran out". This
one stops on any of:

  * the queue is empty
  * the spend ceiling is reached
  * the wall-clock limit is reached
  * rounds keep failing, which means the setup is wrong and continuing would
    turn a broken configuration into a bill

The last is the one that matters. A provider that is not signed in, a schema the
API rejects, a build host that is unreachable: each fails every round in the same
way, and a loop without a circuit breaker will happily pay for all of them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .loop import RoundResult

# An unattended run needs a reason to stop that is not "the money ran out".
# A provider that is not signed in, a schema the API rejects, a build host that
# is unreachable: each fails every round in the same way, and a loop without a
# circuit breaker will happily pay for all of them.
MAX_CONSECUTIVE_FAILED_ROUNDS = 2

# A round where most of the batch failed is a broken round, not a hard one.
FAILURE_RATE_LIMIT = 0.75

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class AutoResult:
    rounds: list[RoundResult] = field(default_factory=list)
    stopped_because: str = ""
    elapsed_s: float = 0.0
    started_pending: int = 0
    remaining: int = 0

    @property
    def written(self) -> int:
        return sum(r.ported + r.drafted for r in self.rounds)

    @property
    def mechanical(self) -> int:
        return sum(r.drafted for r in self.rounds)

    @property
    def blocked(self) -> int:
        return sum(r.blocked for r in self.rounds)

    @property
    def failed(self) -> int:
        return sum(r.failed for r in self.rounds)

    @property
    def tokens(self) -> int:
        return sum(r.tokens for r in self.rounds)

    @property
    def cost(self) -> float:
        return sum(r.cost_usd for r in self.rounds)

    def brief(self) -> str:
        minutes = self.elapsed_s / 60
        lines = [
            f"stopped\t{self.stopped_because}",
            f"rounds\t{len(self.rounds)}\t{minutes:.0f} min",
            f"written\t{self.written}\t(mechanical {self.mechanical}, "
            f"model {self.written - self.mechanical})",
            f"blocked\t{self.blocked}\tfailed\t{self.failed}",
            f"spent\t{self.tokens} tokens\t${self.cost:.2f}",
        ]
        if self.written:
            lines.append(f"per written port\t{self.tokens // self.written} tokens")
        if self.started_pending:
            done = self.started_pending - self.remaining
            lines.append(
                f"progress\t{done} of {self.started_pending}"
                f"\t{self.remaining} still to do"
            )
        lines.append(
            "note\tthese ports are written and linted, not verified. Verifying "
            "needs a build host and a session."
        )
        return "\n".join(lines)


def run(project: Project, batch: int = 8, provider: str = "",
        subsystem: str = "", tier: str = "", max_cost_usd: float = 5.0,
        max_minutes: float = 0.0, max_rounds: int = 0,
        port_only: bool = True, host: str = "", echo=None) -> AutoResult:
    """Keep porting until one of the stopping conditions is met."""
    from . import loop as loop_mod
    from .queue import NEEDS_WORK

    def pending() -> int:
        placeholders = ",".join("?" for _ in NEEDS_WORK)
        sql = (
            f"SELECT COUNT(*) FROM function WHERE in_corpus=1 AND gate IS NULL "
            f"AND COALESCE(status,'pending') IN ({placeholders})"
        )
        params = list(NEEDS_WORK)
        if subsystem:
            sql += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
            params.append(subsystem)
        return project.db.scalar(sql, tuple(params), 0) or 0

    result = AutoResult(started_pending=pending())
    started = time.time()
    consecutive_failures = 0

    while True:
        elapsed = time.time() - started
        if max_minutes and elapsed > max_minutes * 60:
            result.stopped_because = f"reached the {max_minutes:.0f} minute limit"
            break
        if max_rounds and len(result.rounds) >= max_rounds:
            result.stopped_because = f"completed {max_rounds} rounds"
            break
        if max_cost_usd and result.cost >= max_cost_usd:
            result.stopped_because = f"reached the ${max_cost_usd:.2f} ceiling"
            break
        if pending() == 0:
            result.stopped_because = "nothing left to work on"
            break

        remaining_budget = max(0.0, max_cost_usd - result.cost) if max_cost_usd else 0.0
        one = loop_mod.run(
            project, n=batch, rounds=1, tier=tier, subsystem=subsystem,
            provider=provider, host=host, port_only=port_only,
            no_session=port_only,
            max_cost_usd=remaining_budget,
        )
        if not one.rounds:
            result.stopped_because = "the round produced nothing"
            break

        round_result = one.rounds[0]
        round_result.round = len(result.rounds) + 1
        result.rounds.append(round_result)
        if echo is not None:
            echo(round_result)

        # --- reasons to stop that are not the budget ------------------------
        if round_result.stopped_at in ("queue",):
            result.stopped_because = round_result.why
            break
        if round_result.stopped_at in ("build", "session", "verify"):
            result.stopped_because = (
                f"{round_result.stopped_at} refused: {round_result.why}"
            )
            break
        if round_result.stopped_at == "budget":
            result.stopped_because = round_result.why
            break

        attempted = round_result.picked or 1
        failed_share = round_result.failed / attempted
        produced = round_result.ported + round_result.drafted + round_result.blocked
        if not produced or failed_share >= FAILURE_RATE_LIMIT:
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILED_ROUNDS:
                result.stopped_because = (
                    f"{consecutive_failures} rounds in a row produced nothing "
                    f"usable, which means the setup is wrong rather than the "
                    f"work being hard"
                )
                break
        else:
            consecutive_failures = 0

    result.elapsed_s = round(time.time() - started, 1)
    result.remaining = pending()
    if not result.stopped_because:
        result.stopped_because = "finished"
    return result
