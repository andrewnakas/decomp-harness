"""`decomp verify`: turn a session log into verdicts, if the session is trustworthy.

The order is the point. Controls are checked first, and if no deliberately wrong
port was caught, nothing else in the log is recorded. A session that cannot fail
has not verified anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.db import addr_str
from ..core.stages import now_iso

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class VerifyResult:
    session_id: int | None
    trusted: bool
    by_result: dict[str, int] = field(default_factory=dict)
    control_summary: str = ""
    notes: list[str] = field(default_factory=list)
    recorded: int = 0

    def brief(self) -> str:
        lines = []
        if not self.trusted:
            lines.append(f"UNTRUSTED\t{self.control_summary}")
            lines.append("no verdicts recorded: a session that cannot fail proves nothing")
        else:
            lines.append(f"trusted\t{self.control_summary}")
        lines.append("verdicts\t" + " ".join(
            f"{k}={v}" for k, v in sorted(self.by_result.items())
        ))
        if self.recorded:
            lines.append(f"recorded\t{self.recorded}")
        lines.extend(f"note\t{n}" for n in self.notes[:4])
        return "\n".join(lines)


def run(project: Project, session_id: int | None = None,
        log_path: str = "", require_controls: bool = True) -> VerifyResult:
    """Summarize a session and record what it proved."""
    from ..adapters.session.shadow import parse_log

    if log_path:
        text = open(log_path, errors="replace").read()
        session = None
    else:
        session = (
            project.db.one("SELECT * FROM session WHERE id=?", (session_id,))
            if session_id
            else project.db.one("SELECT * FROM session ORDER BY id DESC LIMIT 1")
        )
        if not session:
            raise ValueError("no session to verify: run `decomp session` first")
        path = session.get("log_path")
        if not path:
            raise ValueError(f"session {session['id']} has no log")
        text = open(path, errors="replace").read()

    summary = parse_log(text)
    diverged = {v.addr for v in summary.verdicts if v.result == "diverged"}

    # --- trust first -------------------------------------------------------
    controls = json.loads((session or {}).get("negative_controls_json") or "[]")
    control_addrs = [int(c["addr"]) if isinstance(c, dict) else int(c) for c in controls]
    applied = [c for c in controls if not isinstance(c, dict) or c.get("applied", True)]

    if require_controls and not applied:
        return VerifyResult(
            session_id=(session or {}).get("id"), trusted=False,
            by_result=summary.by_result(),
            control_summary="no negative control was armed",
        )

    missed = [a for a in control_addrs if a not in diverged]
    trusted = not missed or not require_controls
    control_summary = (
        f"{len(control_addrs)} control(s) armed, all caught"
        if trusted and control_addrs
        else f"{len(missed)} control(s) not caught: "
             + " ".join(addr_str(a) for a in missed[:3])
    )

    if session is not None:
        project.db.execute(
            "UPDATE session SET trusted=?, negcontrol_ok=?, calls_total=?, "
            "summary_json=?, ended=? WHERE id=?",
            (
                1 if trusted else 0, 1 if trusted else 0, summary.calls_total,
                json.dumps(summary.by_result()), now_iso(), session["id"],
            ),
        )

    if not trusted:
        return VerifyResult(
            session_id=(session or {}).get("id"), trusted=False,
            by_result=summary.by_result(), control_summary=control_summary,
            notes=summary.notes,
        )

    # --- record ------------------------------------------------------------
    recorded = 0
    sid = (session or {}).get("id")
    with project.db.tx():
        for v in summary.verdicts:
            if v.addr in control_addrs:
                continue                      # a control is evidence, not work
            project.db.execute(
                "INSERT INTO verdict (session_id, addr, result, calls, compared, "
                "skipped, first_divergence_json) VALUES (?,?,?,?,?,?,?)",
                (sid, v.addr, v.result, v.calls, v.compared, v.skipped,
                 json.dumps({"detail": v.divergence}) if v.divergence else None),
            )
            status = _status_for(v)
            update = {"addr": v.addr, "status": status, "updated_at": now_iso()}
            if v.divergence:
                update["last_divergence"] = v.divergence[:300]
            project.db.upsert("function", update, "addr")
            project.db.execute(
                "UPDATE port SET status=? WHERE addr=?", (status, v.addr)
            )
            recorded += 1

    return VerifyResult(
        session_id=sid, trusted=True, by_result=summary.by_result(),
        control_summary=control_summary, notes=summary.notes, recorded=recorded,
    )


def _status_for(verdict) -> str:
    if verdict.result != "verified":
        return {"diverged": "divergent"}.get(verdict.result, verdict.result)
    # Verified over a handful of calls is still verified, but the promotion rule
    # is what decides whether that evidence is enough to run for real.
    return "verified"
