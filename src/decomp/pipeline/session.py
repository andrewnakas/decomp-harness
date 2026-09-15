"""`decomp session`: run the program with the candidate ports armed.

Two refusals are built in, because each corresponds to a way the audio project
produced a session whose verdicts meant nothing:

  * a session against a binary the current ports were not built into
  * a session with no deliberately wrong port armed to prove the oracle works
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.db import addr_str
from ..core.stages import now_iso

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class SessionStageResult:
    session_id: int | None
    ok: bool
    label: str
    host: str
    profile: str
    armed: int = 0
    controls: list = field(default_factory=list)
    calls_total: int = 0
    log_path: str = ""
    refused: str = ""

    def brief(self) -> str:
        if self.refused:
            return f"session\tREFUSED\t{self.refused}"
        head = "ok" if self.ok else "FAILED"
        lines = [
            f"session\t{head}\t#{self.session_id}\t{self.label}\t{self.host}"
            f"\t{self.profile}\tarmed={self.armed}\tcalls={self.calls_total}",
        ]
        for c in self.controls:
            lines.append(c.brief() if hasattr(c, "brief") else str(c))
        lines.append(f"next\tdecomp verify --session {self.session_id}")
        return "\n".join(lines)


def run(project: Project, label: str = "", profile: str = "play",
        host: str = "", duration_s: int = 120, controls: int = 2,
        allow_stale: bool = False, dry_run: bool = False) -> SessionStageResult:
    from ..adapters.session.shadow import from_project as session_from_project
    from ..core.remote import transport_for
    from ..verify import controls as controls_mod

    label = label or f"{profile}-{int(__import__('time').time())}"
    transport = transport_for(project, host, dry_run=dry_run)

    # --- refuse to run against a stale build -------------------------------
    build = project.db.one("SELECT * FROM build WHERE ok=1 ORDER BY id DESC LIMIT 1")
    if not build and not allow_stale:
        return SessionStageResult(
            session_id=None, ok=False, label=label, host=transport.name,
            profile=profile,
            refused="no verified build: run `decomp build` first",
        )

    port_rows = project.db.query(
        "SELECT addr, path, build_id FROM port WHERE status IN "
        "('written','verified','thin','partial','promoted')"
    )
    if build and not allow_stale:
        unbuilt = [r["addr"] for r in port_rows if r.get("build_id") != build["id"]]
        if unbuilt:
            names = " ".join(addr_str(a) for a in unbuilt[:4])
            return SessionStageResult(
                session_id=None, ok=False, label=label, host=transport.name,
                profile=profile,
                refused=(
                    f"{len(unbuilt)} port(s) are not in build #{build['id']}: {names}. "
                    "Rebuild, or pass --allow-stale to accept that the armed set "
                    "and the binary disagree."
                ),
            )

    # --- arm the controls --------------------------------------------------
    verified_ports = [
        (r["addr"], Path(r["path"]))
        for r in project.db.query(
            "SELECT addr, path FROM port WHERE status IN ('verified','promoted') "
            "AND path IS NOT NULL"
        )
    ]
    control_list = controls_mod.build_controls(
        verified_ports, project.sub("controls"), count=controls
    ) if controls and verified_ports else []

    applied = [c for c in control_list if controls_mod.confirm_applied(c)]
    for c in control_list:
        c.applied = c in applied

    if controls and not applied:
        detail = (
            "no verified port to mutate yet"
            if not verified_ports
            else "no mutation could be applied to any candidate"
        )
        return SessionStageResult(
            session_id=None, ok=False, label=label, host=transport.name,
            profile=profile, controls=control_list,
            refused=(
                f"no negative control is armed ({detail}). A session in which "
                "nothing can fail cannot verify anything. Pass --controls 0 to "
                "run anyway, and treat its verdicts as unproven."
            ),
        )

    # --- run ---------------------------------------------------------------
    runner = session_from_project(project)
    armed = [r["addr"] for r in port_rows]
    run_result = runner.run(transport, label=label, profile=profile,
                            armed=armed, duration_s=duration_s)

    log_dir = project.sub("sessions")
    local_log = log_dir / f"{label}.log"
    local_log.write_text(run_result.raw or "")

    cur = project.db.execute(
        "INSERT INTO session (host, build_id, profile, armed_json, "
        "negative_controls_json, calls_total, log_path, started) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            transport.name,
            (build or {}).get("id"),
            profile,
            json.dumps(armed),
            json.dumps([
                {"addr": c.addr, "kind": c.kind, "applied": c.applied}
                for c in control_list
            ]),
            run_result.calls_total,
            str(local_log),
            now_iso(),
        ),
    )

    return SessionStageResult(
        session_id=int(cur.lastrowid), ok=run_result.ok, label=label,
        host=transport.name, profile=profile, armed=len(armed),
        controls=control_list, calls_total=run_result.calls_total,
        log_path=str(local_log),
    )
