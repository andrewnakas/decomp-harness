"""`decomp build`: compile the written ports and prove the binary changed."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.hashing import sha256_files
from ..core.stages import now_iso

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class BuildStageResult:
    build_id: int | None
    ok: bool
    host: str
    ports: int
    verified_symbols: int = 0
    duration_s: float = 0.0
    why: str = ""
    diagnostics: str = ""

    def brief(self) -> str:
        head = "ok" if self.ok else "FAILED"
        lines = [
            f"build\t{head}\t#{self.build_id or '-'}\t{self.host}\t"
            f"{self.ports} port(s)\t{self.duration_s:.1f}s",
            f"artifact\t{self.why}",
        ]
        if self.diagnostics:
            lines.append(self.diagnostics)
        return "\n".join(lines)


def run(project: Project, host: str = "", targets: list[str] | None = None,
        dry_run: bool = False) -> BuildStageResult:
    """Sync ports, build, and verify the artifact by symbol and timestamp."""
    from ..adapters.build.cmake_ninja import from_project as build_from_project
    from ..core.remote import transport_for

    builder = build_from_project(project)
    transport = transport_for(project, host, dry_run=dry_run)

    rows = project.db.query(
        "SELECT addr, path FROM port WHERE path IS NOT NULL AND status IN "
        "('written','verified','thin','partial','promoted')"
    )
    sources = [Path(r["path"]) for r in rows if Path(r["path"]).is_file()]
    expected = [f"port_{r['addr']:08X}" for r in rows]

    dest = project.get("build.port_dest", "")
    if dest and sources:
        if not builder.sync(transport, sources, dest):
            return BuildStageResult(
                build_id=None, ok=False, host=transport.name, ports=len(sources),
                why="could not copy port sources to the build host",
            )

    # Recorded before the build starts: the artifact must be newer than this, or
    # nothing was rebuilt and every later verdict would describe the old binary.
    started_at = time.time()
    result = builder.build(transport, targets=targets)
    check = builder.verify(transport, expected, newer_than=started_at)

    ok = result.ok and check.ok
    cur = project.db.execute(
        "INSERT INTO build (host, ports_hash, artifact_path, artifact_mtime, "
        "nm_symbols_ok, expected_syms, found_syms, ok, duration_s, log_path, "
        "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            transport.name,
            sha256_files(sources) if sources else "",
            check.path,
            check.mtime,
            1 if check.ok else 0,
            check.expected_symbols,
            check.found_symbols,
            1 if ok else 0,
            result.duration_s,
            result.log_path or None,
            now_iso(),
        ),
    )
    build_id = int(cur.lastrowid)

    if ok:
        project.db.execute(
            "UPDATE port SET build_id=? WHERE status='written'", (build_id,)
        )

    why = check.why() if result.ok else (result.error or "build failed")
    return BuildStageResult(
        build_id=build_id, ok=ok, host=transport.name, ports=len(sources),
        verified_symbols=check.found_symbols, duration_s=result.duration_s,
        why=why, diagnostics=result.diagnostics,
    )
