"""`decomp analyze`: decompile the corpus.

One engine session for the whole batch. The expensive parts - starting the JVM,
loading the image, applying names, fixing the register-save stubs - happen once,
and then each function costs only its own decompilation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.stages import now_iso, stage
from ..core.tokens import estimate

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class AnalyzeResult:
    requested: int
    defined: int = 0
    decompiled: int = 0
    failed: int = 0
    names_applied: int = 0
    helpers_fixed: int = 0
    duration_s: float = 0.0
    engine: str = ""
    examples: list[str] = field(default_factory=list)

    def brief(self) -> str:
        lines = [
            f"engine\t{self.engine}",
            f"prepared\tnames={self.names_applied}\thelpers={self.helpers_fixed}",
            f"decompiled\t{self.decompiled}/{self.requested}\tfailed={self.failed}"
            f"\t{self.duration_s:.1f}s",
        ]
        if self.failed:
            lines.append(
                "note\tfunctions the decompiler cannot recover fall back to the "
                "authoritative assembly in their packet"
            )
        lines.extend(f"  {e}" for e in self.examples[:3])
        return "\n".join(lines)


@stage(
    "analyze",
    inputs=lambda p, **kw: [
        kw.get("subsystem"), kw.get("scope"), kw.get("limit"),
        p.db.scalar("SELECT COUNT(*) FROM function WHERE in_corpus=1", (), 0),
        (p.target_row() or {}).get("image_sha256"),
    ],
)
def run(project: Project, ctx, subsystem: str = "", scope: str = "corpus",
        limit: int = 0, redo: bool = False, engine=None) -> AnalyzeResult:
    """Decompile corpus functions and cache the result as their C view.

    `engine` accepts an already-open engine. A JVM holds one program at a time,
    and starting a second is both slow and an error, so a loop that analyses
    repeatedly should open once and pass it in.
    """
    import time

    from ..adapters.engine.ghidra import from_project as engine_from_project

    target = project.target_row()
    if not target or not target.get("image_path"):
        raise ValueError("no image: run `decomp import image <file> --base 0x...`")
    if not Path(target["image_path"]).is_file():
        raise FileNotFoundError(f"image not found: {target['image_path']}")

    sql = "SELECT addr FROM function WHERE 1=1"
    params: list = []
    if scope == "corpus":
        sql += " AND in_corpus=1"
    if subsystem:
        sql += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
        params.append(subsystem)
    if not redo:
        sql += (
            " AND addr NOT IN (SELECT addr FROM view_cache WHERE kind='ghidra_c')"
        )
    sql += " ORDER BY COALESCE(hot,0) DESC, addr"
    if limit:
        sql += f" LIMIT {int(limit)}"

    addrs = [r["addr"] for r in project.db.query(sql, tuple(params))]
    result = AnalyzeResult(requested=len(addrs))
    if not addrs:
        result.engine = "(nothing to do)"
        return result

    started = time.time()
    borrowed = engine is not None
    if engine is None:
        engine = engine_from_project(project)
        info = engine.open(
            target["image_path"],
            int(target.get("base_addr") or 0),
            target.get("ghidra_lang") or project.get("target.ghidra_lang", ""),
            str(project.ghidra_dir),
            analyze=False,
        )
        result.engine = info.brief()
    else:
        result.engine = f"{engine.id} (reused)"

    try:
        result.defined = engine.define_functions(addrs)

        # Names before decompiling, so call sites read as names. Helpers before
        # anything, because a corpus decompiled without the fix has wrong
        # parameters and every struct offset read from it is wrong with it.
        names = {
            r["addr"]: r["name"]
            for r in project.db.query(
                "SELECT addr, name FROM function WHERE name IS NOT NULL "
                "AND name NOT LIKE 'sub\\_%' ESCAPE '\\'"
            )
        }
        if names:
            result.names_applied = engine.apply_names(names)
        result.helpers_fixed = engine.fix_helpers()
        if result.helpers_fixed:
            project.db.meta_set("engine.fixhelpers_applied", now_iso())

        out_dir = project.sub("views", "c")
        with project.db.tx():
            for addr in addrs:
                decompiled = engine.decompile(addr)
                if not decompiled.ok:
                    result.failed += 1
                    if len(result.examples) < 3:
                        result.examples.append(decompiled.brief())
                    project.db.upsert(
                        "function",
                        {"addr": addr, "decompile_ok": 0,
                         "decompile_warnings": decompiled.error[:200]},
                        "addr",
                    )
                    continue

                path = out_dir / f"sub_{addr:08X}.c"
                path.write_text(decompiled.c)
                project.db.upsert(
                    "view_cache",
                    {
                        "addr": addr, "kind": "ghidra_c", "path": str(path),
                        "tokens": estimate(decompiled.c),
                        "lines": decompiled.c.count("\n") + 1,
                        "version_hash": target.get("image_sha256", "")[:16],
                    },
                    ("addr", "kind"),
                )
                update = {"addr": addr, "decompile_ok": 1,
                          "ghidra_lines": decompiled.c.count("\n") + 1}
                if decompiled.signature:
                    update["signature"] = decompiled.signature[:200]
                project.db.upsert("function", update, "addr")
                result.decompiled += 1
    finally:
        if not borrowed:
            engine.close()

    result.duration_s = round(time.time() - started, 2)
    ctx.record(decompiled=result.decompiled, failed=result.failed)
    return result
