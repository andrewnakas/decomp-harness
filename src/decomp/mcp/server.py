"""The same core, exposed to an interactive session.

Two rules shape this surface, both taken from what made the CLI cheap:

  * Few tools, and each one small. A tool list is sent on every request, so a
    hundred tools is a tax on every message. This exposes fifteen.
  * Every tool returns the terse form by default. A tool that dumps a file is a
    tool that undoes the reason this harness exists; `fn_view` takes a line
    range and a kind, and defaults to the cheapest one.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.config import open_project
from ..core.db import addr_str, parse_addr

_PROJECT_ROOT: Path | None = None


def _project():
    return open_project(_PROJECT_ROOT)


def build_server(root: Path | None = None, name: str = "decomp"):
    """Construct the MCP server. Imported lazily so the CLI does not need it."""
    from mcp.server.mcpserver import MCPServer

    global _PROJECT_ROOT
    _PROJECT_ROOT = root

    server = MCPServer(
        name=name,
        instructions=(
            "Reverse-engineering harness. Read facts with these tools rather "
            "than opening files: the corpus is large and reading it is what "
            "this harness exists to avoid. Use queue_next to choose work, "
            "fn_view for one function's body, and port_submit to hand in a "
            "port. Names and offsets you propose are stored as proposals, not "
            "as facts."
        ),
    )

    # ---------------------------------------------------------------- state
    @server.tool(description="Project state: corpus size, queue counts, last build and session.")
    def project_status() -> str:
        from ..pipeline.status import run as run_status

        return run_status(_project()).brief()

    @server.tool(description="The next functions worth working on, ordered by tier then family then hotness.")
    def queue_next(n: int = 8, tier: str = "", subsystem: str = "") -> str:
        from ..pipeline.queue import next_items

        return next_items(_project(), tier=tier, limit=n, subsystem=subsystem).brief()

    @server.tool(description="One function's facts: name, tier, gate, calls, callees, stores.")
    def fn_info(addr: str) -> str:
        project = _project()
        target = parse_addr(addr)
        row = project.db.one("SELECT * FROM function WHERE addr=?", (target,))
        if not row:
            return f"{addr_str(target)}\tnot in this project"
        gate = project.db.one("SELECT * FROM gate WHERE addr=?", (target,))
        lines = [
            f"{addr_str(target)}\t{row.get('name') or ''}",
            f"tier\t{row.get('tier')}\tstatus\t{row.get('status')}"
            f"\tdifficulty\t{row.get('difficulty')}",
            f"gate\t{row.get('gate') or 'pass'}\t{row.get('gate_reason') or ''}",
            f"lines\tlifted={row.get('lifted_lines')}\tc={row.get('ghidra_lines')}"
            f"\tvector={bool(row.get('vmx128'))}",
        ]
        if row.get("note"):
            lines.append(f"note\t{row['note']}")
        if gate and gate.get("windows_json"):
            windows = json.loads(gate["windows_json"])
            lines.append(f"windows\t{len(windows)} suggested")
        return "\n".join(lines)

    @server.tool(description="One function's body. kind: packet (default, cheapest) | c | asm. Use lines to read a range.")
    def fn_view(addr: str, kind: str = "packet", lines: str = "") -> str:
        from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from
        from ..views.packet import build as build_packet

        project = _project()
        target = parse_addr(addr)
        if kind == "packet":
            text = build_packet(project, target).text
        elif kind == "asm":
            text = truth_from(project).collapse(target, max_lines=240)
        else:
            row = project.db.one(
                "SELECT path FROM view_cache WHERE addr=? AND kind='ghidra_c'",
                (target,),
            )
            path = Path(row["path"]) if row and row.get("path") else None
            text = path.read_text(errors="replace") if path and path.is_file() else ""
        if not text:
            return f"{addr_str(target)}\tno {kind} view"
        if lines:
            start, _, end = lines.partition("-")
            body = text.splitlines()
            text = "\n".join(body[int(start) - 1 : int(end or start)])
        return text

    @server.tool(description="Callers and callees of a function. direction: out (default) | in.")
    def fn_graph(addr: str, direction: str = "out", limit: int = 20) -> str:
        project = _project()
        target = parse_addr(addr)
        if direction == "in":
            rows = project.db.query(
                "SELECT caller AS other, kind FROM xref WHERE callee=? LIMIT ?",
                (target, limit),
            )
        else:
            rows = project.db.query(
                "SELECT callee AS other, callee_name, kind FROM xref WHERE caller=? "
                "LIMIT ?", (target, limit),
            )
        if not rows:
            return f"{addr_str(target)}\tno {direction} edges"
        out = []
        for r in rows:
            name = r.get("callee_name") or ""
            other = r["other"]
            label = name or (addr_str(other) if other else "(indirect)")
            out.append(f"{label}\t{r['kind']}")
        return "\n".join(out)

    @server.tool(description="Find functions by name, or a constant they reference.")
    def search(name: str = "", constant: str = "", limit: int = 20) -> str:
        project = _project()
        if constant:
            value = parse_addr(constant)
            rows = project.db.query(
                "SELECT c.addr, f.name FROM const_ref c LEFT JOIN function f "
                "ON f.addr=c.addr WHERE c.value=? LIMIT ?", (value, limit),
            )
            return "\n".join(
                f"{addr_str(r['addr'])}\t{r.get('name') or ''}" for r in rows
            ) or f"no function references 0x{value:08X}"
        rows = project.db.query(
            "SELECT addr, name, status FROM function WHERE name LIKE ? LIMIT ?",
            (f"%{name}%", limit),
        )
        return "\n".join(
            f"{addr_str(r['addr'])}\t{r['name']}\t{r.get('status') or ''}" for r in rows
        ) or f"nothing matching '{name}'"

    @server.tool(description="Functions with a similar shape, so one insight serves several.")
    def similar(addr: str, limit: int = 8) -> str:
        project = _project()
        target = parse_addr(addr)
        family = project.db.scalar(
            "SELECT family_id FROM function WHERE addr=?", (target,)
        )
        if not family:
            return f"{addr_str(target)}\tno family"
        rows = project.db.query(
            "SELECT addr, name, status FROM function WHERE family_id=? AND addr!=? "
            "ORDER BY COALESCE(hot,0) DESC LIMIT ?", (family, target, limit),
        )
        return "\n".join(
            f"{addr_str(r['addr'])}\t{r.get('name') or ''}\t{r.get('status') or ''}"
            for r in rows
        ) or f"family {family} has one member"

    @server.tool(description="A recovered struct layout. Established fields only.")
    def struct_get(name: str) -> str:
        project = _project()
        struct = project.db.one("SELECT * FROM struct WHERE name=?", (name,))
        if not struct:
            known = [r["name"] for r in project.db.query("SELECT name FROM struct")]
            return f"no struct '{name}'. Known: {', '.join(known) or '(none)'}"
        rows = project.db.query(
            "SELECT offset, size, ctype, name, status FROM struct_field "
            "WHERE struct_id=? ORDER BY offset", (struct["id"],),
        )
        out = [f"{struct['name']}\tsize=0x{(struct.get('size') or 0):X}"]
        for r in rows:
            mark = "" if r["status"] in ("established", "confirmed") else "  (proposed)"
            out.append(
                f"  +0x{r['offset']:03X}  {(r['ctype'] or 'u32'):<10} {r['name']}{mark}"
            )
        return "\n".join(out)

    @server.tool(description="Traps recorded on this project, so they are not rediscovered.")
    def lessons(stage: str = "") -> str:
        from ..core import lessons as lessons_mod

        project = _project()
        rows = (lessons_mod.for_stage(project, stage) if stage
                else lessons_mod.all_lessons(project))
        return "\n".join(f"{r['title']}. {r['body']}" for r in rows) or "none recorded"

    # ----------------------------------------------------------------- work
    @server.tool(description="Hand in a port: code plus the memory spans it writes. Linted before it is stored.")
    def port_submit(addr: str, code: str, windows: str = "[]",
                    result_registers: str = "", note: str = "") -> str:
        from ..llm.schemas import PortAnswer
        from ..port import emit, lint

        project = _project()
        target = parse_addr(addr)
        try:
            parsed_windows = json.loads(windows) if windows else []
        except json.JSONDecodeError as exc:
            return f"windows is not valid JSON: {exc}"

        answer = PortAnswer(
            addr=f"{target:08X}", code=code, windows=parsed_windows,
            result_registers=[r.strip() for r in result_registers.split(",") if r.strip()],
            note=note[:300],
        )
        report = lint.check(
            answer, expected_addr=target,
            budget_bytes=project.get("oracle.window_budget_bytes", 32768),
            budget_spans=project.get("oracle.window_budget_spans", 32),
        )
        if not report.ok:
            return "rejected:\n" + report.feedback()

        artifact = emit.write(
            answer, target, project.sub("ports"),
            macro=project.get("oracle.port_macro", "SKATE3_PORT"),
            status="written", provenance="submitted through mcp",
        )
        from ..pipeline.port import _record

        _record(project, target, answer, status="written", path=artifact.path,
                attempts=1)
        return f"accepted\t{artifact.path.name}"

    @server.tool(description="Mark a function unverifiable, with the reason. Better than a port that cannot be checked.")
    def mark_blocked(addr: str, gate: str, why: str) -> str:
        from ..pipeline.queue import set_status

        if gate not in ("gate1", "gate2", "gate3", "gate4"):
            return "gate must be gate1, gate2, gate3 or gate4"
        project = _project()
        target = parse_addr(addr)
        set_status(project, target, status=gate, note=why[:300])
        project.db.upsert(
            "function", {"addr": target, "gate": gate, "gate_reason": why[:200]}, "addr"
        )
        return f"{addr_str(target)}\t{gate}\trecorded"

    @server.tool(description="Propose a name or a struct field. Stored as a proposal, never overwriting a cited fact.")
    def propose(kind: str, addr: str = "", name: str = "", struct: str = "",
                offset: int = 0, size: int = 4, ctype: str = "u32",
                why: str = "") -> str:
        from ..core.stages import now_iso

        project = _project()
        if kind == "name":
            target = parse_addr(addr)
            project.db.execute(
                "INSERT INTO symbol_evidence (addr, name, kind, source, confidence, "
                "created_at) VALUES (?,?,?,?,?,?)",
                (target, name, "llm", "mcp", 0.6, now_iso()),
            )
            return f"{addr_str(target)}\tproposed name '{name}'"
        if kind == "field":
            project.db.upsert("struct", {"name": struct, "origin": "llm"}, "name")
            struct_id = project.db.scalar("SELECT id FROM struct WHERE name=?", (struct,))
            existing = project.db.one(
                "SELECT status FROM struct_field WHERE struct_id=? AND offset=?",
                (struct_id, offset),
            )
            if existing and existing["status"] in ("established", "confirmed"):
                return (
                    f"{struct}+0x{offset:X} is already established; a proposal does "
                    f"not overwrite a cited fact"
                )
            project.db.upsert(
                "struct_field",
                {"struct_id": struct_id, "offset": offset, "size": size,
                 "ctype": ctype, "name": name, "status": "proposed",
                 "confidence": 0.5},
                ("struct_id", "offset"),
            )
            return f"{struct}+0x{offset:X}\tproposed '{name}'"
        return "kind must be 'name' or 'field'"

    @server.tool(description="Tokens per verified function, cache hit rate, spend.")
    def cost(by: str = "") -> str:
        from ..llm import ledger

        return ledger.report(_project(), group_by=by).brief()

    @server.tool(description="The stable operating brief: target facts, rules, layouts.")
    def brief() -> str:
        from ..llm.prefix import build as build_prefix

        return build_prefix(_project()).text

    return server


def serve(root: Path | None = None) -> None:
    build_server(root).run()
