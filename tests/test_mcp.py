from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")


@pytest.fixture
def served(project, fixtures, tmp_path, monkeypatch):
    from decomp.mcp import server as server_mod
    from decomp.pipeline.importer import import_lifted, import_structs, import_xrefs
    from decomp.pipeline.queue import build as queue_build
    from decomp.pipeline.screen import screen

    import_lifted(project, path=fixtures / "lifted")
    import_structs(project, path=fixtures / "ingest/structs.h")
    project.db.execute("UPDATE function SET in_corpus=1 WHERE addr < 0x82F00000")
    import_xrefs(project, scope="corpus")
    screen(project)
    queue_build(project)

    monkeypatch.setattr(server_mod, "_project", lambda: project)
    return server_mod.build_server(project.root)


def _tools(server) -> dict:
    """The server's tools, by name."""
    import asyncio

    listed = asyncio.run(server.list_tools())
    return {t.name: t for t in listed}


def test_the_tool_surface_stays_small(served):
    """A tool list is sent on every request, so each tool is a standing tax."""
    tools = _tools(served)
    assert 8 <= len(tools) <= 20, f"{len(tools)} tools is too many to send on every request"
    for name in ("project_status", "queue_next", "fn_info", "fn_view",
                 "port_submit", "cost"):
        assert name in tools


def test_every_tool_describes_itself(served):
    for name, tool in _tools(served).items():
        assert tool.description, f"{name} has no description"
        assert len(tool.description) < 200, f"{name}'s description is an essay"


def test_fn_view_defaults_to_the_cheapest_form(served, project):
    """A tool that dumps a file undoes the reason this harness exists."""
    import asyncio

    packet = asyncio.run(served.call_tool("fn_view", {"addr": "82B10000"}))
    text = str(packet)
    assert "sub_82B10000" in text
    assert len(text) < 8000


def test_fn_view_can_take_a_line_range(served):
    import asyncio

    ranged = str(asyncio.run(
        served.call_tool("fn_view", {"addr": "82B10000", "kind": "asm",
                                     "lines": "1-3"})
    ))
    assert ranged.count("\n") <= 6


def test_a_bad_port_is_rejected_with_the_reason(served):
    import asyncio

    result = str(asyncio.run(served.call_tool("port_submit", {
        "addr": "82B10000",
        "code": "REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);",
        "windows": "[]",
    })))
    assert "rejected" in result
    assert "undeclared_writes" in result or "vacuous" in result


def test_a_good_port_is_accepted(served, project):
    import asyncio

    result = str(asyncio.run(served.call_tool("port_submit", {
        "addr": "82B10000",
        "code": "REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);",
        "windows": json.dumps([{"base": "r3", "offset": 8, "length": 4}]),
        "result_registers": "r3",
        "note": "stores the argument",
    })))
    assert "accepted" in result
    assert project.db.scalar(
        "SELECT status FROM function WHERE addr=?", (0x82B10000,)
    ) == "written"


def test_malformed_windows_are_explained_not_raised(served):
    import asyncio

    result = str(asyncio.run(served.call_tool("port_submit", {
        "addr": "82B10000", "code": "x;", "windows": "not json",
    })))
    assert "not valid JSON" in result


def test_a_proposal_never_overwrites_a_cited_fact(served, project):
    import asyncio

    result = str(asyncio.run(served.call_tool("propose", {
        "kind": "field", "struct": "rw_scheduler", "offset": 0x40,
        "name": "something_else",
    })))
    assert "already established" in result
    assert project.db.scalar(
        "SELECT name FROM struct_field WHERE offset=0x40 AND struct_id="
        "(SELECT id FROM struct WHERE name='rw_scheduler')"
    ) == "delta_time"


def test_a_new_field_is_stored_as_a_proposal(served, project):
    import asyncio

    asyncio.run(served.call_tool("propose", {
        "kind": "field", "struct": "rw_scheduler", "offset": 0x60,
        "name": "guessed", "size": 4,
    }))
    assert project.db.scalar(
        "SELECT status FROM struct_field WHERE offset=0x60 AND struct_id="
        "(SELECT id FROM struct WHERE name='rw_scheduler')"
    ) == "proposed"


def test_marking_blocked_records_the_reason(served, project):
    import asyncio

    result = str(asyncio.run(served.call_tool("mark_blocked", {
        "addr": "82B10000", "gate": "gate2",
        "why": "walks a list of unknown length",
    })))
    assert "gate2" in result
    row = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B10000,))
    assert row["gate"] == "gate2"
    assert "unknown length" in row["gate_reason"]


def test_an_invalid_gate_is_refused(served):
    import asyncio

    result = str(asyncio.run(served.call_tool("mark_blocked", {
        "addr": "82B10000", "gate": "gate9", "why": "x",
    })))
    assert "must be" in result
