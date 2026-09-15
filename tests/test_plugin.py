from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN = Path(__file__).parent.parent / "plugin"
GUARD = PLUGIN / "hooks" / "guard_corpus.py"


def run_guard(payload: dict) -> dict | None:
    result = subprocess.run(
        [sys.executable, str(GUARD)], input=json.dumps(payload),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)


# --------------------------------------------------------------------- guard
@pytest.mark.parametrize("path,expected_tool", [
    ("/home/u/skate3recomp-dev/generated/skate3_recomp.67.cpp", "asm"),
    ("/home/u/sk8AudioDecompile/out/decomp/sub_82B28A00.c", "fn_view"),
    ("/home/u/sk8AudioDecompile/out/lifted/sub_82AF0338.cpp", "asm"),
    ("/home/u/proj/.decomp/views/c/sub_82B10000.c", "fn_view"),
    ("/home/u/repo/probe/ports/notes/sub_82B28A00.md", "fn_info"),
])
def test_corpus_reads_are_refused_with_an_alternative(path, expected_tool):
    """A rule in a prompt is a request; this is the enforcement."""
    out = run_guard({"tool_name": "Read", "tool_input": {"file_path": path}})
    assert out is not None, f"{path} should have been refused"
    decision = out["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert expected_tool in decision["permissionDecisionReason"]


@pytest.mark.parametrize("path", [
    "/home/u/project/src/main.py",
    "/home/u/project/README.md",
    "/home/u/skate3recomp-dev/CMakeLists.txt",
    "/home/u/skate3recomp-dev/src/skate3_audio_native.cpp",
    "/home/u/proj/.decomp/ports/sub_82B10000.inc",
])
def test_ordinary_files_pass(path):
    """A harness that fought the user over ordinary files would be turned off."""
    assert run_guard({"tool_name": "Read", "tool_input": {"file_path": path}}) is None


def test_globs_and_patterns_are_checked_too():
    assert run_guard({
        "tool_name": "Glob",
        "tool_input": {"pattern": "**/out/decomp/sub_*.c"},
    }) is not None


def test_malformed_input_is_not_an_error():
    """A hook that crashes blocks the tool it was meant to guard."""
    result = subprocess.run(
        [sys.executable, str(GUARD)], input="not json",
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert not result.stdout.strip()

    assert run_guard({"tool_name": "Read", "tool_input": {}}) is None
    assert run_guard({}) is None


# -------------------------------------------------------------------- shape
def test_plugin_manifest_is_valid():
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == "decomp"
    assert manifest["description"]


def test_mcp_config_points_at_the_cli():
    config = json.loads((PLUGIN / ".mcp.json").read_text())
    server = config["mcpServers"]["decomp"]
    assert server["command"] == "decomp"
    assert server["args"] == ["mcp"]


def test_hooks_are_wired_to_the_read_tools():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    entry = hooks["hooks"]["PreToolUse"][0]
    assert "Read" in entry["matcher"] and "Grep" in entry["matcher"]
    assert "guard_corpus.py" in entry["hooks"][0]["command"]


@pytest.mark.parametrize("skill", ["decomp-status", "decomp-next", "decomp-hunt"])
def test_every_skill_declares_itself(skill):
    text = (PLUGIN / "skills" / skill / "SKILL.md").read_text()
    assert text.startswith("---")
    front = text.split("---")[1]
    assert f"name: {skill}" in front
    assert "description:" in front
    # A description is what decides whether the skill is loaded at all.
    description = [ln for ln in front.splitlines() if ln.startswith("description:")][0]
    assert len(description) > 60


@pytest.mark.parametrize("agent", ["porter", "reviewer"])
def test_every_agent_declares_itself(agent):
    text = (PLUGIN / "agents" / f"{agent}.md").read_text()
    front = text.split("---")[1]
    assert f"name: {agent}" in front
    assert "model:" in front


def test_the_skills_tell_the_model_not_to_read_the_corpus():
    """The hook enforces it, but a skill that does not say so wastes a refusal."""
    porting = (PLUGIN / "skills" / "decomp-next" / "SKILL.md").read_text()
    assert "Do not open" in porting or "do not open" in porting
    hunting = (PLUGIN / "skills" / "decomp-hunt" / "SKILL.md").read_text()
    assert "do not grep" in hunting.lower()
