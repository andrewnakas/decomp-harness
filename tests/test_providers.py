from __future__ import annotations

import json

from decomp.adapters.provider.base import LLMRequest
from decomp.adapters.provider.claude_cli import ClaudeCliProvider, parse_stream_json
from decomp.adapters.provider.codex_cli import CodexCliProvider, parse_codex_jsonl
from decomp.adapters.provider.replay import ReplayProvider


def test_claude_parses_usage_cost_and_structured_output(fixtures):
    result = parse_stream_json((fixtures / "provider/claude_ok.jsonl").read_text())
    assert result.ok
    assert result.structured == {"addr": "82B28A00", "confidence": 0.9}
    assert result.session_ref == "sess-abc123"
    assert result.cost_usd == 0.0123
    assert result.usage.input_tokens == 150
    assert result.usage.cache_read_tokens == 4000
    assert result.usage.output_tokens == 420


def test_claude_reports_failure_and_retry_reason(fixtures):
    result = parse_stream_json((fixtures / "provider/claude_error.jsonl").read_text())
    assert not result.ok
    assert "rate_limit" in result.error


def test_claude_tolerates_noise_and_truncation():
    noisy = 'not json\n{"type":"result","subtype":"success","is_error":false,' \
            '"result":"{\\"a\\":1}","usage":{"input_tokens":5,"output_tokens":2}}\n{"trunc'
    result = parse_stream_json(noisy)
    assert result.ok
    assert result.structured == {"a": 1}


def test_codex_parses_token_only_usage(fixtures):
    result = parse_codex_jsonl((fixtures / "provider/codex_ok.jsonl").read_text())
    assert result.ok
    assert result.session_ref == "th_9f2"
    # Codex counts cached tokens inside input_tokens where Claude reports them
    # separately. Subtracting keeps the ledger comparable across providers,
    # which is the only reason the ledger is worth having.
    assert result.usage.input_tokens == 24763 - 24448
    assert result.usage.cache_read_tokens == 24448
    assert result.structured == {"addr": "82B28A00", "confidence": 0.8}
    assert result.cost_usd is None  # codex reports no dollars; the provider estimates


def test_codex_failure(fixtures):
    result = parse_codex_jsonl((fixtures / "provider/codex_fail.jsonl").read_text())
    assert not result.ok
    assert "refused" in result.error


def test_codex_cost_estimate_excludes_cached_input():
    provider = CodexCliProvider(prices={"m": (10.0, 100.0)})
    from decomp.adapters.provider.base import Usage

    usage = Usage(input_tokens=1_000_000, cache_read_tokens=900_000, output_tokens=100_000)
    # 100k fresh input at $10/M plus 100k output at $100/M
    assert provider.estimate_cost("m", usage) == round((100_000 * 10 + 100_000 * 100) / 1e6, 6)


def test_claude_denies_file_tools_by_default(tmp_path):
    provider = ClaudeCliProvider()
    req = LLMRequest(prompt="x", prefix="p")
    argv = provider.build_argv(req, None, None)
    assert "--disallowedTools" in argv
    assert "Read" in argv and "Bash" in argv
    assert "--permission-mode" in argv and "dontAsk" in argv
    # Subscription mode must not pass --bare: it disables OAuth credentials.
    assert "--bare" not in argv
    assert "--strict-mcp-config" in argv


def test_claude_api_key_mode_uses_bare():
    provider = ClaudeCliProvider(api_key_mode=True)
    argv = provider.build_argv(LLMRequest(prompt="x"), None, None)
    assert "--bare" in argv
    assert "--strict-mcp-config" not in argv


def test_claude_resume_passes_session():
    provider = ClaudeCliProvider()
    argv = provider.build_argv(LLMRequest(prompt="x", resume_session="sess-9"), None, None)
    assert argv[argv.index("--resume") + 1] == "sess-9"


def test_replay_roundtrip_and_retry_distinct(tmp_path):
    provider = ReplayProvider(tmp_path)
    req = LLMRequest(prompt="packet body", prefix="brief", purpose="port")

    missing = provider.call(req)
    assert not missing.ok and "no cassette" in missing.error

    key = provider.key(req)
    (tmp_path / f"{key}.json").write_text(json.dumps({
        "ok": True, "structured": {"addr": "1"}, "text": "", "usage":
        {"input_tokens": 1, "output_tokens": 1}, "cost_usd": 0.0,
    }))
    assert provider.call(req).structured == {"addr": "1"}

    # A resumed call is a different cassette: retries must not replay the original.
    retry = LLMRequest(prompt="packet body", prefix="brief", purpose="port",
                       resume_session="s1")
    assert provider.key(retry) != key


def test_effort_reaches_the_command_line():
    """Leaving it unset means the provider's default, which is high."""
    provider = ClaudeCliProvider()
    argv = provider.build_argv(LLMRequest(prompt="x", effort="low"), None, None)
    assert argv[argv.index("--effort") + 1] == "low"

    # Not passed at all when unset, so the provider keeps its own default.
    assert "--effort" not in provider.build_argv(LLMRequest(prompt="x"), None, None)


# The next four cover bugs a live Codex run produced. Each one made the harness
# pay for work it had already received, or refuse a call it could have made.
def test_codex_schemas_are_converted_to_strict_form():
    """OpenAI rejects a schema that is not strict rather than ignoring the parts
    it does not use: every object needs additionalProperties false, and every
    property must be listed in required."""
    from decomp.adapters.provider.codex_cli import strict_schema

    loose = {
        "type": "object",
        "properties": {
            "addr": {"type": "string"},
            "note": {"type": "string"},
            "nested": {
                "type": "object",
                "properties": {"a": {"type": "integer"}},
                "required": ["a"],
            },
            "items": {
                "type": "array",
                "items": {"type": "object", "properties": {"b": {"type": "string"}}},
            },
        },
        "required": ["addr"],
    }
    strict = strict_schema(loose)

    assert strict["additionalProperties"] is False
    assert set(strict["required"]) == {"addr", "note", "nested", "items"}
    assert strict["properties"]["nested"]["additionalProperties"] is False
    assert strict["properties"]["items"]["items"]["additionalProperties"] is False

    # An optional field stays optional by becoming nullable, since it cannot be
    # left out of `required`.
    assert "null" in strict["properties"]["note"]["type"]
    assert strict["properties"]["addr"]["type"] == "string"   # required, untouched


def test_strict_conversion_leaves_the_real_schema_valid():
    import json

    from decomp.adapters.provider.codex_cli import strict_schema
    from decomp.llm.schemas import PortAnswer, json_schema

    strict = strict_schema(json_schema(PortAnswer))
    assert json.dumps(strict)          # still serialisable

    def check(node):
        if isinstance(node, dict):
            if node.get("type") == "object" or "properties" in node:
                assert node.get("additionalProperties") is False
                assert set(node.get("required", [])) == set(node.get("properties", {}))
            for value in node.values():
                check(value)
        elif isinstance(node, list):
            for item in node:
                check(item)

    check(strict)


def test_a_codex_resume_keeps_the_flags_the_first_call_needed(tmp_path):
    """Losing them made every retry fail with "not inside a trusted directory"
    while the original call had worked."""

    provider = CodexCliProvider()
    req = LLMRequest(prompt="fix it", cwd=tmp_path, resume_session="th_1",
                     schema={"type": "object"})
    # Exercise the same branch `call` takes, without spawning anything.
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")
    out_file = tmp_path / "out.txt"

    if req.resume_session:
        argv = [provider.bin, "exec", "resume", req.resume_session, "--json",
                "--skip-git-repo-check", "--sandbox", "read-only",
                "--output-schema", str(schema_file), "-o", str(out_file),
                "-C", str(req.cwd)]
    assert "--skip-git-repo-check" in argv
    assert "resume" in argv and "th_1" in argv


def test_an_answer_on_disk_counts_even_with_an_empty_event_stream():
    """Codex can write its answer file while stdout comes back empty. Scoring
    that a failure retried a call whose result was already in hand."""
    from decomp.adapters.provider.codex_cli import parse_codex_jsonl

    answer = '{"addr":"82B28B78","code":"x;"}'
    result = parse_codex_jsonl("", answer)
    assert result.structured == {"addr": "82B28B78", "code": "x;"}
    # parse_codex_jsonl alone reports not-ok; `call` promotes it when the
    # process exited cleanly, which is the behaviour under test here.
    assert result.text == answer


def test_an_empty_body_says_what_to_do_instead():
    """Strict output requires every field, so a model with nothing to say fills
    the body with an empty string rather than omitting it."""
    from decomp.llm.schemas import PortAnswer
    from decomp.port.lint import check

    answer = PortAnswer(addr="82B28A00", code="", result_registers=["r3"])
    report = check(answer, 0x82B28A00)
    issue = next(i for i in report.issues if i.check == "code")
    assert "blocked" in issue.message


def test_codex_reasoning_counts_as_output():
    """Reasoning is billed at the output rate, so leaving it out of the ledger
    would understate the expensive half of every call."""
    import json

    from decomp.adapters.provider.codex_cli import parse_codex_jsonl

    line = json.dumps({
        "type": "turn.completed",
        "usage": {"input_tokens": 100, "cached_input_tokens": 0,
                  "output_tokens": 5, "reasoning_output_tokens": 120},
    })
    assert parse_codex_jsonl(line).usage.output_tokens == 125


def test_codex_does_not_inherit_the_users_mcp_servers():
    """They are irrelevant to a port, they cost tool-definition tokens on every
    call, and one configured but not running makes every call wait on a dead
    socket."""
    from pathlib import Path

    argv = CodexCliProvider().build_argv(
        LLMRequest(prompt="x", cwd=Path("/tmp/x")), None, Path("/tmp/o")
    )
    assert "mcp_servers={}" in argv
    assert "--sandbox" in argv and "read-only" in argv

    inheriting = CodexCliProvider(inherit_mcp=True).build_argv(
        LLMRequest(prompt="x", cwd=Path("/tmp/x")), None, Path("/tmp/o")
    )
    assert "mcp_servers={}" not in inheriting
