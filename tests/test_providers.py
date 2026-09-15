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
    assert result.usage.input_tokens == 24763
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
