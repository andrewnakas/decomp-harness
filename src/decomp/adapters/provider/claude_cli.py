"""Claude provider: spawns the user's own `claude` binary in print mode.

We pass the packet on stdin and the stable brief via --append-system-prompt-file
so the prefix is cached (cache reads cost a fraction of fresh input). Structured
answers come back through --json-schema as `structured_output`.

Credentials are never touched: the binary owns its own login.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .base import LLMRequest, LLMResult, Provider, ProviderHealth, Usage

TIER_ALIASES = {"small": "haiku", "mid": "sonnet", "strong": "opus"}

# Denied unless a call explicitly asks for tools: the model answers from the
# packet alone. Keeps context small and makes cost predictable.
NO_FILE_TOOLS = [
    "Read", "Write", "Edit", "Glob", "Grep", "Bash",
    "WebFetch", "WebSearch", "Agent", "NotebookEdit",
]


class ClaudeCliProvider(Provider):
    id = "claude"

    def __init__(self, bin_path: str = "claude", routing: dict[str, str] | None = None,
                 cache_ttl: str = "1h", api_key_mode: bool = False):
        self.bin = bin_path
        self.routing = routing or {}
        self.cache_ttl = cache_ttl
        # api_key_mode adds --bare (deterministic, ignores user config) but
        # --bare never reads OAuth credentials, so it requires ANTHROPIC_API_KEY.
        self.api_key_mode = api_key_mode

    # ------------------------------------------------------------- health
    def health(self) -> ProviderHealth:
        exe = shutil.which(self.bin)
        if not exe:
            return ProviderHealth(
                self.id, available=False, logged_in=False,
                detail=f"`{self.bin}` not on PATH",
                login_hint="install Claude Code, then run `claude` and sign in",
            )
        version = _run_text([exe, "--version"], timeout=20).strip()
        if self.api_key_mode:
            has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
            return ProviderHealth(
                self.id, available=True, logged_in=has_key, version=version,
                detail="api-key mode",
                login_hint="set ANTHROPIC_API_KEY",
            )
        raw = _run_text([exe, "auth", "status"], timeout=30)
        logged_in = False
        detail = ""
        try:
            info = json.loads(raw)
            logged_in = bool(info.get("loggedIn"))
            detail = str(info.get("authMethod", ""))
        except (json.JSONDecodeError, TypeError):
            logged_in = "logged in" in raw.lower() or "loggedIn\": true" in raw
        return ProviderHealth(
            self.id, available=True, logged_in=logged_in, version=version,
            detail=detail,
            login_hint="run `claude` and use /login (the harness never handles tokens)",
        )

    def resolve_model(self, tier: str) -> str:
        return self.routing.get(tier) or TIER_ALIASES.get(tier, tier)

    # --------------------------------------------------------------- call
    def build_argv(self, req: LLMRequest, prefix_file: Path | None,
                   schema_file: Path | None) -> list[str]:
        model = req.model or self.resolve_model(req.tier)
        argv = [self.bin, "-p", "--output-format", "stream-json", "--verbose"]
        if self.api_key_mode:
            # Deterministic: no user hooks, skills, MCP autodiscovery or CLAUDE.md.
            argv.append("--bare")
        else:
            # Subscription runs cannot use --bare, so neutralize project config
            # explicitly instead: no project MCP servers, no inherited settings.
            argv += ["--strict-mcp-config", "--settings",
                     json.dumps({"promptCacheTtl": req.cache_ttl or self.cache_ttl})]
        if model:
            argv += ["--model", model]
        if req.effort:
            argv += ["--effort", req.effort]
        if req.max_turns:
            argv += ["--max-turns", str(req.max_turns)]
        if prefix_file is not None:
            argv += ["--append-system-prompt-file", str(prefix_file)]
        if schema_file is not None:
            argv += ["--json-schema", schema_file.read_text()]
        if req.mcp_config:
            argv += ["--mcp-config", json.dumps(req.mcp_config)]
        if req.allowed_tools:
            argv += ["--allowedTools", *req.allowed_tools]
        else:
            # The packet is the whole world. Denying file and shell tools is the
            # single biggest token saving: it removes repo discovery entirely,
            # which was the largest sink in the manual sessions.
            argv += ["--disallowedTools", *NO_FILE_TOOLS]
        argv += ["--permission-mode", "dontAsk"]
        if req.resume_session:
            argv += ["--resume", req.resume_session]
        return argv

    def call(self, req: LLMRequest) -> LLMResult:
        workdir = Path(req.cwd) if req.cwd else Path.cwd()
        workdir.mkdir(parents=True, exist_ok=True)

        prefix_file = None
        if req.prefix and not req.resume_session:
            prefix_file = workdir / "prefix.md"
            prefix_file.write_text(req.prefix)
        schema_file = None
        if req.schema:
            schema_file = workdir / "schema.json"
            schema_file.write_text(json.dumps(req.schema))

        argv = self.build_argv(req, prefix_file, schema_file)
        raw_path = workdir / "claude_raw.jsonl"
        started = time.time()
        try:
            proc = subprocess.run(
                argv, input=req.prompt, capture_output=True, text=True,
                timeout=req.timeout_s, cwd=str(workdir),
            )
        except subprocess.TimeoutExpired:
            return LLMResult(ok=False, error=f"timeout after {req.timeout_s}s",
                             duration_ms=int((time.time() - started) * 1000))
        except FileNotFoundError:
            return LLMResult(ok=False, error=f"`{self.bin}` not found on PATH")

        duration_ms = int((time.time() - started) * 1000)
        raw_path.write_text(proc.stdout)
        result = parse_stream_json(proc.stdout)
        result.duration_ms = duration_ms
        result.raw_path = raw_path
        if not result.ok and not result.error:
            result.error = (proc.stderr or "").strip()[:500] or f"exit {proc.returncode}"
        return result


def parse_stream_json(stdout: str) -> LLMResult:
    """Parse `claude -p --output-format stream-json` output.

    The final `result` event carries usage, cost, session id and (with
    --json-schema) the parsed `structured_output`.
    """
    result = LLMResult(ok=False)
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = evt.get("type")
        if etype == "system" and evt.get("subtype") == "init":
            result.session_ref = evt.get("session_id", "") or result.session_ref
            result.model = evt.get("model", "") or result.model
        elif etype == "system" and evt.get("subtype") == "api_retry":
            err = evt.get("error") or evt.get("error_status")
            if err:
                result.error = f"api_retry: {err}"
        elif etype == "result":
            result.ok = not evt.get("is_error", False) and evt.get("subtype") == "success"
            result.text = evt.get("result", "") or ""
            result.session_ref = evt.get("session_id", "") or result.session_ref
            result.cost_usd = evt.get("total_cost_usd")
            result.structured = evt.get("structured_output")
            usage = evt.get("usage") or {}
            result.usage = Usage(
                input_tokens=int(usage.get("input_tokens", 0) or 0),
                cache_read_tokens=int(usage.get("cache_read_input_tokens", 0) or 0),
                cache_write_tokens=int(usage.get("cache_creation_input_tokens", 0) or 0),
                output_tokens=int(usage.get("output_tokens", 0) or 0),
            )
            model_usage = evt.get("modelUsage") or evt.get("model_usage") or {}
            if model_usage and not result.model:
                result.model = next(iter(model_usage), "")
            if evt.get("subtype") and evt["subtype"] != "success":
                result.error = result.error or str(evt.get("subtype"))
    if result.structured is None and result.text:
        result.structured = _try_json(result.text)
    return result


def _try_json(text: str) -> Any:
    """Recover JSON from prose or a fenced block when structured output is absent."""
    text = text.strip()
    if text.startswith("```"):
        body = text.split("```", 2)
        if len(body) >= 2:
            inner = body[1]
            inner = inner.split("\n", 1)[1] if "\n" in inner else inner
            text = inner.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _run_text(argv: list[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or proc.stderr or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
