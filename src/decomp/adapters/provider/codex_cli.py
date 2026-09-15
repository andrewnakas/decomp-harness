"""Codex provider: spawns the user's own `codex` binary in non-interactive mode.

Codex has no system-prompt flag, so the stable prefix is written as AGENTS.md in
the isolated work directory. Usage arrives on `turn.completed` as token counts
only, so cost is estimated from a configurable price table.

Credentials are never touched: `codex login` owns them.
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

# USD per million tokens. Overridable via decomp.toml [providers.codex.prices].
DEFAULT_PRICES: dict[str, tuple[float, float]] = {
    "default": (1.25, 10.0),
}


def strict_schema(schema: Any) -> Any:
    """Rewrite a JSON Schema into the strict form OpenAI requires.

    Two rules that Pydantic's output does not satisfy on its own, and that the
    API rejects outright rather than ignoring:

      * every object must say `additionalProperties: false`
      * every property must appear in `required`

    Optional fields therefore cannot simply be left out of `required`. They are
    made nullable instead, which keeps the same meaning: the field is always
    present and may be null. The harness treats null and absent alike.
    """
    if isinstance(schema, list):
        return [strict_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema

    out = {key: strict_schema(value) for key, value in schema.items()}

    if out.get("type") == "object" or "properties" in out:
        out["additionalProperties"] = False
        properties = out.get("properties") or {}
        if properties:
            optional = [
                name for name in properties
                if name not in (out.get("required") or [])
            ]
            for name in optional:
                properties[name] = _nullable(properties[name])
            out["required"] = list(properties)
    return out


def _nullable(prop: Any) -> Any:
    """Allow null, so a field can be optional while still being required."""
    if not isinstance(prop, dict):
        return prop
    if "anyOf" in prop:
        variants = prop["anyOf"]
        if not any(v.get("type") == "null" for v in variants if isinstance(v, dict)):
            prop["anyOf"] = [*variants, {"type": "null"}]
        return prop
    kind = prop.get("type")
    if isinstance(kind, str) and kind != "null":
        prop["type"] = [kind, "null"]
    elif isinstance(kind, list) and "null" not in kind:
        prop["type"] = [*kind, "null"]
    return prop


class CodexCliProvider(Provider):
    id = "codex"

    def __init__(self, bin_path: str = "codex", routing: dict[str, str] | None = None,
                 prices: dict[str, Any] | None = None, inherit_mcp: bool = False):
        self.bin = bin_path
        self.routing = routing or {}
        self.prices = prices or {}
        self.inherit_mcp = inherit_mcp

    # ------------------------------------------------------------- health
    def health(self) -> ProviderHealth:
        exe = shutil.which(self.bin)
        if not exe:
            return ProviderHealth(
                self.id, available=False, logged_in=False,
                detail=f"`{self.bin}` not on PATH",
                login_hint="install the Codex CLI, then run `codex login`",
            )
        version = _run_text([exe, "--version"], timeout=20).strip()
        status = _run_text([exe, "login", "status"], timeout=30).strip()
        logged_in = "logged in" in status.lower() or "chatgpt" in status.lower()
        if not logged_in and os.environ.get("OPENAI_API_KEY"):
            logged_in, status = True, "OPENAI_API_KEY"
        return ProviderHealth(
            self.id, available=True, logged_in=logged_in, version=version,
            detail=status.splitlines()[0][:80] if status else "",
            login_hint="run `codex login` yourself (the harness never handles tokens)",
        )

    def resolve_model(self, tier: str) -> str:
        return self.routing.get(tier, "")

    # --------------------------------------------------------------- call
    def build_argv(self, req: LLMRequest, schema_file: Path | None,
                   out_file: Path) -> list[str]:
        argv = [self.bin, "exec", "--json", "--skip-git-repo-check"]
        model = req.model or self.resolve_model(req.tier)
        if model:
            argv += ["-m", model]
        if req.effort:
            argv += ["-c", f"model_reasoning_effort={req.effort}"]
        if schema_file is not None:
            argv += ["--output-schema", str(schema_file)]
        argv += ["-o", str(out_file)]
        # Read-only sandbox: the model has no reason to touch the filesystem.
        argv += ["--sandbox", "read-only"]
        # Do not inherit the user's MCP servers. They are irrelevant to a port,
        # they cost tool-definition tokens on every call, and one that is
        # configured but not running makes every call wait on a dead socket.
        # This is the same reasoning as --strict-mcp-config on the other side.
        if not self.inherit_mcp:
            argv += ["-c", "mcp_servers={}"]
        if req.cwd:
            argv += ["-C", str(req.cwd)]
        return argv

    def build_resume_argv(self, req: LLMRequest, schema_file: Path | None,
                          out_file: Path) -> list[str]:
        """Continue an existing session.

        `resume` accepts a narrower set of flags than `exec`: the sandbox and
        the working directory were settled by the first call and are not
        repeatable here. Passing them anyway makes the CLI read the prompt as a
        flag argument and fail.
        """
        argv = [self.bin, "exec", "resume", req.resume_session, "--json",
                "--skip-git-repo-check"]
        if schema_file is not None:
            argv += ["--output-schema", str(schema_file)]
        argv += ["-o", str(out_file)]
        return argv

    def call(self, req: LLMRequest) -> LLMResult:
        workdir = Path(req.cwd) if req.cwd else Path.cwd()
        workdir.mkdir(parents=True, exist_ok=True)

        # Codex reads AGENTS.md from the working directory: that is our prefix.
        if req.prefix:
            (workdir / "AGENTS.md").write_text(req.prefix)
        schema_file = None
        if req.schema:
            schema_file = workdir / "schema.json"
            # OpenAI rejects a schema that is not strict, rather than ignoring
            # the parts it does not use, so it is converted rather than passed
            # through as Claude's is.
            schema_file.write_text(json.dumps(strict_schema(req.schema)))
        out_file = workdir / "codex_answer.txt"

        if req.resume_session:
            argv = self.build_resume_argv(req, schema_file, out_file)
        else:
            argv = self.build_argv(req, schema_file, out_file)
        argv.append(req.prompt)

        raw_path = workdir / "codex_raw.jsonl"
        started = time.time()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=req.timeout_s,
                cwd=str(workdir),
            )
        except subprocess.TimeoutExpired:
            return LLMResult(ok=False, error=f"timeout after {req.timeout_s}s",
                             duration_ms=int((time.time() - started) * 1000))
        except FileNotFoundError:
            return LLMResult(ok=False, error=f"`{self.bin}` not found on PATH")

        duration_ms = int((time.time() - started) * 1000)
        raw_path.write_text(proc.stdout)
        final_text = out_file.read_text() if out_file.is_file() else ""
        result = parse_codex_jsonl(proc.stdout, final_text)

        # The event stream can come back empty while the answer file is written,
        # and an answer on disk is an answer. Without this the call was scored a
        # failure and retried, paying twice for a result already in hand.
        if not result.ok and result.structured is not None and proc.returncode == 0:
            result.ok = True
            result.error = ""
        result.duration_ms = duration_ms
        result.raw_path = raw_path
        result.model = result.model or req.model or self.resolve_model(req.tier)
        result.cost_usd = self.estimate_cost(result.model, result.usage)
        if not result.ok and not result.error:
            result.error = (proc.stderr or "").strip()[:500] or f"exit {proc.returncode}"
        return result

    def estimate_cost(self, model: str, usage: Usage) -> float | None:
        table = {**DEFAULT_PRICES, **(self.prices or {})}
        entry = table.get(model) or table.get("default")
        if not entry:
            return None
        rate_in, rate_out = (entry if isinstance(entry, (list, tuple)) else (None, None))
        if rate_in is None:
            return None
        # Cached input is billed at a discount; without a published rate we do not guess.
        fresh_in = max(0, usage.input_tokens - usage.cache_read_tokens)
        return round(
            (fresh_in * rate_in + usage.output_tokens * rate_out) / 1_000_000, 6
        )


def parse_codex_jsonl(stdout: str, final_text: str = "") -> LLMResult:
    """Parse `codex exec --json` output: usage rides on `turn.completed`."""
    from .claude_cli import _try_json

    result = LLMResult(ok=False, text=final_text)
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = evt.get("type")
        if etype == "thread.started":
            result.session_ref = evt.get("thread_id", "") or result.session_ref
        elif etype == "turn.completed":
            result.ok = True
            usage = evt.get("usage") or {}
            fresh = int(usage.get("input_tokens", 0) or 0)
            cached = int(usage.get("cached_input_tokens", 0) or 0)
            result.usage = Usage(
                # Codex reports input_tokens inclusive of the cached ones, where
                # Claude reports them separately. Subtracting keeps the ledger
                # comparable across providers, which is the whole point of it.
                input_tokens=max(0, fresh - cached),
                cache_read_tokens=cached,
                cache_write_tokens=int(usage.get("cache_write_input_tokens", 0) or 0),
                output_tokens=int(usage.get("output_tokens", 0) or 0)
                + int(usage.get("reasoning_output_tokens", 0) or 0),
            )
        elif etype in ("turn.failed", "error"):
            result.ok = False
            err = evt.get("error") or evt.get("message") or evt
            result.error = str(err)[:500]
        elif etype == "item.completed":
            item = evt.get("item") or {}
            if item.get("type") in ("agent_message", "assistant_message") and not final_text:
                result.text = item.get("text", "") or result.text
    if result.text:
        result.structured = _try_json(result.text)
    return result


def _run_text(argv: list[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or proc.stderr or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
