"""Provider protocol: how the harness asks a model for judgment.

Auth policy, deliberate and load-bearing:
  * We spawn the user's own unmodified `claude` / `codex` binary.
  * We never read, copy, store, forward, or proxy any credential or token.
  * If a binary is not logged in we print the vendor's own login command.
This is the sanctioned path (Anthropic's legal terms permit invoking the
unmodified binary; they forbid third parties intermediating claude.ai
credentials). An API-key tier exists for CI and survives policy changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class Usage:
    input_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0

    @property
    def fresh_input(self) -> int:
        """Input tokens sent fresh this call.

        Both providers report `input_tokens` exclusive of cache reads, so this
        is already the uncached count - never subtract cache_read from it.
        """
        return self.input_tokens

    @property
    def total(self) -> int:
        return (
            self.input_tokens + self.cache_read_tokens
            + self.cache_write_tokens + self.output_tokens
        )

    def brief(self) -> str:
        return (
            f"in={self.input_tokens} cache_r={self.cache_read_tokens} "
            f"cache_w={self.cache_write_tokens} out={self.output_tokens}"
        )


@dataclass
class LLMRequest:
    """One model call. `prefix` is the cached, byte-stable part."""

    prompt: str                                  # the packet (the only varying part)
    prefix: str = ""                             # system prompt / AGENTS.md content
    schema: dict[str, Any] | None = None         # JSON schema for structured output
    tier: str = "mid"                            # small | mid | strong
    model: str = ""                              # explicit override; else resolved from tier
    effort: str = ""                             # low | medium | high
    max_turns: int = 1
    cwd: Path | None = None                      # isolated work dir
    resume_session: str = ""                     # provider session id for diff-only retries
    allowed_tools: list[str] = field(default_factory=list)
    mcp_config: dict[str, Any] | None = None
    timeout_s: int = 900
    purpose: str = "port"
    addrs: list[int] = field(default_factory=list)
    cache_ttl: str = "1h"


@dataclass
class LLMResult:
    ok: bool
    structured: Any = None
    text: str = ""
    usage: Usage = field(default_factory=Usage)
    cost_usd: float | None = None
    session_ref: str = ""
    model: str = ""
    duration_ms: int = 0
    raw_path: Path | None = None
    error: str = ""

    def brief(self) -> str:
        head = "ok" if self.ok else f"FAIL {self.error[:120]}"
        cost = f" ${self.cost_usd:.4f}" if self.cost_usd is not None else ""
        return f"{head} {self.model} {self.usage.brief()}{cost} {self.duration_ms}ms"


@dataclass
class ProviderHealth:
    id: str
    available: bool
    logged_in: bool
    version: str = ""
    detail: str = ""
    login_hint: str = ""

    def brief(self) -> str:
        if not self.available:
            return f"{self.id}\tmissing\t{self.detail}"
        state = "ready" if self.logged_in else "not-logged-in"
        hint = f"\t{self.login_hint}" if not self.logged_in and self.login_hint else ""
        return f"{self.id}\t{state}\t{self.version}{hint}"


class Provider(Protocol):
    id: str

    def health(self) -> ProviderHealth:
        """Is the binary present and has the user logged in themselves?"""
        ...

    def call(self, req: LLMRequest) -> LLMResult:
        ...

    def resolve_model(self, tier: str) -> str:
        ...
