"""Provider adapters and their registry."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .base import LLMRequest, LLMResult, Provider, ProviderHealth, Usage

if TYPE_CHECKING:
    from ...core.config import Project

__all__ = [
    "LLMRequest",
    "LLMResult",
    "Provider",
    "ProviderHealth",
    "Usage",
    "get_provider",
    "all_providers",
]

KNOWN = ("claude", "codex", "replay")


def get_provider(project: Project, name: str | None = None, *,
                 record: bool = False) -> Provider:
    """Build a provider from project config. `name` defaults to providers.default."""
    from .claude_cli import ClaudeCliProvider
    from .codex_cli import CodexCliProvider
    from .replay import ReplayProvider

    name = name or project.get("providers.default", "claude")
    routing = project.get("routing", {}) or {}
    tiers = {k: v for k, v in routing.items() if k in ("small", "mid", "strong")}

    if name == "claude":
        cfg = project.get("providers.claude", {}) or {}
        return ClaudeCliProvider(
            bin_path=cfg.get("bin", "claude"),
            routing=cfg.get("models", tiers),
            cache_ttl=cfg.get("cache_ttl", "1h"),
            api_key_mode=bool(cfg.get("api_key_mode", False)),
        )
    if name == "codex":
        cfg = project.get("providers.codex", {}) or {}
        return CodexCliProvider(
            bin_path=cfg.get("bin", "codex"),
            routing=cfg.get("models", {}),
            prices=cfg.get("prices", {}),
        )
    if name == "replay":
        cfg = project.get("providers.replay", {}) or {}
        cassettes = Path(cfg.get("dir") or (project.state / "cassettes"))
        inner = None
        if record:
            inner = get_provider(project, cfg.get("record_with", "claude"))
        return ReplayProvider(cassettes, inner=inner, record=record)
    raise KeyError(f"unknown provider '{name}' (known: {', '.join(KNOWN)})")


def all_providers(project: Project) -> list[Provider]:
    out = []
    for name in ("claude", "codex"):
        try:
            out.append(get_provider(project, name))
        except Exception:
            continue
    return out
