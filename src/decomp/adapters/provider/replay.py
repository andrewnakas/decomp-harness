"""Replay provider: canned answers keyed by packet hash.

Two modes. `record` wraps a real provider and saves every answer; `replay`
serves those answers with zero tokens. This is how the whole loop is tested
end to end, including retries, without spending anything.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...core.hashing import sha256_text
from .base import LLMRequest, LLMResult, Provider, ProviderHealth, Usage


class ReplayProvider(Provider):
    id = "replay"

    def __init__(self, cassette_dir: Path | str, inner: Provider | None = None,
                 record: bool = False):
        self.dir = Path(cassette_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.inner = inner
        self.record = record

    def health(self) -> ProviderHealth:
        n = len(list(self.dir.glob("*.json")))
        mode = "record" if self.record else "replay"
        return ProviderHealth(
            self.id, available=True, logged_in=True,
            version=f"{mode}:{n} cassettes", detail=str(self.dir),
        )

    def resolve_model(self, tier: str) -> str:
        return f"replay-{tier}"

    def key(self, req: LLMRequest) -> str:
        """Cassette identity: prompt + prefix + purpose + resume state.

        Resume is part of the key so a retry replays the retry answer, not the
        original one.
        """
        material = json.dumps(
            {
                "prompt": req.prompt,
                "prefix": req.prefix,
                "purpose": req.purpose,
                "resumed": bool(req.resume_session),
            },
            sort_keys=True,
        )
        return sha256_text(material)[:16]

    def call(self, req: LLMRequest) -> LLMResult:
        key = self.key(req)
        path = self.dir / f"{key}.json"
        if path.is_file():
            data = json.loads(path.read_text())
            usage = data.get("usage") or {}
            return LLMResult(
                ok=data.get("ok", True),
                structured=data.get("structured"),
                text=data.get("text", ""),
                usage=Usage(**usage) if usage else Usage(),
                cost_usd=data.get("cost_usd", 0.0),
                session_ref=data.get("session_ref", f"replay-{key}"),
                model=data.get("model", "replay"),
                duration_ms=0,
                raw_path=path,
                error=data.get("error", ""),
            )
        if self.record and self.inner is not None:
            result = self.inner.call(req)
            path.write_text(
                json.dumps(
                    {
                        "ok": result.ok,
                        "structured": result.structured,
                        "text": result.text,
                        "usage": result.usage.__dict__,
                        "cost_usd": result.cost_usd,
                        "session_ref": result.session_ref,
                        "model": result.model,
                        "error": result.error,
                        "_prompt_preview": req.prompt[:400],
                    },
                    indent=2,
                    default=str,
                )
            )
            return result
        return LLMResult(
            ok=False,
            error=f"no cassette {key} in {self.dir} (record one with --record)",
        )
