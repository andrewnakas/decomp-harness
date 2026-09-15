# Providers

The harness spawns the `claude` or `codex` binary you installed and signed into
yourself. It never reads, stores, forwards, or proxies a credential. If a CLI is
not signed in, `decomp login` prints that vendor's own login command for you to
run.

```sh
decomp login              # both
decomp llm ping           # one tiny structured call, recorded in the ledger
```

## Choosing one

```sh
decomp port 82B28B78 --provider codex      # per command
```

Or set the default in `decomp.toml`:

```toml
[providers]
default = "codex"
```

## Claude

Nothing to configure. Model tiers map to the CLI's own aliases:

```toml
[routing]
small  = "haiku"
mid    = "sonnet"
strong = "opus"
```

Subscription runs cannot use `--bare`, because that mode does not read OAuth
credentials, so the harness neutralizes project configuration explicitly
instead: `--strict-mcp-config` and an explicit `--settings`. An API-key run
(`ANTHROPIC_API_KEY` with `api_key_mode = true`) uses `--bare` and is fully
deterministic.

## Codex

Two things differ, and both are handled but worth knowing.

**Schemas are rewritten.** OpenAI's structured output is strict: every object
must declare `additionalProperties: false` and every property must appear in
`required`. A schema that does not is rejected outright rather than being
partly ignored. The harness converts before sending, making optional fields
nullable so they can stay optional while still being required.

**Cost is estimated.** Codex reports token counts but no dollar figure, so the
harness prices them from a table you can override:

```toml
[providers.codex]
# USD per million tokens, as (input, output)
prices = { default = [1.25, 10.0] }
```

**Models.** Leave `models` unset and Codex uses whatever `~/.codex/config.toml`
says. To route by tier instead:

```toml
[providers.codex.models]
small  = "gpt-5.6-luna"
mid    = "gpt-5.6-terra"
strong = "gpt-6-astra"
```

**Reasoning effort.** The harness passes effort per tier, which overrides your
`model_reasoning_effort` default for its own calls. That matters: a default of
`xhigh` makes a simple port take minutes and bills reasoning at several times
the input rate.

**Sandbox and trust.** Every call runs `--sandbox read-only` in an isolated work
directory, with `--skip-git-repo-check` because that directory is not a
repository. The model has no reason to touch the filesystem: the packet is the
whole context.

## Replay

For testing the loop without spending anything:

```toml
[providers]
default = "replay"

[providers.replay]
dir = ".decomp/cassettes"
record_with = "claude"     # what to call when a cassette is missing
```

Record once, then replay for free. Cassettes are keyed by prompt, prefix,
purpose and whether the call is a retry, so a retry replays the retry answer
rather than the original.

## What they cost

Every call is a ledger row.

```sh
decomp cost --by provider
decomp cost --by model
```

The per-verified figure is cost-weighted: a cached read counts at a tenth of a
fresh one and output at five times, because summing the four kinds raw
overstates a cache-heavy run by a wide margin.
