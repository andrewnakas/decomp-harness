# Working on DecompHarness

Run `decomp brief` in a project to get the operating brief. Read `docs/design.md`
before changing the pipeline.

## What this codebase is for

Reverse engineering with a model in the loop, where the model is asked only for
judgment and everything else is mechanical. When adding anything, ask which side
of that line it falls on. If a program can answer it, a program should.

## Rules that hold everywhere here

**Report what happened, including when nothing did.** A stage that cannot do its
job says so. Silence is how a harness produces results that look fine and mean
nothing — and this project exists because that happened.

**Never let a proposal overwrite a fact.** Evidence carries its source and
confidence. A model's name does not displace one resolved from the binary.

**A refusal is a result.** A drafter that declines, a screener that gates, a
model that answers `blocked` with a reason — all better than a guess that
reaches a session.

**Measure rather than claim.** If a change is supposed to save tokens, the
ledger should show it. Numbers in commit messages come from a run, not an
estimate.

## Layout

- `core/` — database, config, stage runner, transport, lessons
- `adapters/` — one package per protocol; see `docs/adapters.md`
- `pipeline/` — one module per command, each a plain function returning a result
- `views/`, `queue/`, `port/`, `verify/`, `llm/` — the parts between stages
- `cli/main.py` — argument parsing and formatting only, no logic

## Tests

`pytest` runs everything. Tests that need a JVM skip cleanly without one. The
fixture at `tests/fixtures/mini_ppc/` is a real PowerPC big-endian image built
from five C functions, so the engine is tested against a binary rather than a
mock.
