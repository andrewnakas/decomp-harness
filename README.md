# DecompHarness

A command-line harness for reverse engineering binaries, where the model is
asked only for the part a model is actually needed for.

The premise comes from a measured result. An AI agent can decompile a real game
subsystem — 1,694 functions, seven recovered struct layouts, 138 of them proved
equal to the original call for call. But most of the tokens went to work a
program should have done: reading a decompiled corpus of about a million tokens,
re-reading the same instructions every session, grepping offsets that alias
across unrelated structures, and re-learning the same traps.

`decomp` inverts that. Every mechanical step is a resumable command over a
project database. The model is called once per function with a packet of about a
thousand tokens and no file access, and its answer is not believed until a
deterministic oracle agrees.

```
decomp import lifted ./generated        # 47,652 functions indexed in 5s
decomp subsystems                       # 124 communities found in the call graph
decomp screen                           # 1,692 functions triaged, no tokens
decomp loop -n 8 --host linux           # port, build, verify, promote
decomp cost --by model                  # tokens per verified function
```

## What it does for free

Before any model is called, the harness has already:

- indexed the corpus and resolved every call site it can name
- folded `lis`/`addi` pairs arithmetically, because reading one by eye caused
  the original project's first divergence
- bounded the work by call-graph closure rather than an address range
- decided which functions an oracle can bracket at all, and why not
- translated the ones that need no judgment

On a real 612-function corpus that last step covers 82 of them, about one in
eight, at zero cost.

## What it refuses

- a session against a binary the armed ports were not built into
- a session with no deliberately wrong port armed, because a run where nothing
  can fail is indistinguishable from one where nothing was compared
- a build believed on its exit status rather than on the symbols in its artifact
- a packet that would exceed its token budget, which drops a section and says so

## Install

```sh
uv tool install --editable . --python 3.13 --with pyghidra --with mcp
decomp doctor
```

That puts `decomp` on your PATH and keeps it pointed at this checkout, so edits
take effect without reinstalling. `doctor` reports what is missing and what it
would enable.

Python 3.13 is pinned because Ghidra's bundled PyGhidra ships wheels for 3.9
through 3.13 only. The `pyghidra` extra is what makes `decomp analyze` work; the
`mcp` extra is what makes `decomp mcp` work. Without them everything else still
runs and `doctor` says so.

For working on the harness itself:

```sh
uv venv --python 3.13 && uv pip install -e ".[dev]" && pytest
```

## Sign-in

The harness spawns the `claude` or `codex` binary you installed and signed into
yourself. It never reads, stores, forwards, or proxies a credential. If a CLI is
not signed in, `decomp login` prints that vendor's own login command.

```sh
decomp login
decomp llm ping --provider claude
```

An API-key tier (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) is available for CI and
keeps working regardless of subscription policy.

## Measuring

Efficiency is reported, not asserted. Every model call is a ledger row.

```sh
decomp cost --by model
decomp cost --baseline-from ~/path/to/earlier/project --baseline-verified 138
```

The baseline is reconstructed from the Claude Code transcripts of the manual
work, so the comparison is against what this replaces.

## Documentation

- [Design](docs/design.md) — the shape and the reasoning
- [Providers](docs/providers.md) — Claude, Codex, and replay
- [Adapters](docs/adapters.md) — how to target something else
- [Data model](docs/data-model.md) — evidence, states, the ledger
- [Skate 3 runbook](docs/skate3-runbook.md) — the real sequence, with real numbers

## License

MIT. Powered by Claude; not affiliated with Anthropic or OpenAI.
