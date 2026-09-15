# DecompHarness

A command-line harness for reverse engineering binaries with an AI model doing
only the part a model is actually needed for.

The premise comes from a measured result: an agent can decompile a real game
subsystem, but most of the tokens go to work a program should have done. Reading
whole decompiled corpora, re-deriving pipeline steps, grepping offsets that alias
across structures, and re-learning the same traps every session cost far more
than the judgment calls that required a model at all.

`decomp` inverts that. Every mechanical step is a resumable command over a
project database: load the image, decompile, bound the corpus by call-graph
closure, screen what can be verified, rank the queue, build a packet, lint the
answer, build, run the oracle, record the verdict, promote. The model is called
once per function with a packet of about a thousand tokens and no file access,
and its answer is not believed until a deterministic oracle agrees.

## Status

Early. Phase 0 (project, database, providers, ledger) is in place.

## Install

```sh
uv venv --python 3.13
uv pip install -e ".[dev]"
decomp doctor
```

Python 3.13 is pinned because Ghidra's bundled PyGhidra ships wheels for 3.9
through 3.13 only.

## Sign-in

The harness spawns the `claude` or `codex` binary you installed and signed into
yourself. It never reads, stores, forwards, or proxies a credential. If a CLI is
not signed in, `decomp login` prints that vendor's own login command for you to
run.

```sh
decomp login
decomp llm ping --provider claude
```

An API-key tier (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) is available for CI.

## Measuring

Efficiency is reported, not asserted:

```sh
decomp cost --by model
decomp cost --baseline-from ~/Documents/sk8AudioDecompile --baseline-verified 138
```

## License

MIT. Powered by Claude; not affiliated with Anthropic or OpenAI.
