# Adapters

Everything platform-specific is an adapter. The pipeline and the database are
the parts that do not change.

| Kind | Protocol | Shipped | Answers |
|---|---|---|---|
| Target | `adapters/target` | raw image, XEX | What is the image, where does it load, what are its entry points |
| Engine | `adapters/engine` | Ghidra via PyGhidra | What does this function look like in C |
| Ground truth | `adapters/groundtruth` | RexGlue lifted C++ | What is the authoritative form when the decompiler is not trustworthy |
| Screen | `adapters/screen` | rexglue census | Can an oracle bracket this function at all |
| Draft | `adapters/draft` | lifted to native | Can this be translated without judgment |
| Provider | `adapters/provider` | claude, codex, api key, replay | Ask a model a question |
| Build | `adapters/build` | cmake + ninja | Compile, and prove the binary changed |
| Session | `adapters/session` | shadow harness | Run the program and compare |

## Writing one

Each protocol is a `typing.Protocol` in that package's `base.py` with the
dataclasses it exchanges. A new adapter implements the protocol and is selected
from `decomp.toml`. Nothing else changes.

The rule every adapter follows: report what happened, including when nothing
did. A build system that cannot find its artifact says so. A screener that
cannot classify a store says so. Silence is how a harness produces results that
look fine and mean nothing.

## Oracles are peers

Shadow execution is the one shipped, because it is what the Skate 3
recompilation provides. Three others fit the same protocol:

- **byte match** — compile a candidate and compare the object against the
  original, symbol by symbol. This is what the matching-decompilation scene
  uses, and its verdict is a percentage rather than a boolean.
- **differential execution** — run original and candidate under an emulator on
  recorded or synthesized inputs. Works where there is no recompilation to host
  a shadow harness.
- **replay vectors** — record entry state, read set and write set per call, then
  replay them offline against a port in another language. This is how a Rust
  translation is validated without the game.

A project can use more than one. They answer the same question differently, and
a function that passes two is better evidenced than one that passes either.
