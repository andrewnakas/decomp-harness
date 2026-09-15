# Design

## The problem this solves

An AI model can reverse engineer a real subsystem of a shipped game. The
skate3-audio project decompiled 1,694 audio functions of an Xbox 360
executable, recovered seven struct layouts with thirty-five machine-checked
offsets, decoded three container formats sample-exactly, and produced 216 native
C++ port bodies of which 138 were proved equal to the original call for call.

It also showed where the money went. Most of the tokens were not spent on
judgment. They went on re-reading a decompiled corpus of about a million tokens,
on per-function notes averaging four kilobytes each, on a fifty-kilobyte README
and an eighteen-kilobyte instruction file re-read every session, on grepping
offsets that alias across unrelated structures, and on re-learning the same
traps. The one step that genuinely needed a model — writing a port from a
prepared packet — was a small fraction of the bill.

So the harness inverts the ratio. Everything a program can do, a program does.
The model is asked one question at a time, on a packet of about a thousand
tokens, with no file access, and its answer is not believed until a
deterministic oracle agrees.

## Shape

```
 image + lifted corpus
        │
        ▼
 import ─► analyze ─► subsystems ─► corpus ─► screen ─► queue
        (all mechanical, no tokens)              │
                                                 ▼
                          draft ──────────────► lint ─► build ─► oracle ─► verdict
                       (mechanical)               ▲                          │
                            │ declines            │                          ▼
                            ▼                     │                      promote
                      packet ─► model ────────────┘
```

Every arrow is a command, every command is resumable, and every result is a row
in a SQLite database that survives the session.

## Principles

**The packet is the whole world.** The model has no file tools. Repo discovery
was the largest single sink in the manual sessions, so it is removed rather than
optimised. Anything the model needs is in the packet; anything it might need it
asks for.

**Nothing is believed without an oracle.** A port is a hypothesis until a
comparison disagrees with it or fails to. Lint catches structural errors in
milliseconds, the build proves the binary changed, and the session compares the
candidate against the original on inputs the program generated for itself.

**A verdict is only worth recording if it could have been negative.** Every
session arms deliberately wrong ports and requires them to be caught. A run in
which nothing can fail is indistinguishable from one in which nothing was
compared.

**Refusing is a result.** A drafter that declines costs nothing. A model that
answers `blocked` with a reason is more useful than one that ports a function
whose write set cannot be enumerated. A comparison covering a third of a
function's calls is reported as covering a third.

**Measure, do not assert.** Every model call is a row in a ledger. `decomp cost`
reports tokens per verified function and the cache hit rate, so a change that
makes the harness more expensive is visible.

## Where the savings come from

Ranked by what they actually remove, measured on a real corpus:

| Technique | Effect |
|---|---|
| No file access; packets only | Removes repo discovery entirely |
| Mechanical screening before any call | 1,692 functions to 612 worth attempting |
| Mechanical drafts | 82 of those 612 need no model at all |
| Stable cached prefix | A first call cost $0.0278, the identical second cost $0.0034 |
| Normalized views | 10.6% smaller, and far denser in meaning |
| Diff-only retries | A retry re-sends the correction, not the packet |
| Structured output | No prose, no scaffolding, notes capped at 300 characters |
| Persisted knowledge | Traps become checks instead of paragraphs re-read each session |

The normalization number is deliberately unflattering. Its value is not size: it
is that `+0x150` becomes `Player.decoder` where that is established, and stays
`+0x150` where it is not.
