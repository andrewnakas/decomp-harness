# Running unattended

```sh
decomp auto --provider codex -n 8 --max-cost 20
```

Takes work from the queue in batches, translates what it can mechanically, asks
the model for the rest, lints every answer, and keeps going.

## When it stops

Five conditions, and only one of them is the budget:

| Condition | Meaning |
|---|---|
| nothing left to work on | the queue is empty |
| reached the ceiling | `--max-cost`, checked before the round that would cross it |
| reached the time limit | `--max-minutes` |
| completed N rounds | `--max-rounds` |
| rounds produced nothing usable | two in a row failed, so the setup is wrong |

The last one is the one that matters for an unattended run. A provider that is
not signed in, a schema the API rejects, a build host that is unreachable: each
fails every round in the same way, and a loop without a circuit breaker will
happily pay for all of them. Marking functions unverifiable does *not* count as
failure, because refusing is a result.

## What it produces

Ports that are **written and linted, not verified**. Nothing has run them. The
summary says so every time, because writing a port and proving it are different
claims and only the second is worth anything.

To verify, you need a machine that can build and run the program:

```sh
decomp hosts add linux --ssh user@box --workdir /path/to/recomp
decomp auto --provider codex --verify --host linux
```

With `--verify` each round also builds, runs a session with deliberately wrong
ports armed, reads the verdicts, and promotes what earned it. If the build or
the session refuses, the run stops rather than continuing to write ports that
cannot be checked.

## Picking a budget

Cost per port depends on the provider, the tier, and how many retries a function
needs. From real runs on this corpus:

- a mechanical translation costs nothing, and covers roughly one ungated
  function in eight
- a model port on the small tier runs tens of thousands of tokens, most of it
  reasoning

Start small and read the ledger rather than guessing:

```sh
decomp auto --provider codex -n 4 --max-rounds 2 --max-cost 1
decomp cost --by model
```

## Watching it

Each round prints as it completes. To follow a long run from another terminal:

```sh
decomp status          # queue counts, in flight, settled
decomp cost --by model # what it has spent
```

Everything is resumable. A killed run loses the round it was in and nothing
else: the ports it already wrote are on disk and recorded, and the next `auto`
picks up where it stopped.
