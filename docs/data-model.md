# Data model

One SQLite file per project, at `.decomp/db.sqlite`. It is the harness's memory:
what the corpus is, what has been established about it, what was tried, and what
each attempt cost.

## Evidence

The table that matters most is `symbol_evidence` and its counterpart
`field_evidence`. A name or an offset is never stored as a bare fact. It is
stored with where it came from and how much that source is worth:

| Source | Confidence | Meaning |
|---|---|---|
| `lifted` | 0.95 | The recompiler resolved it from the binary |
| `plugin_meta` | 0.85 | Read out of the program's own metadata |
| `doc` | 0.9 | A recovered-layout header, cited to a function |
| `llm` | ≤ 0.6 | A model's proposal |
| `user` | 1.0 | A person said so |

A model's name never displaces one resolved from the binary, and a proposed
field never overwrites a cited one. This is enforced in code, not by convention.

The reason is specific. Offsets alias across unrelated structures: `+0x30` and
`+0xCC` appear in half a dozen layouts, and three of the audio project's
investigations went wrong by treating a coincidence as a fact. So a packet
annotates an offset only where exactly one struct claims it, and says nothing
where several do.

## Function states

```
pending ─► drafted / written ─► armed ─► verified ─► promoted
                │                  │         │
                │                  │         └─► thin      (verified, thinly covered)
                │                  └─► divergent           (a comparison disagreed)
                └─► gate1..gate4                           (cannot be bracketed)
                └─► needs_human                            (three attempts, no answer)
```

`thin` is not a failure. It means a comparison never disagreed but did not cover
enough of the function for that to mean much, which is a different claim from
`verified` and worth keeping separate.

## The ledger

Every model call writes a row: provider, model, purpose, the packet's hash and
estimated size, the four token counts, cost, duration, whether the answer
matched its schema, and the outcome. `decomp cost` reads this.

The token estimator calibrates itself from these rows. It starts at 3.1
characters per token and moves toward what the providers actually report,
rejecting observations that imply an implausible ratio — a call dominated by a
cached prefix would otherwise skew it badly.
