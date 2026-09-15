---
name: decomp-hunt
description: Answer a question about a binary - what calls this, what is at this offset, what references this constant, what does this struct look like. Use when asked to investigate or find something in a decompilation project.
---

# Investigating

Use the tools; do not grep the corpus. Offsets alias across unrelated
structures, and three of the original project's investigations went wrong by
treating that coincidence as a fact.

| Question | Tool |
|---|---|
| What is this function | `fn_info`, then `fn_view` |
| What calls it, what does it call | `fn_graph` with `direction` |
| What references this address | `search` with `constant` |
| What is this struct | `struct_get` |
| What looks like this | `similar` |
| What went wrong here before | `lessons` |

## Reporting what you find

Say what the evidence supports and no more. `struct_get` marks proposed fields
as proposed; repeat that distinction when you report them, because a proposal
laundered into a fact is how the original project lost three sessions.

If you learn something worth keeping, record it: `propose` for a name or a
field. It is stored as a proposal and will not overwrite anything cited.

A coherent story that explains several loose ends at once is the most dangerous
kind, because it feels like insight. Check it against the whole distribution,
not the first few cases.
