---
name: decomp-next
description: Port the next functions in a decompilation project, or a specific address. Use when asked to work on the decompilation, port a function, or continue the decomp.
---

# Porting a function

## Choosing

`queue_next` gives the next functions in order: tier, then family, then how
often they run. Siblings arrive together on purpose, because one insight
usually serves several.

## Working one

1. `fn_info <addr>` for the facts: tier, gate, call counts, how many stores.
2. `fn_view <addr>` for the packet. That is the whole context. Do not open
   files: the corpus is large and reading it is what this harness exists to
   avoid. If you need the assembly, ask for `kind="asm"`.
3. `similar <addr>` if a verified sibling exists; its shape usually transfers.
4. Write the body and submit it with `port_submit`.

## What to submit

Statements only. The harness writes the namespace, the signature and the
registration macro, so writing them yourself is rejected.

Reproduce the original exactly, bugs included. It will be compared against the
original's own behaviour, and a fix reads as a divergence.

Declare every memory span the body writes, including writes made by anything it
calls, and exclude the function's own frame. The harness rewinds exactly what
you declare, so a write outside your windows is never undone and reaches the
running program. An incomplete window set is not a smaller answer, it is a wrong
one.

A window rooted at a pointer read during the call needs a `deref`: the hint
`[r3+4]+336` means load from `r3+4`, then offset 336 from there. Writing
`r3+336` instead rewinds the wrong address entirely.

Name in `result_registers` whatever the caller reads. A return value nobody
compares is a comparison that cannot fail.

## When not to port

If the write set cannot be known from the entry state, if the function reaches
something unreplayable, or if it reads the clock, call `mark_blocked` with the
reason. A function honestly marked unverifiable is worth more than one that
passes a comparison covering a third of its calls.

If the packet does not contain what you need, say so rather than guessing.
