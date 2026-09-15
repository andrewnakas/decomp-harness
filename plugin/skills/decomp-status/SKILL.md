---
name: decomp-status
description: Where a decompilation project stands - corpus size, queue counts, what is verified, and what it has cost so far. Use when asked how the decompilation is going, what is left, or how many tokens it has used.
---

# Project state

Call `project_status` for the corpus, the queue and the last build and session.
Call `cost` for tokens per verified function and the cache hit rate.

Read both before answering. The numbers that matter to someone asking "how is it
going" are: how many functions are settled, how many are open, and whether the
last session was trusted. A session that ran but was not trusted verified
nothing, and saying otherwise would be wrong.

If the last session shows `UNTRUSTED`, say so first and say why: it means no
deliberately wrong port was caught, so the verdicts from it were not recorded.
