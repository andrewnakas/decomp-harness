#!/usr/bin/env python3
"""Refuse to read the corpus directly, and say what to use instead.

Reading decompiled output file by file was the largest single token sink in the
work this harness replaces. The tools exist precisely so that does not happen,
and a rule in a prompt is a request; this is the enforcement.

The guard is narrow on purpose. It blocks the generated and decompiled trees
where a single file can be thousands of lines, and lets everything else through:
a harness that fought the user over ordinary files would just be turned off.
"""

from __future__ import annotations

import json
import re
import sys

# Paths where one file is large and a tool answers the same question smaller.
# Matched on the directory rather than the filename, so a glob is caught as
# readily as a single path: `**/out/decomp/sub_*.c` is the same request.
CORPUS_PATTERNS = (
    (re.compile(r"/generated/[\w*]*_recomp\."), 'fn_view with kind="asm"'),
    (re.compile(r"/out/decomp/"), "fn_view"),
    (re.compile(r"/out/lifted/"), 'fn_view with kind="asm"'),
    (re.compile(r"/\.decomp/views/"), "fn_view"),
    (re.compile(r"/ports/notes/"), "fn_info"),
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    candidate = " ".join(
        str(tool_input.get(key, ""))
        for key in ("file_path", "path", "pattern", "glob")
    )
    if not candidate.strip():
        return 0

    for pattern, alternative in CORPUS_PATTERNS:
        if pattern.search(candidate):
            print(
                json.dumps({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"That is the decompiled corpus. One file there can be "
                            f"thousands of lines, and reading it is the cost this "
                            f"harness exists to remove. Use {alternative} instead, "
                            f"which returns the same function at a fraction of the "
                            f"size."
                        ),
                    }
                })
            )
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
