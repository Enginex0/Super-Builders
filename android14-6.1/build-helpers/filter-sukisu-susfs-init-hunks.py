#!/usr/bin/env python3
"""Drop two legacy KernelSU init.c hunks handled by the SukiSU v4.1 port."""

from __future__ import annotations

from pathlib import Path
import os
import sys
import tempfile


TARGET = "kernel/core/init.c"
EXPECTED_HUNKS = 8
EXPECTED_REMOVED = 2

INCLUDE_HUNK_MARKERS = (
    '#include "hook/syscall_hook.h"',
    '#include "infra/symbol_resolver.h"',
    '#include "hook/setuid_hook.h"',
    '#include "feature/sucompat.h"',
)

INIT_HUNK_MARKERS = (
    "ksu_init_symbol_resolver();",
    "ksu_syscall_hook_init();",
    "susfs_init();",
    "ksu_feature_init();",
)


def hunk_payload(lines: list[str]) -> str:
    payload: list[str] = []
    for line in lines[1:]:
        if line[:1] in {" ", "+", "-"}:
            payload.append(line[1:])
        else:
            payload.append(line)
    return "".join(payload)


def should_remove(lines: list[str]) -> bool:
    payload = hunk_payload(lines)
    return all(marker in payload for marker in INCLUDE_HUNK_MARKERS) or all(
        marker in payload for marker in INIT_HUNK_MARKERS
    )


def filter_patch(text: str) -> tuple[str, list[str], int, int]:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    removed_headers: list[str] = []
    current_file: str | None = None
    target_hunks = 0
    retained_target_hunks = 0
    index = 0

    while index < len(lines):
        line = lines[index]

        if line.startswith("diff --git "):
            current_file = None

        if line.startswith("--- a/"):
            current_file = line[len("--- a/") :].strip()

        if current_file == TARGET and line.startswith("@@ "):
            end = index + 1
            while end < len(lines):
                candidate = lines[end]
                if (
                    candidate.startswith("@@ ")
                    or candidate.startswith("diff --git ")
                    or candidate.startswith("--- a/")
                ):
                    break
                end += 1

            hunk = lines[index:end]
            target_hunks += 1
            if should_remove(hunk):
                removed_headers.append(line.strip())
            else:
                output.extend(hunk)
                retained_target_hunks += 1
            index = end
            continue

        output.append(line)
        index += 1

    return "".join(output), removed_headers, target_hunks, retained_target_hunks


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PATCH", file=sys.stderr)
        return 2

    patch = Path(sys.argv[1])
    if not patch.is_file():
        print(f"error: SUSFS KernelSU patch does not exist: {patch}", file=sys.stderr)
        return 1

    original = patch.read_text(encoding="utf-8")
    filtered, removed, target_hunks, retained = filter_patch(original)

    if target_hunks != EXPECTED_HUNKS:
        print(
            f"error: expected {EXPECTED_HUNKS} {TARGET} hunks, found {target_hunks}",
            file=sys.stderr,
        )
        return 1
    if len(removed) != EXPECTED_REMOVED:
        print(
            f"error: expected to remove {EXPECTED_REMOVED} legacy {TARGET} hunks, "
            f"matched {len(removed)}",
            file=sys.stderr,
        )
        return 1
    if retained != EXPECTED_HUNKS - EXPECTED_REMOVED:
        print(
            f"error: expected to retain {EXPECTED_HUNKS - EXPECTED_REMOVED} "
            f"{TARGET} hunks, retained {retained}",
            file=sys.stderr,
        )
        return 1
    if filtered == original:
        print("error: SUSFS patch was not changed", file=sys.stderr)
        return 1

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{patch.name}.", suffix=".tmp", dir=patch.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as temporary:
            temporary.write(filtered)
        os.replace(temporary_name, patch)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)

    print(
        "Prepared SukiSU-compatible SUSFS patch: "
        f"removed {len(removed)} legacy {TARGET} hunks and retained {retained}."
    )
    for header in removed:
        print(f"  removed {header}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
