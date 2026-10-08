#!/bin/bash
set -euo pipefail

KSU_TREE="${1:?KernelSU tree}"
TARGET="$KSU_TREE/kernel/supercall/dispatch.c"

[[ -f "$TARGET" ]] || {
  echo "::error::ReSukiSU dispatch source is unavailable: $TARGET"
  exit 1
}

python3 - "$TARGET" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

marker = 'cmd_manage_try_umount: %s is already here!'
if text.count(marker) != 1:
    raise SystemExit(f"Expected exactly one duplicate-umount marker, found {text.count(marker)}")

# Isolate only the duplicate-entry branch. The previous implementation searched
# from the marker to any later `return 0;`, which could cross the closing brace
# and falsely classify an untouched `return -EEXIST;` as already patched.
start = text.index(marker)
branch_end = text.find('}', start)
if branch_end < 0:
    raise SystemExit("Could not isolate duplicate umount ADD branch")

block = text[start:branch_end]
neg = list(re.finditer(r'return\s+-EEXIST\s*;', block))
pos = list(re.finditer(r'return\s+0\s*;', block))

if len(neg) == 1 and not pos:
    match = neg[0]
    block = block[:match.start()] + 'return 0;' + block[match.end():]
    text = text[:start] + block + text[branch_end:]
    print("ReSukiSU duplicate umount ADD patched: -EEXIST -> 0")
elif not neg and len(pos) == 1:
    print("ReSukiSU duplicate umount ADD is already idempotent")
else:
    raise SystemExit(
        "Unexpected duplicate umount ADD return layout: "
        f"-EEXIST={len(neg)} return0={len(pos)}"
    )

# Re-isolate and audit the exact branch after modification. Do not accept a
# return from any later branch in cmd_manage_try_umount().
start = text.index(marker)
branch_end = text.find('}', start)
block = text[start:branch_end]
if re.search(r'return\s+-EEXIST\s*;', block):
    raise SystemExit("Duplicate umount ADD still returns -EEXIST")
if len(re.findall(r'return\s+0\s*;', block)) != 1:
    raise SystemExit("Duplicate umount ADD does not contain exactly one success return")

path.write_text(text, encoding="utf-8")
print("ReSukiSU duplicate kernel umount ADD now returns success")
print("Existing mount-list entry and flags remain unchanged; only duplicate status becomes idempotent")
PY
