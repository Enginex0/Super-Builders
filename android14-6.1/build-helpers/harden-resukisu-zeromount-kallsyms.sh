#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common tree}"
TARGET="$COMMON_TREE/kernel/kallsyms.c"

[[ -f "$TARGET" ]] || {
  echo "::error::kallsyms source is unavailable: $TARGET"
  exit 1
}

python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

base_marker = 'susfs_starts_with(iter->name, "ksu_") ||'
if base_marker not in text:
    raise SystemExit(
        "SUSFS kallsyms filter is missing; refusing to modify an unexpected kallsyms.c"
    )

# SUSFS versions differ in which KSU prefixes are already filtered.  Add each
# missing prefix independently instead of using one existing prefix as a proxy
# for the whole group.  This keeps the helper idempotent across pinned SUSFS
# revisions and avoids false audit failures when only one new leak class is
# absent (for example __initcall__kmod_kernelsu).
ksu_anchor = 'susfs_starts_with(iter->name, "is_ksu_") ||'
ksu_filters = (
    'susfs_starts_with(iter->name, "setup_ksu_") ||',
    'susfs_starts_with(iter->name, "do_ksu_") ||',
    'susfs_starts_with(iter->name, "is_task_ksu_") ||',
    'susfs_starts_with(iter->name, "anon_ksu_") ||',
    'susfs_starts_with(iter->name, "bb_bprm_set_creds.ksu_") ||',
    'susfs_starts_with(iter->name, "__initstub__kmod_kernelsu") ||',
    'susfs_starts_with(iter->name, "__initcall__kmod_kernelsu") ||',
)

duplicate_ksu = [needle for needle in ksu_filters if text.count(needle) > 1]
if duplicate_ksu:
    raise SystemExit(f"Duplicate KSU kallsyms filters detected: {duplicate_ksu}")

missing_ksu = [needle for needle in ksu_filters if needle not in text]
if missing_ksu:
    if text.count(ksu_anchor) != 1:
        raise SystemExit("KSU kallsyms insertion anchor is not unique")
    insertion = '\n\t\t\t'.join(missing_ksu) + '\n\t\t\t'
    text = text.replace(ksu_anchor, insertion + ksu_anchor, 1)

# ZeroMount is not covered by upstream SUSFS.  Treat its normal/init symbol
# classes with the same per-prefix missing-set logic.
zm_anchor = 'susfs_starts_with(iter->name, "susfs_") ||'
zm_filters = (
    'susfs_starts_with(iter->name, "zeromount_") ||',
    'susfs_starts_with(iter->name, "__initstub__kmod_zeromount") ||',
    'susfs_starts_with(iter->name, "__initcall__kmod_zeromount") ||',
)

duplicate_zm = [needle for needle in zm_filters if text.count(needle) > 1]
if duplicate_zm:
    raise SystemExit(f"Duplicate ZeroMount kallsyms filters detected: {duplicate_zm}")

missing_zm = [needle for needle in zm_filters if needle not in text]
if missing_zm:
    if text.count(zm_anchor) != 1:
        raise SystemExit("ZeroMount kallsyms insertion anchor is not unique")
    text = text.replace(
        zm_anchor,
        zm_anchor + ''.join('\n\t\t\t' + needle for needle in missing_zm),
        1,
    )

required = ksu_filters + zm_filters
invalid = [needle for needle in required if text.count(needle) != 1]
if invalid:
    raise SystemExit(f"kallsyms hardening audit failed: {invalid}")

path.write_text(text, encoding="utf-8")
print("ReSukiSU kallsyms filter covers observed KSU normal/init/local symbol names")
print("ZeroMount kallsyms filter covers normal, initstub and initcall symbols")
print("Kallsyms hardening is idempotent across partially pre-hardened SUSFS revisions")
print("Internal kallsyms lookup/export tables are unchanged; only /proc/kallsyms output is filtered")
PY
