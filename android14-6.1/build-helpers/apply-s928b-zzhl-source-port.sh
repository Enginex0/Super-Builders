#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree}"
OVERLAY_ARCHIVE="${2:?Samsung ZZHL source port archive}"
EXPECTED_OVERLAY_SHA256="${3:?expected overlay SHA256}"
EXPECTED_AOSP_COMMIT="${4:?expected AOSP common base commit}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

[[ -e "$COMMON_TREE/.git" ]] || {
  echo "::error::Common kernel Git tree not found: $COMMON_TREE"
  exit 1
}
[[ -f "$OVERLAY_ARCHIVE" ]] || {
  echo "::error::Samsung source port archive not found: $OVERLAY_ARCHIVE"
  exit 1
}

ACTUAL_AOSP_COMMIT=$(git -C "$COMMON_TREE" rev-parse HEAD)
[[ "$ACTUAL_AOSP_COMMIT" == "$EXPECTED_AOSP_COMMIT" ]] || {
  echo "::error::Samsung source port base mismatch: $ACTUAL_AOSP_COMMIT != $EXPECTED_AOSP_COMMIT"
  exit 1
}
[[ -z "$(git -C "$COMMON_TREE" status --porcelain --untracked-files=all)" ]] || {
  echo "::error::Samsung source port requires a clean, freshly synced AOSP common tree"
  git -C "$COMMON_TREE" status --short
  exit 1
}

ACTUAL_OVERLAY_SHA256=$(sha256sum "$OVERLAY_ARCHIVE" | awk '{print $1}')
[[ "$ACTUAL_OVERLAY_SHA256" == "$EXPECTED_OVERLAY_SHA256" ]] || {
  echo "::error::Samsung source port SHA256 mismatch"
  echo "expected=$EXPECTED_OVERLAY_SHA256"
  echo "actual=$ACTUAL_OVERLAY_SHA256"
  exit 1
}

"$PYTHON_BIN" - "$COMMON_TREE" "$OVERLAY_ARCHIVE" <<'PY'
from __future__ import annotations

import csv
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

root = Path(sys.argv[1]).resolve()
archive = Path(sys.argv[2]).resolve()


def safe_relative(raw: str) -> Path:
    posix = PurePosixPath(raw)
    if posix.is_absolute() or not posix.parts or ".." in posix.parts or "." in posix.parts:
        raise SystemExit(f"unsafe Samsung overlay path: {raw!r}")
    if "\\" in raw or posix.parts[0] == ".git":
        raise SystemExit(f"forbidden Samsung overlay path: {raw!r}")
    return Path(*posix.parts)


def git_blob(data: bytes) -> str:
    prefix = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(prefix + data).hexdigest()


members: dict[str, tuple[bytes, int]] = {}
with tarfile.open(archive, "r:xz") as source:
    for member in source:
        if not member.isfile():
            raise SystemExit(f"non-regular Samsung overlay member: {member.name!r}")
        safe_relative(member.name)
        if member.name in members:
            raise SystemExit(f"duplicate Samsung overlay member: {member.name!r}")
        extracted = source.extractfile(member)
        if extracted is None:
            raise SystemExit(f"cannot read Samsung overlay member: {member.name!r}")
        members[member.name] = (extracted.read(), member.mode & 0o777)

expected_metadata = {"SOURCE.txt", "manifest.tsv", "delete.txt"}
actual_metadata = {name for name in members if not name.startswith("files/")}
if actual_metadata != expected_metadata:
    raise SystemExit(
        f"unexpected Samsung overlay metadata: {sorted(actual_metadata ^ expected_metadata)}"
    )

source_text = members["SOURCE.txt"][0].decode("utf-8")
source_markers = (
    "Samsung source: SM-S928B_16_Opensource.zip / S928BXXS6DZG1",
    "Samsung package SHA256: 512c0a0b74646ddbb64ac8adea7c396c90458c2c12cf7f437e9d20282a33fa3c",
    "Target firmware: S928BXXU6ZZHL / EUX",
    "Target: e3q_eur_openx",
    "Chipset: pineapple",
    "AOSP common base: 4bd1b41bff8bb87bed8c3621fa2bb5b2e96f5d8c",
    "Port base: 0f62335d867d7ccc2933ff1e3c5ae6a244d12994",
    "Port method: three-way merge retaining AOSP 6.1.162 and Samsung DZG1 changes",
    "Line endings: 18 Samsung text payloads normalized to LF for deterministic Linux patching",
    "Port repair: retained AOSP 6.1.162 ARM CPU IDs required by cpu_errata.c",
    "Port repair: removed stale timing and return locals from Samsung void f2fs_enable_checkpoint",
    "Port repair: restored Samsung nf_conn alloc/free vendor-hook declaration, include, and exports",
)
for marker in source_markers:
    if marker not in source_text:
        raise SystemExit(f"Samsung overlay source marker is missing: {marker}")

manifest_text = members["manifest.tsv"][0].decode("utf-8")
reader = csv.DictReader(io.StringIO(manifest_text), delimiter="\t")
expected_fields = ["status", "path", "aosp_git_blob", "ported_git_blob", "size"]
if reader.fieldnames != expected_fields:
    raise SystemExit(f"unexpected Samsung overlay manifest fields: {reader.fieldnames}")

manifest: dict[str, dict[str, str]] = {}
status_counts = {"changed": 0, "ported-only": 0}
for row in reader:
    relative = safe_relative(row["path"]).as_posix()
    if relative in manifest:
        raise SystemExit(f"duplicate Samsung overlay manifest path: {relative}")
    if row["status"] not in status_counts:
        raise SystemExit(f"unexpected Samsung overlay status: {row['status']}")
    if len(row["ported_git_blob"]) != 40:
        raise SystemExit(f"invalid ported Git blob for {relative}")
    base = root / safe_relative(relative)
    if row["status"] == "changed":
        if len(row["aosp_git_blob"]) != 40 or not base.is_file():
            raise SystemExit(f"missing pinned AOSP base file for {relative}")
        if git_blob(base.read_bytes()) != row["aosp_git_blob"]:
            raise SystemExit(f"pinned AOSP base Git blob mismatch: {relative}")
    elif row["aosp_git_blob"] != "-" or base.exists() or base.is_symlink():
        raise SystemExit(f"ported-only path already exists in pinned AOSP base: {relative}")
    archive_name = "files/" + relative
    if archive_name not in members:
        raise SystemExit(f"Samsung overlay payload is missing: {relative}")
    data = members[archive_name][0]
    if len(data) != int(row["size"]):
        raise SystemExit(f"Samsung overlay size mismatch: {relative}")
    if git_blob(data) != row["ported_git_blob"]:
        raise SystemExit(f"Samsung port Git blob mismatch: {relative}")
    manifest[relative] = row
    status_counts[row["status"]] += 1

payload_paths = {name.removeprefix("files/") for name in members if name.startswith("files/")}
if payload_paths != set(manifest):
    raise SystemExit("Samsung overlay payload and manifest path sets differ")
if status_counts != {"changed": 402, "ported-only": 421}:
    raise SystemExit(f"unexpected Samsung overlay counts: {status_counts}")

delete_paths = [line for line in members["delete.txt"][0].decode("utf-8").splitlines() if line]
if len(delete_paths) != 308 or len(set(delete_paths)) != 308:
    raise SystemExit(f"unexpected Samsung deletion count: {len(delete_paths)}")
for raw in delete_paths:
    relative = safe_relative(raw)
    target = root / relative
    if target.is_dir() and not target.is_symlink():
        raise SystemExit(f"Samsung deletion target unexpectedly became a directory: {raw}")

# The complete archive is validated before mutating the ephemeral synced tree.
for raw in delete_paths:
    target = root / safe_relative(raw)
    if target.exists() or target.is_symlink():
        target.unlink()

for relative, row in manifest.items():
    archive_name = "files/" + relative
    data, mode = members[archive_name]
    target = root / safe_relative(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    os.chmod(target, mode)

for relative, row in manifest.items():
    target = root / safe_relative(relative)
    if git_blob(target.read_bytes()) != row["ported_git_blob"]:
        raise SystemExit(f"post-apply Samsung port mismatch: {relative}")

declared_hooks: set[str] = set()
for header in (root / "include/trace/hooks").glob("*.h"):
    declared_hooks.update(
        match.decode("ascii")
        for match in re.findall(
            rb"DECLARE_(?:RESTRICTED_)?HOOK\(\s*(android_(?:r)?vh_[A-Za-z0-9_]+)",
            header.read_bytes(),
        )
    )
called_hooks: set[str] = set()
for relative in manifest:
    if Path(relative).suffix not in {".c", ".h"}:
        continue
    called_hooks.update(
        match.decode("ascii")
        for match in re.findall(
            rb"\btrace_(android_(?:r)?vh_[A-Za-z0-9_]+)\s*\(",
            (root / safe_relative(relative)).read_bytes(),
        )
    )
missing_hooks = {
    hook
    for hook in called_hooks
    if hook not in declared_hooks
    and not (hook.endswith("_enabled") and hook[:-8] in declared_hooks)
}
if missing_hooks:
    raise SystemExit(
        "Samsung source port calls undeclared Android vendor hooks: "
        + ", ".join(sorted(missing_hooks))
    )

print(
    "Applied Samsung common source port for ZZHL: "
    f"{status_counts['changed']} changed, "
    f"{status_counts['ported-only']} added, {len(delete_paths)} removed"
)
print(f"Verified declarations for {len(called_hooks)} Android hook call sites in the port")
PY

for SPEC in \
  "Makefile:36a79f031105375d5ef92f3789e7856d72c14a2431c3a5a06d7342297bebcca2" \
  "fs/namespace.c:a0c3aae461f43272d7b789d713e2724e4326f719fb5ec49045fdaaefb4272a17" \
  "include/trace/hooks/xhci.h:fda469c283497303230ff7a145d26cc16a80cd8ea5bf4b4eff23705b59da4f29" \
  "drivers/android/vendor_hooks.c:827e858bc81c13c77c0eb142080488ec167604cdee339e315b7ab999d42e695e" \
  "drivers/usb/host/xhci-plat.c:adcb2f8a1c1d923d10908e2ddaaa80db2b5be75b47396613d248d6d4aa877347" \
  "arch/arm64/configs/gki_defconfig:e41b9d67b06ebf8a11ae7a4cf6a394d368a97d396cea1ae6001fe7aec05e7b1d" \
  "arch/arm64/include/asm/cputype.h:15f0de7fbe3a1497c624e7ab6cee78d8cdffdecaa2c8379dc4e51a2711a8b3bc" \
  "include/trace/hooks/net.h:8b98cdb3bafa9cb11dc16fc9dfb8c7276e877a6a3b88f727d7a3cf8a2d8c324f" \
  "fs/f2fs/f2fs.h:c2f98582c9f80fb15cea8a71bd3a1450abb9a7ce36e2d5149951ff6ce28eeab8" \
  "fs/f2fs/super.c:9ca984db09c2e4637530011c0777562d16f3fd8013b5871b1d825d8e3577dfab" \
  "kernel/module/main.c:e7cf07d5482191b6dec229ebba591d7139a9f4a21a9070795a3b4c23c0b8125b" \
  "net/netfilter/nf_conntrack_core.c:cc6cedbe253432bfdc2772d0a823631a416ac919611172d11d1034672db83cbb" \
  "android/abi_gki_aarch64_galaxy:8a33aa1742becd1b334bbfb16f88dbad5086a1220f14a586ea47589d7672ef2c"; do
  RELATIVE=${SPEC%%:*}
  EXPECTED=${SPEC#*:}
  ACTUAL=$(sha256sum "$COMMON_TREE/$RELATIVE" | awk '{print $1}')
  [[ "$ACTUAL" == "$EXPECTED" ]] || {
    echo "::error::Audited Samsung source-port hash mismatch: $RELATIVE"
    echo "expected=$EXPECTED"
    echo "actual=$ACTUAL"
    exit 1
  }
done

grep -qx $'#define ARM_CPU_PART_NEOVERSE_V3AE\t0xD83' \
  "$COMMON_TREE/arch/arm64/include/asm/cputype.h"
grep -qx $'#define MIDR_NEOVERSE_V3AE\tMIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_NEOVERSE_V3AE)' \
  "$COMMON_TREE/arch/arm64/include/asm/cputype.h"
grep -qF 'MIDR_ALL_VERSIONS(MIDR_NEOVERSE_V3AE)' \
  "$COMMON_TREE/arch/arm64/kernel/cpu_errata.c"

grep -qF 'DECLARE_RESTRICTED_HOOK(android_rvh_nf_conn_alloc,' \
  "$COMMON_TREE/include/trace/hooks/net.h"
grep -qF 'DECLARE_RESTRICTED_HOOK(android_rvh_nf_conn_free,' \
  "$COMMON_TREE/include/trace/hooks/net.h"
grep -qxF '#include <trace/hooks/net.h>' \
  "$COMMON_TREE/net/netfilter/nf_conntrack_core.c"
grep -qxF 'EXPORT_TRACEPOINT_SYMBOL_GPL(android_rvh_nf_conn_alloc);' \
  "$COMMON_TREE/drivers/android/vendor_hooks.c"
grep -qxF 'EXPORT_TRACEPOINT_SYMBOL_GPL(android_rvh_nf_conn_free);' \
  "$COMMON_TREE/drivers/android/vendor_hooks.c"

F2FS_CHECKPOINT=$(sed -n \
  '/^static void f2fs_enable_checkpoint(struct f2fs_sb_info \*sbi)$/,/^static int f2fs_remount/p' \
  "$COMMON_TREE/fs/f2fs/super.c")
[[ "$(grep -cF 'f2fs_sync_fs(sbi->sb, 1);' <<< "$F2FS_CHECKPOINT")" -eq 1 ]]
for STALE in 'long long start, writeback, end;' 'int ret;' 'ktime_get()'; do
  if grep -qF "$STALE" <<< "$F2FS_CHECKPOINT"; then
    echo "::error::Stale F2FS checkpoint merge fragment remains: $STALE"
    exit 1
  fi
done

for RELATIVE in \
  arch/arm64/configs/gki_defconfig \
  drivers/android/vendor_hooks.c \
  fs/f2fs/f2fs.h \
  fs/f2fs/super.c \
  fs/namespace.c \
  include/trace/hooks/net.h \
  kernel/module/main.c \
  net/netfilter/nf_conntrack_core.c; do
  if LC_ALL=C grep -q $'\r' "$COMMON_TREE/$RELATIVE"; then
    echo "::error::Audited Samsung patch target contains CR line endings: $RELATIVE"
    exit 1
  fi
done

grep -qx 'VERSION = 6' "$COMMON_TREE/Makefile"
grep -qx 'PATCHLEVEL = 1' "$COMMON_TREE/Makefile"
grep -qx 'SUBLEVEL = 162' "$COMMON_TREE/Makefile"
echo "Verified SM-S928B Android 17 ZZHL source port on AOSP 6.1.162"
