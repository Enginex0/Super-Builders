#!/bin/bash
set -euo pipefail

KERNEL_DIR="${1:?}"
SL="${2:?}"
ANDROID_VER="${3:?}"
KERNEL_VER="${4:?}"
KERNEL_PATCHES="${5:-}"

cd "$KERNEL_DIR"

if [[ "$ANDROID_VER" == "android12" && "$KERNEL_VER" == "5.10" && $SL -le 209 ]]; then
  echo "[+] show_pad label fix (sublevel $SL <= 209)"
  sed -i -e 's/goto show_pad;/return 0;/' ./fs/proc/task_mmu.c
fi

if [[ "$ANDROID_VER" == "android12" && "$KERNEL_VER" == "5.10" && $SL -le 117 ]]; then
  PATCH="$KERNEL_PATCHES/wild/susfs_fix_patches/v2.0.0/a12-5.10/fdinfo.c.patch"
  if [ -f "$PATCH" ]; then
    echo "[+] fdinfo.c fix (sublevel $SL <= 117)"
    patch -p1 < "$PATCH" || true
  fi
fi

if [[ "$ANDROID_VER" == "android12" && "$KERNEL_VER" == "5.10" && $SL -le 43 ]]; then
  PATCH="$KERNEL_PATCHES/wild/susfs_fix_patches/v2.0.0/a12-5.10/base.c.patch"
  if [ -f "$PATCH" ]; then
    echo "[+] base.c fix (sublevel $SL <= 43)"
    patch -p1 < "$PATCH" || true
  fi
fi
