#!/bin/bash
set -euo pipefail

FRAGMENT_SRC="${1:?}"
FRAGMENT_DST="${2:?}"
DEFCONFIG="${3:?}"
shift 3

ADD_SUSFS=false
ADD_SUSFS_UID_GATE=false
ADD_OVERLAYFS=false
ADD_ZRAM=false
ADD_KPM=false
ADD_ZEROMOUNT=false
ADD_DROIDSPACES=false
USE_KLEAF=false

for arg in "$@"; do
  case "$arg" in
    --susfs) ADD_SUSFS=true ;;
    --susfs-uid-gated-hiding) ADD_SUSFS_UID_GATE=true ;;
    --overlayfs) ADD_OVERLAYFS=true ;;
    --zram) ADD_ZRAM=true ;;
    --kpm) ADD_KPM=true ;;
    --zeromount) ADD_ZEROMOUNT=true ;;
    --droidspaces) ADD_DROIDSPACES=true ;;
    --kleaf) USE_KLEAF=true ;;
  esac
done

if $ADD_SUSFS_UID_GATE && ! $ADD_SUSFS; then
  echo "::error::UID-gated hiding requires SUSFS"
  exit 1
fi

extract_section() {
  awk "/^# \\[$1\\]/{found=1; next} /^# \\[/{found=0} found && NF" "$FRAGMENT_SRC"
}

extract_file_patch() {
  local source_patch="$1"
  local target_path="$2"
  local output_patch="$3"

  awk -v target="$target_path" '
    /^diff / {
      emit = ($0 ~ target "$" || $0 ~ target "[[:space:]]*$")
    }
    emit { print }
  ' "$source_patch" > "$output_patch"
}

extract_matching_hunks() {
  local source_patch="$1"
  local target_path="$2"
  local pattern="$3"
  local output_patch="$4"
  local file_patch="${output_patch}.file"

  extract_file_patch "$source_patch" "$target_path" "$file_patch"

  python3 - "$file_patch" "$pattern" "$output_patch" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
pattern = re.compile(sys.argv[2])
out = Path(sys.argv[3])
lines = source.read_text().splitlines(keepends=True)

header = []
hunks = []
current = []
for line in lines:
    if line.startswith('@@ '):
        if current:
            hunks.append(current)
        current = [line]
    elif current:
        current.append(line)
    else:
        header.append(line)
if current:
    hunks.append(current)

selected = [h for h in hunks if pattern.search(''.join(h))]
if not selected:
    raise SystemExit(f'No matching hunks for pattern: {pattern.pattern}')
out.write_text(''.join(header + [line for h in selected for line in h]))
PY
}

apply_targeted_patch() {
  local common_tree="$1"
  local source_patch="$2"
  local target_path="$3"
  local temp_patch="$4"
  local hunk_pattern="${5:-}"

  if [[ -n "$hunk_pattern" ]]; then
    extract_matching_hunks "$source_patch" "$target_path" "$hunk_pattern" "$temp_patch"
  else
    extract_file_patch "$source_patch" "$target_path" "$temp_patch"
  fi

  if [[ ! -s "$temp_patch" ]]; then
    echo "::error::No patch section found for $target_path in $(basename "$source_patch")"
    return 1
  fi

  # --forward is mandatory. Without it, GNU patch may silently assume -R and
  # remove hooks that are already installed by the SukiSU reconciliation step.
  if patch -d "$common_tree" -p1 -F3 --forward --dry-run --batch < "$temp_patch" >/dev/null 2>&1; then
    echo "Applying official SUSFS base hooks: $target_path"
    patch -d "$common_tree" -p1 -F3 --forward --batch --no-backup-if-mismatch < "$temp_patch"
    return 0
  fi

  # A successful explicit reverse dry-run means the selected hunks are already
  # present. Never execute the reverse operation.
  if patch -d "$common_tree" -R -p1 -F3 --forward --dry-run --batch < "$temp_patch" >/dev/null 2>&1; then
    echo "Official SUSFS base hooks already present: $target_path"
    return 0
  fi

  echo "::error::Official SUSFS base hooks for $target_path neither apply forward nor are fully present"
  return 1
}

apply_optional_targeted_patch() {
  local common_tree_path="$1"
  local source_patch="$2"
  local target_path="$3"
  local temp_patch="$4"
  local hunk_pattern="${5:-}"

  if [[ -z "$source_patch" || ! -f "$source_patch" ]]; then
    echo "::warning::Skip optional hunk recovery for $target_path (missing patch: $source_patch)"
    return 0
  fi

  if apply_targeted_patch "$common_tree_path" "$source_patch" "$target_path" "$temp_patch" "$hunk_pattern"; then
    return 0
  fi

  echo "::warning::Optional hunk recovery failed for $target_path from $(basename "$source_patch")"
  return 0
}

# Paths shared by both SukiSU reconciliation and the ReSukiSU verification-only
# path. They must exist before the permanent Open Redirect checks below.
if $ADD_SUSFS; then
  VERSION_DIR="$(cd "$(dirname "$FRAGMENT_SRC")" && pwd)"
  COMMON_TREE="$(cd "$(dirname "$DEFCONFIG")/../../.." && pwd)"
  VERIFY_SCRIPT="$VERSION_DIR/build-helpers/verify-susfs-v2.2-procfs.sh"
  AUDIT_DIR="${RUNNER_TEMP:-/tmp}/sukisu-susfs-artifacts"
  AUDIT_FILE="$AUDIT_DIR/susfs-procfs-audit.txt"
  mkdir -p "$AUDIT_DIR"

  [[ -f "$VERIFY_SCRIPT" ]] || {
    echo "::error::Missing SUSFS Procfs verifier: $VERIFY_SCRIPT"
    exit 1
  }
fi

# The targeted Procfs reconciliation below is specific to the enhanced
# SukiSU patch stack. ReSukiSU already receives the complete pinned SUSFS
# patch in its composite action, so replaying SukiSU hunks corrupts detection.
if $ADD_SUSFS && [[ "${KSU_VARIANT:-SukiSU}" == "SukiSU" ]]; then
  SUSFS_CLONE="${SUSFS_FOLDER:-${RUNNER_TEMP:-/tmp}/susfs4ksu}"
  TARGETED_FIX_SCRIPT="$VERSION_DIR/build-helpers/apply-susfs-targeted.sh"
  TARGETED_DIR="${RUNNER_TEMP:-/tmp}/susfs-targeted-fixes"
  ENHANCED_PATCH_DIR="$VERSION_DIR/SukiSU-Ultra/patches"
  ENHANCED_PATCH_GLOB='*enhanced_susfs-*.patch'
  OPEN_REDIRECT_RECOVERY_PATTERN='susfs_get_redirected_path|open_redirect'
  BASE_SUS_MAP_RECOVERY_PATTERN='proc_map_files_readdir|AS_FLAGS_SUS_MAP|SUSFS_IS_INODE_SUS_MAP|susfs_is_current_proc_umounted_app'
  NAMEI_OPEN_REDIRECT_RECOVERY_PATTERN='CONFIG_KSU_SUSFS_OPEN_REDIRECT|AS_FLAGS_OPEN_REDIRECT|susfs_get_redirected_path|fake_pathname|set_nameidata'

  UPSTREAM_PATCH="$(find "$SUSFS_CLONE/kernel_patches" -maxdepth 1 -type f \
    \( -name '50_add_susfs_in_kernel-6.1.patch' \
       -o -name '50_add_susfs_in_gki-android14-6.1.patch' \
       -o -name '50_add_susfs_in_kernel*6.1*.patch' \) \
    -print -quit 2>/dev/null || true)"

  [[ -n "$UPSTREAM_PATCH" && -f "$UPSTREAM_PATCH" ]] || {
    echo "::error::Official Android 14 / 6.1 SUSFS base patch was not found under $SUSFS_CLONE/kernel_patches"
    find "$SUSFS_CLONE/kernel_patches" -maxdepth 2 -type f -name '*.patch' -print 2>/dev/null || true
    exit 1
  }

  echo "Using official SUSFS base patch: $UPSTREAM_PATCH"
  mkdir -p "$TARGETED_DIR"

  apply_targeted_patch "$COMMON_TREE" "$UPSTREAM_PATCH" \
    'fs/proc/task_mmu.c' "$TARGETED_DIR/task_mmu-base.patch"
  apply_targeted_patch "$COMMON_TREE" "$UPSTREAM_PATCH" \
    'fs/proc/base.c' "$TARGETED_DIR/proc-base-base.patch"

  # namei.c already contains unrelated SUS_PATH changes from the reconciliation.
  # Import only the Open Redirect insertion hunks to avoid colliding with them.
  apply_targeted_patch "$COMMON_TREE" "$UPSTREAM_PATCH" \
    'fs/namei.c' "$TARGETED_DIR/namei-open-redirect.patch" \
    'CONFIG_KSU_SUSFS_OPEN_REDIRECT|AS_FLAGS_OPEN_REDIRECT|susfs_get_redirected_path'

  chmod +x "$VERIFY_SCRIPT"
  if ! "$VERIFY_SCRIPT" "$COMMON_TREE" "$AUDIT_FILE"; then
    echo "::warning::Initial SUSFS source audit failed; retrying with targeted hunk recovery"
    [[ -n "$UPSTREAM_PATCH" ]] || {
      echo "::error::Missing upstream SUSFS patch path for recovery (UPSTREAM_PATCH is empty)"
      exit 1
    }
    mapfile -t ENHANCED_PATCHES < <(find "$ENHANCED_PATCH_DIR" -maxdepth 1 -type f \
      -name "$ENHANCED_PATCH_GLOB" -print 2>/dev/null | LC_ALL=C sort)
    ENHANCED_PATCH="${ENHANCED_PATCHES[0]:-}"
    if (( ${#ENHANCED_PATCHES[@]} > 1 )); then
      echo "::warning::Multiple enhanced SUSFS patches detected; using first match: ${ENHANCED_PATCH##*/}"
    fi
    [[ -n "$ENHANCED_PATCH" ]] || {
      echo "::warning::Enhanced SUSFS patch was not found; using upstream-only recovery"
    }

    apply_optional_targeted_patch "$COMMON_TREE" "$UPSTREAM_PATCH" \
      'fs/susfs.c' "$TARGETED_DIR/susfs-open-redirect.patch" \
      "$OPEN_REDIRECT_RECOVERY_PATTERN"
    apply_optional_targeted_patch "$COMMON_TREE" "$UPSTREAM_PATCH" \
      'include/linux/susfs.h' "$TARGETED_DIR/susfs-h-open-redirect.patch" \
      "$OPEN_REDIRECT_RECOVERY_PATTERN"

    if [[ -n "$ENHANCED_PATCH" ]]; then
      apply_optional_targeted_patch "$COMMON_TREE" "$ENHANCED_PATCH" \
        'fs/proc/base.c' "$TARGETED_DIR/proc-base-enhanced.patch" \
        "$BASE_SUS_MAP_RECOVERY_PATTERN"
      apply_optional_targeted_patch "$COMMON_TREE" "$ENHANCED_PATCH" \
        'fs/namei.c' "$TARGETED_DIR/namei-open-redirect-enhanced.patch" \
        "$NAMEI_OPEN_REDIRECT_RECOVERY_PATTERN"
    fi

    if ! "$VERIFY_SCRIPT" "$COMMON_TREE" "$AUDIT_FILE"; then
      if [[ -f "$TARGETED_FIX_SCRIPT" ]]; then
        echo "::warning::Applying script-based SUSFS targeted recovery: $TARGETED_FIX_SCRIPT"
        chmod +x "$TARGETED_FIX_SCRIPT"
        "$TARGETED_FIX_SCRIPT" "$COMMON_TREE" || true
      fi

      if ! "$VERIFY_SCRIPT" "$COMMON_TREE" "$AUDIT_FILE"; then
        echo "::error::SUSFS source audit still failing after targeted hunk recovery. Check $AUDIT_FILE for details."
        exit 1
      fi
    fi
  fi
fi

# ReSukiSU must not replay the SukiSU reconciliation patch, but it must still
# prove that the pinned SUSFS action installed the complete functional hook set.
if $ADD_SUSFS && [[ "${KSU_VARIANT:-SukiSU}" != "SukiSU" ]]; then
  chmod +x "$VERIFY_SCRIPT"
  EXPECTED_SUSFS_VERSION="${SUSFS_EXPECTED_VERSION:-v2.2.0}"
  echo "Verifying pinned SUSFS ${EXPECTED_SUSFS_VERSION} hooks for ${KSU_VARIANT:-ReSukiSU}"
  if ! "$VERIFY_SCRIPT" "$COMMON_TREE" "$AUDIT_FILE"; then
    echo "::error::Pinned SUSFS ${EXPECTED_SUSFS_VERSION} source audit failed for ${KSU_VARIANT:-ReSukiSU}. Check $AUDIT_FILE"
    exit 1
  fi
fi

extract_section "base" >> "$FRAGMENT_DST"
$ADD_SUSFS && extract_section "susfs" >> "$FRAGMENT_DST"
$ADD_SUSFS_UID_GATE && extract_section "susfs_uid_gated_hiding" >> "$FRAGMENT_DST"
$ADD_OVERLAYFS && extract_section "overlayfs" >> "$FRAGMENT_DST"
$ADD_ZRAM && extract_section "zram" >> "$FRAGMENT_DST"
$ADD_KPM && extract_section "kpm" >> "$FRAGMENT_DST"
$ADD_ZEROMOUNT && extract_section "zeromount" >> "$FRAGMENT_DST"
$ADD_DROIDSPACES && extract_section "droidspaces" >> "$FRAGMENT_DST"

# Open Redirect is a permanent part of the Android 14 / 6.1 SUSFS build.
if $ADD_SUSFS; then
  sed -i '/^CONFIG_KSU_SUSFS_OPEN_REDIRECT=/d' "$FRAGMENT_DST"
  echo 'CONFIG_KSU_SUSFS_OPEN_REDIRECT=y' >> "$FRAGMENT_DST"

  if ! grep -Rqx 'config KSU_SUSFS_OPEN_REDIRECT' \
      "$COMMON_TREE" "${KSU_DIR:+$(dirname "$COMMON_TREE")/$KSU_DIR}" \
      --include='Kconfig*' 2>/dev/null; then
    echo "::error::SUSFS Open Redirect Kconfig symbol is missing"
    exit 1
  fi

  if [[ -n "${ARTIFACT_BASE:-}" ]]; then
    ARTIFACT_BASE="${ARTIFACT_BASE%-OpenRedirect-Test}"
    echo "ARTIFACT_BASE=$ARTIFACT_BASE" >> "${GITHUB_ENV:-/dev/null}"
  fi
  if [[ -n "${FILE_NAME:-}" ]]; then
    FILE_NAME="${FILE_NAME%-OpenRedirect-Test}"
    echo "FILE_NAME=$FILE_NAME" >> "${GITHUB_ENV:-/dev/null}"
  fi
fi

# dedup fragment: last-wins per CONFIG_ key
tac "$FRAGMENT_DST" | awk -F= '/^CONFIG_/{if(seen[$1]++)next} {print}' | tac > "${FRAGMENT_DST}.tmp"
mv "${FRAGMENT_DST}.tmp" "$FRAGMENT_DST"

if $ADD_SUSFS; then
  grep -qx 'CONFIG_KSU_SUSFS_OPEN_REDIRECT=y' "$FRAGMENT_DST" || {
    echo "::error::Open Redirect was not retained in the assembled fragment"
    exit 1
  }
fi

if $USE_KLEAF; then
  sed -i 's/^\(CONFIG_[A-Za-z0-9_]*\)=n$/# \1 is not set/' "$FRAGMENT_DST"
else
  grep '=n$' "$FRAGMENT_DST" >> "$DEFCONFIG" 2>/dev/null || true
  sed -i '/=n$/d' "$FRAGMENT_DST"
  cat "$FRAGMENT_DST" >> "$DEFCONFIG"
fi

if $ADD_ZRAM; then
  sed -i 's/CONFIG_ZRAM=m/CONFIG_ZRAM=y/g' "$DEFCONFIG" 2>/dev/null || true
  sed -i 's/CONFIG_ZSMALLOC=m/CONFIG_ZSMALLOC=y/g' "$DEFCONFIG" 2>/dev/null || true
fi

if ! $USE_KLEAF; then
  tac "$DEFCONFIG" | awk -F= '/^CONFIG_/{if(seen[$1]++)next} {print}' | tac > "${DEFCONFIG}.tmp"
  mv "${DEFCONFIG}.tmp" "$DEFCONFIG"
fi
