#!/bin/bash
set -euo pipefail

COMMON="${1:?kernel common tree is required}"
REPORT="${2:-${RUNNER_TEMP:-/tmp}/susfs-procfs-audit.txt}"
EXPECTED_SUSFS_VERSION="${SUSFS_EXPECTED_VERSION:-v2.2.0}"

TASK_MMU="$COMMON/fs/proc/task_mmu.c"
PROC_BASE="$COMMON/fs/proc/base.c"
BOOTCONFIG="$COMMON/fs/proc/bootconfig.c"
NAMEI="$COMMON/fs/namei.c"
OPEN_C="$COMMON/fs/open.c"
SUSFS_C="$COMMON/fs/susfs.c"
SUSFS_H="$COMMON/include/linux/susfs.h"
SUSFS_DEF="$COMMON/include/linux/susfs_def.h"

passes=0
failures=0

mkdir -p "$(dirname "$REPORT")"
: > "$REPORT"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
pass() { passes=$((passes + 1)); log "[PASS] $*"; }
fail() { failures=$((failures + 1)); log "[FAIL] $*"; }

require_file() {
  if [[ -f "$1" ]]; then pass "present: ${1#$COMMON/}"; else fail "missing: ${1#$COMMON/}"; fi
}

require_pattern() {
  local file="$1" pattern="$2" description="$3"
  if grep -Eq "$pattern" "$file" 2>/dev/null; then pass "$description"; else fail "$description"; fi
}

require_literal_line() {
  local file="$1" literal="$2" description="$3"
  if grep -qxF "$literal" "$file" 2>/dev/null; then pass "$description"; else fail "$description"; fi
}

require_any_pattern() {
  local description="$1" pattern="$2"
  shift 2
  local file
  for file in "$@"; do
    if [[ -f "$file" ]] && grep -Eq "$pattern" "$file" 2>/dev/null; then
      pass "$description (${file#$COMMON/})"
      return 0
    fi
  done
  fail "$description"
}

require_count() {
  local file="$1" pattern="$2" minimum="$3" description="$4" count
  count=$(grep -Ec "$pattern" "$file" 2>/dev/null || true)
  if (( count >= minimum )); then
    pass "$description (count=$count)"
  else
    fail "$description (count=$count, expected >= $minimum)"
  fi
}

SUS_MAP_RE='AS_FLAGS_SUS_MAP|PRE_CHECK_SUS_MAP|SUSFS_IS_INODE_SUS_MAP|susfs_is_inode_sus_map'
OPEN_REDIRECT_FLAG_RE='AS_FLAGS_OPEN_REDIRECT|SUSFS_IS_INODE_OPEN_REDIRECT|susfs_is_inode_open_redirect'
OPEN_REDIRECT_LOOKUP_RE='susfs_get_redirected_path|susfs_get_redirected_pathname|susfs_get_open_redirect|susfs_lookup_open_redirect|susfs_get_redirected_inode|susfs_open_redirect_spoof_do_sys_openat|susfs_open_redirect_spoof_vfs_readlink|susfs_open_redirect_spoof_do_proc_readlink|susfs_open_redirect_spoof_seq_show|susfs_open_redirect_spoof_show_map_vma|susfs_open_redirect_spoof_vfs_statfs'

log "SUSFS ${EXPECTED_SUSFS_VERSION} Procfs/SUS_MAP/Open Redirect source audit"
log "common tree: $COMMON"
log ""

for file in "$TASK_MMU" "$PROC_BASE" "$BOOTCONFIG" "$NAMEI" "$SUSFS_C" "$SUSFS_H" "$SUSFS_DEF"; do
  require_file "$file"
done

if (( failures > 0 )); then
  log ""
  log "Audit stopped because required files are missing."
  exit 1
fi

require_literal_line "$SUSFS_H" "#define SUSFS_VERSION \"${EXPECTED_SUSFS_VERSION}\"" \
  "SUSFS reports ${EXPECTED_SUSFS_VERSION}"
require_pattern "$SUSFS_DEF" 'AS_FLAGS_SUS_MAP|SUSFS_IS_INODE_SUS_MAP' \
  "SUS_MAP inode test is defined"
require_pattern "$SUSFS_C" 'susfs_add_sus_map' \
  "SUS_MAP registration path exists"
require_pattern "$SUSFS_C" 'AS_FLAGS_SUS_MAP|SUSFS_SET_INODE_SUS_MAP|susfs_set_inode_sus_map' \
  "SUS_MAP inode/address-space flag is assigned"

require_pattern "$BOOTCONFIG" 'static_key_enabled\(&susfs_is_fake_cmdline_or_bootconfig_buffer_set\)' \
  "bootconfig runtime gate reads the static key directly"
require_pattern "$BOOTCONFIG" 'susfs_spoof_cmdline_or_bootconfig\(m\);' \
  "bootconfig proc reader calls the SUSFS spoof helper"
if grep -Eq 'static_branch_(likely|unlikely)\([[:space:]]*&susfs_is_fake_cmdline_or_bootconfig_buffer_set[[:space:]]*\)' "$BOOTCONFIG"; then
  fail "legacy jump-label bootconfig gate remains"
else
  pass "legacy jump-label bootconfig gate is absent"
fi

# Pinned upstream revisions may use direct AS_FLAGS tests or the SUSFS_IS_INODE_SUS_MAP
# wrapper. Both represent the same reader integration and must be accepted.
require_count "$TASK_MMU" "$SUS_MAP_RE" 4 \
  "task_mmu.c contains SUS_MAP hooks for maps/smaps/rollup/pagemap"
require_pattern "$TASK_MMU" 'show_map_vma' "maps output path is present"
require_pattern "$TASK_MMU" 'show_smap|smap_gather_stats|smaps' "smaps statistics path is present"
require_pattern "$TASK_MMU" 'pagemap_read' "pagemap filtering path is present"
require_pattern "$TASK_MMU" 'walk_page_range' "pagemap walk path is auditable"

if grep -Rq 'susfs_is_current_proc_umounted_app' "$TASK_MMU" "$PROC_BASE" "$SUSFS_C" "$SUSFS_H"; then
  pass "current unmounted-app process guard is integrated"
elif grep -Rq 'susfs_is_current_proc_umounted' "$TASK_MMU" "$PROC_BASE" "$SUSFS_C" "$SUSFS_H" && \
     grep -RqE 'current_uid\(\)\.val[[:space:]]*>?=[[:space:]]*10000|uid[^\n]*10000' "$TASK_MMU" "$PROC_BASE" "$SUSFS_C" "$SUSFS_H"; then
  pass "legacy helper is paired with an explicit app UID guard"
else
  fail "no valid unmounted-app process guard found"
fi

require_count "$PROC_BASE" "$SUS_MAP_RE" 1 \
  "base.c includes SUS_MAP filtering hooks"
require_pattern "$PROC_BASE" '__access_remote_vm|mem_rw' "remote-memory access path is covered"
require_pattern "$PROC_BASE" 'map_files' "map_files directory path is covered"

registration_count=$(grep -Ec 'AS_FLAGS_SUS_MAP|SUSFS_SET_INODE_SUS_MAP|susfs_set_inode_sus_map' "$SUSFS_C" || true)
reader_count=$(( $(grep -Ec "$SUS_MAP_RE" "$TASK_MMU" || true) + \
                 $(grep -Ec "$SUS_MAP_RE" "$PROC_BASE" || true) ))
if (( registration_count > 0 && reader_count >= 6 )); then
  pass "registration and procfs reader integration are both present"
else
  fail "partial SUS_MAP backport detected (registration=$registration_count readers=$reader_count)"
fi

if grep -Eq "$SUS_MAP_RE" "$TASK_MMU" && \
   grep -Eq 'continue;|goto[[:space:]]+show_pad|return[[:space:]]+0|seq_setwidth|memset\(&mss' "$TASK_MMU"; then
  pass "task_mmu.c contains SUS_MAP hide/anonymize control flow"
else
  fail "task_mmu.c lacks SUS_MAP hide/anonymize control flow"
fi

# Open Redirect changed shape across pinned SUSFS revisions. Some trees put the open
# hook in namei.c, others in open.c; helper wrappers may hide the raw AS flag.
require_pattern "$SUSFS_DEF" 'AS_FLAGS_OPEN_REDIRECT|SUSFS_IS_INODE_OPEN_REDIRECT' \
  "Open Redirect inode test is defined"
require_pattern "$SUSFS_C" 'susfs_add_open_redirect|add_open_redirect' \
  "Open Redirect registration path exists"
require_any_pattern "Open Redirect lookup path exists" "$OPEN_REDIRECT_LOOKUP_RE" \
  "$SUSFS_C" "$SUSFS_H" "$SUSFS_DEF"
require_any_pattern "open path is guarded by Open Redirect Kconfig" 'CONFIG_KSU_SUSFS_OPEN_REDIRECT' \
  "$NAMEI" "$OPEN_C"
require_any_pattern "open path checks the Open Redirect inode state" "$OPEN_REDIRECT_FLAG_RE" \
  "$NAMEI" "$OPEN_C"
require_any_pattern "open path resolves or substitutes the redirected target" \
  "$OPEN_REDIRECT_LOOKUP_RE|redirected_path|redirect_path|fake_pathname" \
  "$NAMEI" "$OPEN_C"

log ""
log "Summary: PASS=$passes FAIL=$failures"

if (( failures > 0 )); then
  log "SUSFS audit failed. Refusing to build a kernel with partial Procfs/SUS_MAP/Open Redirect integration."
  exit 1
fi

log "SUSFS Procfs/SUS_MAP/Open Redirect audit passed."
