#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree}"
KSU_TREE="${2:?KernelSU tree}"

# ReSukiSU 35127/UAPI4 already owns the scoped [ksu_driver_su] UAPI. Port only
# the proven 35119 session-selection/success semantics plus UAPI-neutral fixes;
# keep the stable SUSFS v2.3.0 base and do not apply the old UAPI2 userspace port.
if [[ "${RESUKISU_VERSION_CODE:-}" == "35127" ]]; then
  SESSION_HELPER="$(dirname "$0")/apply-resukisu-35127-susfs-postexec.sh"
  [[ -s "$SESSION_HELPER" ]] || {
    echo "::error::ReSukiSU 35127 session helper is missing: $SESSION_HELPER"
    exit 1
  }
  chmod +x "$SESSION_HELPER"
  "$SESSION_HELPER" "$COMMON_TREE" "$KSU_TREE"

  # Independent gate. The bootlooping 34396512459 build used a global SUSFS
  # post-exec bridge. Under CONFIG_KSU_SUSFS, CONFIG_KSU_MANUAL_HOOK is not the
  # selected hook method, so the MANUAL-only TIF check did not scope that call.
  # Require the 35119-proven local bool instead.
  python3 - "$COMMON_TREE/fs/exec.c" "$KSU_TREE" <<'PY'
from pathlib import Path
import re
import sys

exec_path = Path(sys.argv[1])
ksu = Path(sys.argv[2])
source = exec_path.read_text(encoding="utf-8")
su_path = ksu / "kernel/feature/sucompat.c"
suh_path = ksu / "kernel/feature/sucompat.h"
app_path = ksu / "kernel/policy/app_profile.c"
allow_path = ksu / "kernel/policy/allowlist.c"
setuid_path = ksu / "kernel/hook/setuid_hook.c"
ksud_path = ksu / "userspace/ksud/src/android/ksucalls.rs"

su = su_path.read_text(encoding="utf-8")
suh = suh_path.read_text(encoding="utf-8")
app = app_path.read_text(encoding="utf-8")
allow = allow_path.read_text(encoding="utf-8")
setuid = setuid_path.read_text(encoding="utf-8")
ksud = ksud_path.read_text(encoding="utf-8")

# The first 35127 success-gate build exposed a Python re.sub replacement-string
# quoting bug: the raw replacement emitted literal backslashes before the C
# string quotes (pr_warn(\"...\")), breaking fs/exec.c parsing. Normalize only
# that exact generated line, then fail closed on any remaining escaped C quote.
broken_warn = r'pr_warn(\"ReSukiSU: su-session FD installation failed: %d\n\", su_fd);'
fixed_warn = r'pr_warn("ReSukiSU: su-session FD installation failed: %d\n", su_fd);'
broken_count = source.count(broken_warn)
if broken_count > 1:
    raise SystemExit(f"ambiguous malformed 35127 pr_warn emission: {broken_count} matches")
if broken_count == 1:
    source = source.replace(broken_warn, fixed_warn, 1)
    exec_path.write_text(source, encoding="utf-8")

if source.count(fixed_warn) != 1:
    raise SystemExit("missing unique valid 35127 su-session warning after source normalization")
if r'pr_warn(\"' in source:
    raise SystemExit("fs/exec.c still contains malformed escaped C quote in pr_warn")
if r'pr_warn(\"' in su:
    raise SystemExit("ReSukiSU sucompat.c contains malformed escaped C quote in pr_warn")

execs = list(re.finditer(r"retval\s*=\s*bprm_execve\(bprm, fd, filename, flags\);", source))
if len(execs) != 1:
    raise SystemExit(f"expected exactly one bprm_execve assignment, found {len(execs)}")
if source.count("bool is_su_session = false;") != 1:
    raise SystemExit("missing unique local is_su_session state")
if source.count("is_su_session = ksu_handle_execveat_su_session") != 1:
    raise SystemExit("missing unique scoped pre-exec session decision")
if source.count("int su_fd = ksu_install_su_fd();") != 1:
    raise SystemExit("missing unique direct UAPI4 scoped-FD install")
if source.count("is_su_session && retval >= 0") != 1:
    raise SystemExit("missing exact is_su_session && retval >= 0 guard")
if "ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval)" in source:
    raise SystemExit("bootloop-prone unscoped post-exec bridge is still present")

success_pos = source.find("is_su_session && retval >= 0")
install_pos = source.find("int su_fd = ksu_install_su_fd();")
if not (execs[0].end() < success_pos < install_pos):
    raise SystemExit("scoped-FD ordering is not bprm_execve -> success/session guard -> install")

required_su = (
    "bool ksu_handle_execveat_su_session(",
    "*is_su_session = true;",
    "ret = escape_with_root_profile();",
    "clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);",
    "retval && *retval >= 0",
)
for marker in required_su:
    if marker not in su:
        raise SystemExit(f"ReSukiSU session contract missing: {marker}")
if "bool ksu_handle_execveat_su_session(" not in suh:
    raise SystemExit("ReSukiSU session API declaration missing")
if "ret = set_cred_ucounts(cred);" not in app:
    raise SystemExit("set_cred_ucounts failure is not propagated")
if 'strcmp(profile->key, "webview_zygote") != 0' not in allow:
    raise SystemExit("WebView UID 1053 profile identity is not constrained")
if "uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID" not in allow:
    raise SystemExit("WebView UID 1053 profile is not preserved during prune")
if "if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID))" not in setuid:
    raise SystemExit("zygote_next does not consult the WebView UID 1053 profile")
if 'SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]"' not in ksud:
    raise SystemExit("35127 UAPI4 ksud lacks native scoped driver support")

print("Verified 35127 native UAPI4 session gate: real ksud session + retval >= 0 + scoped FD")
print("Verified generated C quoting: no malformed pr_warn escaped quotes remain")
print("Verified UAPI-neutral 35119 carryovers: ucounts + WebView UID 1053 consistency")
PY
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35137" || "${RESUKISU_VERSION_CODE:-}" == "35139" || "${RESUKISU_VERSION_CODE:-}" == "35140" || "${RESUKISU_VERSION_CODE:-}" == "35146" || "${RESUKISU_VERSION_CODE:-}" == "35148" || "${RESUKISU_VERSION_CODE:-}" == "35153" || "${RESUKISU_VERSION_CODE:-}" == "35157" || "${RESUKISU_VERSION_CODE:-}" == "35158" ]]; then
  PORT="$(dirname "$0")/su-session-35137"

  # 35139/35140 keep the validated 35137 kernel/UAPI source anchors unchanged.
  # 35146 carries upstream's non-root capability inheritance fix in app_profile.c,
  # outside the adapter's exact set_cred_ucounts() replacement. 35148 adds only
  # manager/CI changes; 35153 adds CI/manager plus userspace dependency updates.
  # 35157 additionally carries kernel/compat/lsm/ksud/manager updates, including
  # the manager RCU copy_to_user fix; 35158 changes only manager launcher-icon
  # component names. Neither changes the adapter-transformed kernel/UAPI anchors.
  # Rebind the complete adapter identity while keeping the transformation itself
  # source-identical, then explicitly verify that capability inheritance survives.
  if [[ "${RESUKISU_VERSION_CODE:-}" == "35139" || "${RESUKISU_VERSION_CODE:-}" == "35140" || "${RESUKISU_VERSION_CODE:-}" == "35146" || "${RESUKISU_VERSION_CODE:-}" == "35148" || "${RESUKISU_VERSION_CODE:-}" == "35153" || "${RESUKISU_VERSION_CODE:-}" == "35157" || "${RESUKISU_VERSION_CODE:-}" == "35158" ]]; then
    ADAPTER="$PORT/apply.py"
    OLD_PIN='3380d41f2043644d0ef6c0e0e91be6b229024d00'
    TARGET_VERSION="${RESUKISU_VERSION_CODE}"
    case "$TARGET_VERSION" in
      35139) NEW_PIN='601f6d2af4801492339f74f622e1a4ae3a445250' ;;
      35140) NEW_PIN='c04159fcbdfdb71b0c3765ecaaf23c4e0a498c93' ;;
      35146) NEW_PIN='833edb0e8e4bc11ac8e976edd7de42da6bdc5bd2' ;;
      35148) NEW_PIN='b22a46e6ee79931b1e3b39fc562d56176936ab77' ;;
      35153) NEW_PIN='6d674e50a022a85076dcfe4498af9a8bfead2cf9' ;;
      35157) NEW_PIN='3d1185d878a856ea6435799b436b3d3ec510da76' ;;
      35158) NEW_PIN='6d18926ae6eeb571a04c1ce7552c324d606fa9d8' ;;
      *) echo "::error::Unsupported ReSukiSU adapter target: $TARGET_VERSION"; exit 1 ;;
    esac

    python3 - "$ADAPTER" "$OLD_PIN" "$NEW_PIN" "$TARGET_VERSION" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old_pin = sys.argv[2]
new_pin = sys.argv[3]
target_version = sys.argv[4]
text = path.read_text(encoding="utf-8")

if old_pin not in text and new_pin not in text:
    raise SystemExit(f"unexpected ReSukiSU pin in {path}")

# Fresh CI workspaces contain the validated 35137 adapter. Rebind its exact
# commit and all identity assertions/receipt labels to the selected target.
# Kernel/UAPI transformation code itself remains unchanged.
text = text.replace(old_pin, new_pin)
text = text.replace("35137", target_version)
path.write_text(text, encoding="utf-8", newline="\n")

updated = path.read_text(encoding="utf-8")
required = (
    f'RESUKISU_PIN = "{new_pin}"',
    f'"resukisu_version":{target_version}',
    f'if compiled_version != {target_version}:',
    f'expected={target_version}',
)
for marker in required:
    if marker not in updated:
        raise SystemExit(f"{target_version} adapter identity marker missing: {marker}")
if old_pin in updated or "35137" in updated:
    raise SystemExit(f"stale 35137 adapter identity survived {target_version} rebinding")
print(f"Rebound complete ReSukiSU session adapter identity: 35137 -> {target_version}")
PY
  fi

  python3 "$PORT/apply.py" --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"

  if [[ "${RESUKISU_VERSION_CODE:-}" == "35146" || "${RESUKISU_VERSION_CODE:-}" == "35148" || "${RESUKISU_VERSION_CODE:-}" == "35153" || "${RESUKISU_VERSION_CODE:-}" == "35157" || "${RESUKISU_VERSION_CODE:-}" == "35158" ]]; then
    APP_PROFILE="$KSU_TREE/kernel/policy/app_profile.c"
    for marker in \
      'memcpy(&cred->cap_inheritable, &profile->capabilities.effective, sizeof(cred->cap_inheritable));' \
      'memcpy(&cred->cap_ambient, &profile->capabilities.effective, sizeof(cred->cap_ambient));'; do
      grep -qF "$marker" "$APP_PROFILE" || {
        echo "::error::ReSukiSU ${RESUKISU_VERSION_CODE} non-root capability inheritance was lost: $marker"
        exit 1
      }
    done
    echo "Verified ReSukiSU ${RESUKISU_VERSION_CODE} non-root capability inheritance survives the SUSFS UAPI4 adapter"
  fi
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35184" ]]; then
  python3 "$(dirname "$0")/su-session-35184/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35187" ]]; then
  python3 "$(dirname "$0")/su-session-35187/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35189" ]]; then
  python3 "$(dirname "$0")/su-session-35189/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35202" ]]; then
  python3 "$(dirname "$0")/su-session-35193/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35203" ]]; then
  python3 "$(dirname "$0")/su-session-35203/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35204" ]]; then
  python3 "$(dirname "$0")/su-session-35204/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35205" ]]; then
  python3 "$(dirname "$0")/su-session-35205/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35212" ]]; then
  python3 "$(dirname "$0")/su-session-35212/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35215" ]]; then
  python3 "$(dirname "$0")/su-session-35215/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

if [[ "${RESUKISU_VERSION_CODE:-}" == "35220" ]]; then
  python3 "$(dirname "$0")/su-session-35220/apply.py" \
    --common "$COMMON_TREE" --ksu "$KSU_TREE" \
    --susfs-commit "${SUSFS_PINNED_COMMIT:?}"
fi

BOOTCONFIG_FIX="$(dirname "$0")/apply-susfs-bootconfig-static-key-fix.sh"
[[ -s "$BOOTCONFIG_FIX" ]] || {
  echo "::error::SUSFS bootconfig static-key fix helper is missing: $BOOTCONFIG_FIX"
  exit 1
}
# Read-only verifier: the runtime fix must already have been applied before
# UIDGate records its source receipt. Do not mutate bootconfig here.

require_source() {
  local relative="$1"
  local needle="$2"
  local path="$COMMON_TREE/$relative"
  [[ -f "$path" ]] || {
    echo "::error::ZeroMount/SUSFS source is missing: $relative"
    exit 1
  }
  grep -qF "$needle" "$path" || {
    echo "::error::ZeroMount/SUSFS hook is missing from $relative: $needle"
    exit 1
  }
}

require_source fs/Kconfig 'config ZEROMOUNT'
require_source fs/Makefile 'obj-$(CONFIG_ZEROMOUNT)'
require_source fs/zeromount.c 'zeromount_ioctl_add_rule'
require_source fs/zeromount.c 'zeromount_inject_dents64'
require_source fs/zeromount.c 'zeromount_is_uid_blocked'
require_source fs/zeromount.c 'zeromount_spoof_statfs'
require_source fs/zeromount.c 'kern_path(statfs_root, LOOKUP_FOLLOW, &root_path)'
require_source fs/zeromount.c '*buf = root_stats'
require_source fs/zeromount.c 'zeromount_spoof_xattr'
require_source include/linux/zeromount.h 'ZEROMOUNT_IOC_GET_STATUS'
require_source fs/namei.c 'zeromount_getname_hook'
require_source fs/readdir.c 'zeromount_inject_dents64'
require_source fs/d_path.c 'zeromount_get_static_vpath'
require_source fs/proc/base.c 'zeromount_get_static_vpath'
require_source fs/stat.c 'zeromount_stat_hook'
require_source fs/statfs.c 'zeromount_spoof_statfs'
require_source fs/xattr.c 'zeromount_spoof_xattr'
require_source fs/susfs.c 'susfs_add_sus_kstat_redirect'
require_source fs/susfs.c 'susfs_add_sus_map'
require_source fs/proc/bootconfig.c 'static_key_enabled(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)'
require_source fs/proc/bootconfig.c 'susfs_spoof_cmdline_or_bootconfig(m);'

[[ -d "$KSU_TREE" ]] || {
  echo "::error::KernelSU tree not found: $KSU_TREE"
  exit 1
}
for needle in \
  'ksu_susfs_ack_deprecated_external_dir' \
  'case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:' \
  'case CMD_SUSFS_SET_SDCARD_ROOT_PATH:'; do
  grep -RqF "$needle" "$KSU_TREE" || {
    echo "::error::ZeroMount/SUSFS external-directory compatibility is missing: $needle"
    exit 1
  }
done

if grep -Eq 'static_branch_(likely|unlikely)\([[:space:]]*&susfs_is_fake_cmdline_or_bootconfig_buffer_set[[:space:]]*\)' "$COMMON_TREE/fs/proc/bootconfig.c"; then
  echo "::error::Legacy jump-label SUSFS bootconfig gate survived the runtime fix"
  exit 1
fi

# The legacy ZeroMount maps hook overlaps the pinned SUSFS show_map_vma() and caused
# a real apexd Oops on e3q. SUSFS SUS_MAP supplies map hiding, so the unsafe
# duplicate task_mmu hook must remain absent.
if grep -qF 'zeromount_spoof_mmap_metadata' "$COMMON_TREE/fs/proc/task_mmu.c"; then
  echo "::error::Unsafe duplicate ZeroMount task_mmu hook was reintroduced"
  exit 1
fi

echo "Verified ZeroMount VFS hooks, SUSFS bootconfig static-key runtime gate, full statfs spoofing, SUSFS ${SUSFS_EXPECTED_VERSION:-pinned} bridge, and external-directory compatibility"
