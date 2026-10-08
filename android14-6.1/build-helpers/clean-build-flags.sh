#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?}"
KERNEL_VER="${2:?}"
SUFFIX="${3:-SukiSU}"
KMI_MODE="${4:-runtime-compat}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

case "$KMI_MODE" in
  runtime-compat|symtypes|strict) ;;
  *) echo "Unsupported KMI mode: $KMI_MODE" >&2; exit 1 ;;
esac

cd "$KERNEL_ROOT"

if [[ "$KERNEL_VER" == "5."* ]] || [[ "$KERNEL_VER" == "6.1" ]]; then
  perl -i -0777 -pe "s/(.*)echo \"\$res\"/\$1echo \"\$res-${SUFFIX}\"/s" ./common/scripts/setlocalversion
else
  perl -i -0777 -pe "s/(.*)echo \"\${KERNELVERSION}\${file_localversion}\${config_localversion}\${LOCALVERSION}\${scm_version}\"/\$1echo \"\${KERNELVERSION}\${file_localversion}\${config_localversion}\${LOCALVERSION}-${SUFFIX}\${scm_version}\"/s" ./common/scripts/setlocalversion
fi

if [ -f "build/build.sh" ]; then
  sed -i 's/-dirty//' ./common/scripts/setlocalversion
else
  sed -i "/stable_scmversion_cmd/s/-maybe-dirty//g" ./build/kernel/kleaf/impl/stamp.bzl
  sed -i 's/-dirty//' ./common/scripts/setlocalversion
  # Samsung vendor_dlkm modules import exported symbols outside Google's
  # protected-export allowlist (including rfkill_*, usbnet_* and vendor XHCI
  # tracepoints). Remove only that export filter in every mode. Strict mode
  # independently retains the Kleaf symbol-list/violation checks, build-time
  # ABI checks and the module loader's CRC rejection path.
  rm -rf ./common/android/abi_gki_protected_exports_*
  perl -pi -e 's/^\s*"protected_exports_list"\s*:\s*"android\/abi_gki_protected_exports_aarch64",\s*$//;' ./common/BUILD.bazel
  echo "Removed the protected-exports filter; KMI mode ${KMI_MODE} retains its independent symbol and CRC policy."
fi

# Keep SUSFS logging compiled in, default-off, serialized and safely toggleable.
SUSFS_SOURCE="./common/fs/susfs.c"
SUSFS_FRAGMENT="./common/arch/arm64/configs/sukisu_gki.fragment"

# The diagnostic ReSukiSU-minimal profile intentionally writes exactly these
# three non-empty lines. Samsung's e3q source overlay can still leave UH/KDP/RKP
# enabled in the base config; ReSukiSU rejects that combination at compile time.
# Add only the three KernelSU-incompatible Samsung disables to the minimal
# fragment so the CRC attribution remains minimal and the full profiles remain
# untouched.
if [ -f "$SUSFS_FRAGMENT" ]; then
  mapfile -t MINIMAL_KMI_LINES < <(grep -Ev '^[[:space:]]*$' "$SUSFS_FRAGMENT")
  if [[ "${#MINIMAL_KMI_LINES[@]}" -eq 3 ]] &&
     grep -qx 'CONFIG_KSU=y' "$SUSFS_FRAGMENT" &&
     grep -qx 'CONFIG_KSU_MULTI_MANAGER_SUPPORT=y' "$SUSFS_FRAGMENT" &&
     grep -qx '# CONFIG_LOCALVERSION_AUTO is not set' "$SUSFS_FRAGMENT"; then
    CONFIG_TOOL="./common/scripts/config"
    [[ -x "$CONFIG_TOOL" ]] || {
      echo "::error::Kernel config editor is unavailable: $CONFIG_TOOL"
      exit 1
    }
    for symbol in UH KDP RKP; do
      "$CONFIG_TOOL" --file "$SUSFS_FRAGMENT" --disable "$symbol"
    done
    for symbol in UH KDP RKP; do
      grep -qx "# CONFIG_${symbol} is not set" "$SUSFS_FRAGMENT" || {
        echo "::error::CONFIG_${symbol} was not disabled in minimal ReSukiSU KMI config"
        exit 1
      }
    done
    echo "Minimal ReSukiSU KMI config: Samsung UH/KDP/RKP disabled."
  fi
fi

if [ -f "$SUSFS_FRAGMENT" ] && [ -f "$SUSFS_SOURCE" ]; then
  grep -qx 'CONFIG_KSU_SUSFS_ENABLE_LOG=y' "$SUSFS_FRAGMENT" || {
    echo "::error::CONFIG_KSU_SUSFS_ENABLE_LOG must remain enabled"
    exit 1
  }
fi

if [ -f "$SUSFS_SOURCE" ]; then
  grep -qx 'DEFINE_STATIC_KEY_FALSE(susfs_is_log_enabled);' "$SUSFS_SOURCE" || {
    echo "::error::SUSFS logging static key must default to FALSE"
    exit 1
  }
  grep -qF 'if (!static_key_enabled(&susfs_is_log_enabled))' "$SUSFS_SOURCE" || {
    echo "::error::SUSFS logging enable transition is not guarded"
    exit 1
  }
  grep -qF 'if (static_key_enabled(&susfs_is_log_enabled))' "$SUSFS_SOURCE" || {
    echo "::error::SUSFS logging disable transition is not guarded"
    exit 1
  }
  grep -qF 'mutex_lock(&susfs_mutex_enable_log);' "$SUSFS_SOURCE" || {
    echo "::error::SUSFS logging transitions are not serialized"
    exit 1
  }
  grep -qF 'mutex_unlock(&susfs_mutex_enable_log);' "$SUSFS_SOURCE" || {
    echo "::error::SUSFS logging transition mutex is not released"
    exit 1
  }
fi

if [[ "$KERNEL_VER" == "6.1" || "$KERNEL_VER" == "6.6" || "$KERNEL_VER" == "6.12" ]]; then
  MODULE_VERSION_FILE="$KERNEL_ROOT/common/kernel/module/version.c"
else
  MODULE_VERSION_FILE="$KERNEL_ROOT/common/kernel/module.c"
fi
MODULE_MAIN_FILE="$KERNEL_ROOT/common/kernel/module/main.c"

# Runtime recovery accepts CRC mismatches only in the proven bootsafe build.
# Symtypes and strict modes retain the upstream return 0 rejection path. The
# reusable workflow may package only the exact full-strict e3q gate after all
# 2469 target ZZHL Samsung DLKM CRCs have converged; other diagnostics stay unflashable.
"$PYTHON_BIN" - "$MODULE_VERSION_FILE" "$KMI_MODE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
mode = sys.argv[2]
if not path.is_file():
    raise SystemExit(f"module version source not found: {path}")

text = path.read_text()
pattern = re.compile(r"(bad_version:.*?\breturn\s+)[01](\s*;)", re.S)
target = "1" if mode == "runtime-compat" else "0"
text, count = pattern.subn(rf"\g<1>{target}\2", text, count=1)
if count != 1:
    raise SystemExit(f"unexpected bad_version replacement count: {count}")

match = re.search(r"bad_version:(.*?)(?:\n[}\t ]*\n|\Z)", text, re.S)
if not match:
    raise SystemExit("bad_version block not found")
block = match.group(1)
if not re.search(rf"\breturn\s+{target}\s*;", block):
    raise SystemExit(f"bad_version does not use the expected return {target}")
other = "0" if target == "1" else "1"
if re.search(rf"\breturn\s+{other}\s*;", block):
    raise SystemExit(f"bad_version still contains conflicting return {other}")
if "disagrees about version of symbol" not in block:
    raise SystemExit("CRC mismatch warning was removed")

path.write_text(text)
PY

# A real module blacklist match must still fail with -EPERM.
if [ -f "$MODULE_MAIN_FILE" ]; then
  sed -i -E 's|^([[:space:]]*)//[[:space:]]*err = -EPERM;|\1err = -EPERM;|' "$MODULE_MAIN_FILE"
  BLACKLIST_BLOCK=$(sed -n '/if (blacklisted(info->name))/,/goto free_copy;/p' "$MODULE_MAIN_FILE")
  printf '%s\n' "$BLACKLIST_BLOCK"
  grep -Eq '^[[:space:]]*err = -EPERM;' <<< "$BLACKLIST_BLOCK" || {
    echo "::error::Blacklisted modules must return -EPERM"
    exit 1
  }
  if grep -Eq '^[[:space:]]*//[[:space:]]*err = -EPERM;' <<< "$BLACKLIST_BLOCK"; then
    echo "::error::Commented blacklist errno remains"
    exit 1
  fi
fi

# Never hide patch failures behind an earlier `|| true`.
mapfile -t PATCH_REJECTS < <(find "$KERNEL_ROOT" -type f -name '*.rej' -print)
if [ "${#PATCH_REJECTS[@]}" -gt 0 ]; then
  printf '::error::Patch reject found: %s\n' "${PATCH_REJECTS[@]}"
  exit 1
fi

AUDIT_ROOT="${GITHUB_WORKSPACE:-$KERNEL_ROOT}"
mkdir -p "$AUDIT_ROOT"
AUDIT_FILE="$AUDIT_ROOT/kmi-module-loader-audit.txt"

{
  echo "============================================================"
  echo "KMI MODULE LOADER RUNTIME-COMPAT AUDIT"
  echo "============================================================"
  echo "UTC: $(date -u '+%Y-%m-%d %H:%M:%S')"
  echo "Kernel root: $KERNEL_ROOT"
  echo "Kernel version: $KERNEL_VER"
  echo "KMI mode: $KMI_MODE"
  echo "Workflow ref: ${GITHUB_REF:-unknown}"
  echo "Workflow SHA: ${GITHUB_SHA:-unknown}"
  echo "Module version file: $MODULE_VERSION_FILE"
  echo

  echo "============================================================"
  echo "1. RELEVANT SOURCE MATCHES"
  echo "============================================================"
  grep -RInE \
    'check_version|disagrees about version|try_to_force_load|IGNORE_MODVERSIONS|same_magic|modversions' \
    "$KERNEL_ROOT/common/kernel/module" 2>/dev/null || true
  echo

  echo "============================================================"
  echo "2. BAD_VERSION CONTROL FLOW"
  echo "============================================================"
  awk '
    /bad_version:/ { active=1; remaining=18 }
    active { print NR ":" $0; remaining-- }
    active && remaining <= 0 { active=0 }
  ' "$MODULE_VERSION_FILE"
  echo

  echo "============================================================"
  echo "3. MODULE-LOADER DIFF"
  echo "============================================================"
  git -C "$KERNEL_ROOT/common" diff -- \
    kernel/module/version.c \
    kernel/module/main.c \
    kernel/module/internal.h \
    kernel/module.c 2>/dev/null || true
  echo

  echo "============================================================"
  echo "4. AUTOMATIC VERDICT"
  echo "============================================================"
  EXPECTED_RETURN=0
  [[ "$KMI_MODE" == "runtime-compat" ]] && EXPECTED_RETURN=1
  if awk -v expected="$EXPECTED_RETURN" '
      /bad_version:/ { active=1; remaining=18; next }
      active && /return[[:space:]]+[01][[:space:]]*;/ {
        line=$0
        if (line ~ ("return[[:space:]]+" expected "[[:space:]]*;")) match_expected=1
        else match_other=1
      }
      active { remaining-- }
      active && remaining <= 0 { active=0 }
      END { exit(match_expected && !match_other ? 0 : 1) }
    ' "$MODULE_VERSION_FILE"; then
    if [[ "$KMI_MODE" == "runtime-compat" ]]; then
      echo "[OK] CRC mismatches are logged and accepted for Samsung KMI compatibility."
    else
      echo "[OK] CRC mismatches are logged and strictly rejected."
    fi
  else
    echo "[ERROR] bad_version is not in runtime-compat mode."
    exit 1
  fi

  if grep -qF 'disagrees about version of symbol' "$MODULE_VERSION_FILE"; then
    echo "[OK] CRC mismatch diagnostics remain enabled."
  else
    echo "[ERROR] CRC mismatch diagnostics are missing."
    exit 1
  fi

  if [ -f "$MODULE_MAIN_FILE" ] && sed -n '/if (blacklisted(info->name))/,/goto free_copy;/p' "$MODULE_MAIN_FILE" | grep -Eq '^[[:space:]]*err = -EPERM;'; then
    echo "[OK] Blacklisted modules still return -EPERM."
  else
    echo "[ERROR] Module blacklist errno propagation is invalid."
    exit 1
  fi

  if grep -q 'CONFIG_MODULE_FORCE_LOAD=y' "$SUSFS_FRAGMENT" 2>/dev/null; then
    echo "[WARN] CONFIG_MODULE_FORCE_LOAD is requested in the fragment."
  else
    echo "[OK] CONFIG_MODULE_FORCE_LOAD is not requested in the fragment."
  fi

  echo "============================================================"
  echo "END"
  echo "============================================================"
} > "$AUDIT_FILE" 2>&1

cat "$AUDIT_FILE"
echo "KMI runtime-compat audit saved outside AnyKernel3: $AUDIT_FILE"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## KMI module-loader runtime compatibility"
    echo
    if [[ "$KMI_MODE" == "runtime-compat" ]]; then
      echo "- CRC mismatches remain visible in dmesg and are accepted only in the proven recovery build."
    else
      echo "- CRC mismatches remain visible and are strictly rejected."
    fi
    echo "- ✅ Real module blacklist matches still propagate \`-EPERM\`."
    echo "- ✅ No patch reject files were found before compilation."
  } >> "$GITHUB_STEP_SUMMARY"
fi

cd common
git config --global user.name "github-actions[bot]"
git config --global user.email "github-actions[bot]@users.noreply.github.com"
git add .
git commit -m "${SUFFIX}: Clean Build" || true
