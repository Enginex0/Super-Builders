#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?kernel root}"
COMMON_TREE="${2:?common kernel tree}"
CONFIG_FILE="${3:?final kernel config}"
STUB="$COMMON_TREE/mm/kasan_kmi_compat.c"
MAKEFILE="$COMMON_TREE/mm/Makefile"
KASAN_HEADER="$COMMON_TREE/include/linux/kasan.h"
SLUB_HEADER="$COMMON_TREE/include/linux/slub_def.h"

[[ -f "$CONFIG_FILE" ]] || {
  echo "::error::Final kernel config is missing: $CONFIG_FILE"
  exit 1
}
[[ -f "$STUB" ]] || {
  echo "::error::KASAN KMI compatibility source is missing: $STUB"
  exit 1
}
grep -qxF 'obj-y += kasan_kmi_compat.o' "$MAKEFILE"
grep -qxF '#if !IS_ENABLED(CONFIG_KASAN_HW_TAGS)' "$STUB"
grep -qxF 'DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);' "$STUB"
grep -qxF 'EXPORT_SYMBOL(kasan_flag_enabled);' "$STUB"
grep -qF 'Samsung KMI: retain the HW-tags kasan_cache layout with KASAN off.' "$KASAN_HEADER"
grep -qF 'Samsung KMI: layout only; KASAN instrumentation remains disabled.' "$SLUB_HEADER"
[[ "$(grep -c $'^\tstruct kasan_cache kasan_info;$' "$SLUB_HEADER" || true)" -eq 1 ]] || {
  echo "::error::Expected exactly one inactive kasan_info layout field in struct kmem_cache"
  exit 1
}

grep -qx '# CONFIG_KASAN is not set' "$CONFIG_FILE" || {
  echo "::error::CONFIG_KASAN is not fully disabled in $CONFIG_FILE"
  grep -E '^CONFIG_KASAN|^# CONFIG_KASAN' "$CONFIG_FILE" || true
  exit 1
}
if grep -Eq '^CONFIG_KASAN(_[A-Z0-9_]+)?=y$' "$CONFIG_FILE"; then
  echo "::error::A KASAN implementation is still enabled"
  grep -E '^CONFIG_KASAN|^# CONFIG_KASAN' "$CONFIG_FILE" || true
  exit 1
fi
for symbol in KASAN_HW_TAGS KASAN_SW_TAGS KASAN_GENERIC; do
  if grep -qx "# CONFIG_${symbol} is not set" "$CONFIG_FILE"; then
    echo "Verified CONFIG_${symbol}=n"
  elif grep -q "^CONFIG_${symbol}=" "$CONFIG_FILE"; then
    echo "::error::CONFIG_${symbol} has an unexpected value"
    grep "^CONFIG_${symbol}=" "$CONFIG_FILE"
    exit 1
  else
    echo "Verified CONFIG_${symbol}=n (dependency-disabled; omitted by Kconfig)"
  fi
done

if command -v llvm-nm >/dev/null 2>&1; then
  NM_BIN="$(command -v llvm-nm)"
elif command -v nm >/dev/null 2>&1; then
  NM_BIN="$(command -v nm)"
else
  echo "::error::Neither llvm-nm nor nm is available"
  exit 1
fi

VMLINUX_CANDIDATES=(
  "$KERNEL_ROOT/out/android14-6.1/dist/vmlinux"
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64/vmlinux"
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64_dist/vmlinux"
)
while IFS= read -r candidate; do
  VMLINUX_CANDIDATES+=("$candidate")
done < <(find -L "$KERNEL_ROOT/bazel-bin/common" "$KERNEL_ROOT/out/android14-6.1" \
  -type f -name vmlinux -print 2>/dev/null || true)

VMLINUX=""
NM_OUTPUT=""
for candidate in "${VMLINUX_CANDIDATES[@]}"; do
  [[ -f "$candidate" ]] || continue
  if candidate_output="$("$NM_BIN" -n --defined-only "$candidate" 2>/dev/null | \
      awk '$NF == "kasan_flag_enabled" { print }')" && [[ -n "$candidate_output" ]]; then
    VMLINUX="$candidate"
    NM_OUTPUT="$candidate_output"
    break
  fi
done
[[ -n "$VMLINUX" ]] || {
  echo "::error::An unstripped vmlinux containing kasan_flag_enabled was not found"
  find -L "$KERNEL_ROOT/bazel-bin/common" "$KERNEL_ROOT/out/android14-6.1" \
    -type f -name vmlinux -print 2>/dev/null || true
  exit 1
}

mapfile -t NM_LINES <<< "$NM_OUTPUT"
[[ "${#NM_LINES[@]}" -eq 1 ]] || {
  echo "::error::Expected exactly one kasan_flag_enabled definition in vmlinux"
  printf '%s\n' "$NM_OUTPUT"
  exit 1
}
NM_TYPE="$(awk 'NR == 1 { print $(NF - 1) }' <<< "$NM_OUTPUT")"
[[ "$NM_TYPE" =~ ^[BDRGS]$ ]] || {
  echo "::error::kasan_flag_enabled is not a global data/read-mostly symbol (nm type: $NM_TYPE)"
  printf '%s\n' "$NM_OUTPUT"
  exit 1
}

SYMVERS_CANDIDATES=(
  "$KERNEL_ROOT/out/android14-6.1/dist/Module.symvers"
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64/Module.symvers"
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64_dist/Module.symvers"
)
while IFS= read -r candidate; do
  SYMVERS_CANDIDATES+=("$candidate")
done < <(find -L "$KERNEL_ROOT/bazel-bin/common" "$KERNEL_ROOT/out/android14-6.1" \
  -type f -name Module.symvers -print 2>/dev/null || true)

SYMVERS=""
SYMVERS_OUTPUT=""
for candidate in "${SYMVERS_CANDIDATES[@]}"; do
  [[ -f "$candidate" ]] || continue
  candidate_output="$(awk '{
    for (i = 1; i <= NF; i++)
      if ($i == "kasan_flag_enabled") {
        print
        break
      }
  }' "$candidate")"
  if [[ -n "$candidate_output" ]]; then
    SYMVERS="$candidate"
    SYMVERS_OUTPUT="$candidate_output"
    break
  fi
done
[[ -n "$SYMVERS" ]] || {
  echo "::error::Module.symvers does not export kasan_flag_enabled"
  exit 1
}
mapfile -t SYMVERS_LINES <<< "$SYMVERS_OUTPUT"
[[ "${#SYMVERS_LINES[@]}" -eq 1 ]] || {
  echo "::error::Expected exactly one kasan_flag_enabled entry in Module.symvers"
  printf '%s\n' "$SYMVERS_OUTPUT"
  exit 1
}
EXPORT_CLASS="$(awk '{
  for (i = 1; i <= NF; i++)
    if ($i ~ /^EXPORT_SYMBOL/)
      print $i
}' <<< "$SYMVERS_OUTPUT")"
[[ "$EXPORT_CLASS" == "EXPORT_SYMBOL" ]] || {
  echo "::error::kasan_flag_enabled export class changed: ${EXPORT_CLASS:-missing}"
  printf '%s\n' "$SYMVERS_OUTPUT"
  exit 1
}

ABI_MATCHES=()
# AOSP names Samsung-family lists "galaxy" and "exynos" on this branch; some
# downstream trees instead use "samsung". Check the base list and every
# Samsung-family spelling without weakening the actual symbol requirement.
for abi_file in \
  "$COMMON_TREE/android/abi_gki_aarch64" \
  "$COMMON_TREE/android/abi_gki_aarch64_samsung" \
  "$COMMON_TREE/android/abi_gki_aarch64_galaxy" \
  "$COMMON_TREE/android/abi_gki_aarch64_exynos"; do
  [[ -f "$abi_file" ]] || continue
  if grep -qw 'kasan_flag_enabled' "$abi_file"; then
    ABI_MATCHES+=("$abi_file")
  fi
done
[[ "${#ABI_MATCHES[@]}" -gt 0 ]] || {
  echo "::error::kasan_flag_enabled is absent from the Android/Samsung-family GKI symbol lists"
  exit 1
}

echo "Verified KASAN fully disabled with one inactive static-key stub and stock SLUB KMI layout"
echo "VMLINUX=$VMLINUX"
printf '%s\n' "$NM_OUTPUT"
echo "MODULE_SYMVERS=$SYMVERS"
printf '%s\n' "$SYMVERS_OUTPUT"
printf 'ABI_SYMBOL_LIST=%s\n' "${ABI_MATCHES[@]}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### KASAN-off KMI compatibility"
    echo
    echo "- Final config: \`CONFIG_KASAN=n\`; no KASAN implementation enabled"
    echo "- vmlinux: exactly one global \`kasan_flag_enabled\` definition (nm type \`$NM_TYPE\`)"
    echo "- Module.symvers: exactly one normal \`EXPORT_SYMBOL\` entry"
    echo "- SLUB: inactive \`kasan_info\` layout retained without instrumentation"
    echo "- ABI list: \`${ABI_MATCHES[0]#"$COMMON_TREE/"}\`"
  } >> "$GITHUB_STEP_SUMMARY"
fi
