#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common tree}"
FRAGMENT="${2:?final defconfig fragment}"
DEFCONFIG="${3:?base defconfig}"
MODE="${4:-kleaf}"
CONFIG_TOOL="$COMMON_TREE/scripts/config"

[[ -x "$CONFIG_TOOL" ]] || {
  echo "::error::Kernel config editor is unavailable: $CONFIG_TOOL"
  exit 1
}
[[ -f "$FRAGMENT" ]] || {
  echo "::error::Final defconfig fragment is unavailable: $FRAGMENT"
  exit 1
}

DISABLED=(
  KFENCE
  KASAN KASAN_HW_TAGS KASAN_SW_TAGS KASAN_GENERIC
  UBSAN UBSAN_TRAP UBSAN_BOUNDS UBSAN_LOCAL_BOUNDS
)
KSU_INCOMPATIBLE=(UH KDP RKP)
REQUIRED_MODULE_COMPAT=(MODULE_ALLOW_BTF_MISMATCH)
REQUIRED_HARDENING=(
  RANDOMIZE_KSTACK_OFFSET RANDOMIZE_KSTACK_OFFSET_DEFAULT
  UNMAP_KERNEL_AT_EL0 VIRTUALIZATION KVM
)

# Kleaf applies this fragment after the base GKI defconfig and olddefconfig.
# Legacy build.sh additionally consumes the edited base defconfig.
TARGETS=("$FRAGMENT")
if [[ "$MODE" == "legacy" ]]; then
  [[ -f "$DEFCONFIG" ]] || {
    echo "::error::Legacy base defconfig is unavailable: $DEFCONFIG"
    exit 1
  }
  TARGETS+=("$DEFCONFIG")
fi

for target in "${TARGETS[@]}"; do
  for symbol in "${DISABLED[@]}" "${KSU_INCOMPATIBLE[@]}"; do
    "$CONFIG_TOOL" --file "$target" --disable "$symbol"
  done
  for symbol in "${REQUIRED_HARDENING[@]}"; do
    "$CONFIG_TOOL" --file "$target" --enable "$symbol"
  done
  for symbol in "${REQUIRED_MODULE_COMPAT[@]}"; do
    "$CONFIG_TOOL" --file "$target" --enable "$symbol"
  done

  # Samsung's very verbose production drivers can overwrite the stock 128 KiB
  # printk ring buffer within minutes. Keep a deterministic 4 MiB buffer in the
  # kernel config and require the matching AnyKernel log_buf_len=4M parameter.
  "$CONFIG_TOOL" --file "$target" --set-val LOG_BUF_SHIFT 22

  for symbol in "${DISABLED[@]}" "${KSU_INCOMPATIBLE[@]}"; do
    grep -qx "# CONFIG_${symbol} is not set" "$target" || {
      echo "::error::CONFIG_${symbol} was not disabled in $target"
      exit 1
    }
  done
  for symbol in "${REQUIRED_HARDENING[@]}"; do
    grep -qx "CONFIG_${symbol}=y" "$target" || {
      echo "::error::CONFIG_${symbol} was not enabled in $target"
      exit 1
    }
  done
  for symbol in "${REQUIRED_MODULE_COMPAT[@]}"; do
    grep -qx "CONFIG_${symbol}=y" "$target" || {
      echo "::error::CONFIG_${symbol} was not enabled in $target"
      exit 1
    }
  done
  grep -qx 'CONFIG_LOG_BUF_SHIFT=22' "$target" || {
    echo "::error::CONFIG_LOG_BUF_SHIFT=22 was not retained in $target"
    exit 1
  }
done

echo "S928B daily debug sanitizers fully disabled in the final build input:"
printf '  CONFIG_%s=n\n' "${DISABLED[@]}"
echo "Samsung Knox hypervisor options incompatible with KernelSU disabled:"
printf '  CONFIG_%s=n\n' "${KSU_INCOMPATIBLE[@]}"
echo "Samsung DLKM BTF compatibility retained for the ReSukiSU/SUSFS-modified kernel:"
printf '  CONFIG_%s=y\n' "${REQUIRED_MODULE_COMPAT[@]}"
echo "S928B printk ring buffer fixed at 4 MiB: CONFIG_LOG_BUF_SHIFT=22"
echo "S928B KMI compatibility is supplied by the always-built inactive kasan_flag_enabled stub."
echo "S928B hardening and kernel-side virtualization support retained:"
printf '  CONFIG_%s=y\n' "${REQUIRED_HARDENING[@]}"
echo "Note: functional /dev/kvm still requires an EL2/HYP handoff from the bootloader."
