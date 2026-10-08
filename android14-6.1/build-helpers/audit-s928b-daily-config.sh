#!/bin/bash
set -euo pipefail

CONFIG_FILE="${1:?final kernel config}"
REQUIRE_KPM="${2:-true}"
REQUIRE_CUSTOM_MANAGER="${3:-false}"
KMI_MODE="${4:-runtime-compat}"
case "$KMI_MODE" in
  runtime-compat|symtypes|strict) ;;
  *)
    echo "::error::Unsupported KMI mode for daily config audit: $KMI_MODE"
    exit 1
    ;;
esac
[[ -f "$CONFIG_FILE" ]] || {
  echo "::error::Kernel config not found: $CONFIG_FILE"
  exit 1
}

REQUIRED=(
  CONFIG_MODULE_ALLOW_BTF_MISMATCH
  CONFIG_KSU
  CONFIG_KSU_MULTI_MANAGER_SUPPORT
  CONFIG_KSU_SUSFS
  CONFIG_KSU_SUSFS_SUS_PATH
  CONFIG_KSU_SUSFS_SUS_MOUNT
  CONFIG_KSU_SUSFS_SUS_KSTAT
  CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT
  CONFIG_KSU_SUSFS_SUS_MAP
  CONFIG_KSU_SUSFS_OPEN_REDIRECT
  CONFIG_KSU_SUSFS_UNICODE_FILTER
  CONFIG_KSU_SUSFS_HIDDEN_NAME
  CONFIG_KSU_SUSFS_SPOOF_UNAME
  CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
  CONFIG_KSU_SUSFS_ENABLE_LOG
  CONFIG_ZEROMOUNT
  CONFIG_BBG
  CONFIG_NAMESPACES
  CONFIG_UTS_NS
  CONFIG_IPC_NS
  CONFIG_PID_NS
  CONFIG_NET_NS
  CONFIG_USER_NS
  CONFIG_ANDROID_BINDERFS
  CONFIG_SYSVIPC
  CONFIG_POSIX_MQUEUE
  CONFIG_TCP_CONG_BBR
  CONFIG_TCP_CONG_BBR3
  CONFIG_DEFAULT_BBR3
  CONFIG_NET_SCH_FQ
  CONFIG_NET_SCH_FQ_CODEL
  CONFIG_NET_SCH_CAKE
  CONFIG_NET_SCH_PIE
  CONFIG_NET_SCH_FQ_PIE
  CONFIG_NTSYNC
  CONFIG_IP_SET
  CONFIG_NETFILTER_XT_SET
  CONFIG_IP6_NF_TARGET_MASQUERADE
  CONFIG_IP_NF_TARGET_TTL
  CONFIG_IP6_NF_TARGET_HL
  CONFIG_IP6_NF_MATCH_HL
  CONFIG_ZRAM
  CONFIG_ZRAM_WRITEBACK
  CONFIG_CRYPTO_LZ4K
  CONFIG_CRYPTO_LZ4KD
  CONFIG_ZRAM_DEF_COMP_LZ4KD
  CONFIG_LRU_GEN
  CONFIG_CFI_CLANG
  CONFIG_SHADOW_CALL_STACK
  CONFIG_RANDOMIZE_KSTACK_OFFSET
  CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT
  CONFIG_UNMAP_KERNEL_AT_EL0
  CONFIG_VIRTUALIZATION
  CONFIG_KVM
)
if [[ "$KMI_MODE" == "strict" ]]; then
  STRICT_KMI_DISABLED=(CONFIG_CGROUP_PIDS CONFIG_LRU_GEN_STATS)
else
  REQUIRED+=(CONFIG_CGROUP_PIDS CONFIG_LRU_GEN_STATS)
  STRICT_KMI_DISABLED=()
fi
if [[ "$REQUIRE_KPM" == "true" ]]; then
  REQUIRED+=(CONFIG_KPM)
fi

missing=()
for symbol in "${REQUIRED[@]}"; do
  grep -qx "${symbol}=y" "$CONFIG_FILE" || missing+=("$symbol")
done
if (("${#missing[@]}")); then
  printf '::error::Required S928B daily options missing: %s\n' "${missing[*]}"
  exit 1
fi

for symbol in "${STRICT_KMI_DISABLED[@]}"; do
  grep -qx "# ${symbol} is not set" "$CONFIG_FILE" || {
    echo "::error::Strict Samsung KMI requires ${symbol}=n"
    exit 1
  }
done

# The S928B production kernel is extremely chatty. The old 128 KiB default
# (CONFIG_LOG_BUF_SHIFT=17) loses early boot diagnostics quickly. Require the
# intended 4 MiB printk ring buffer in both the final .config and extracted
# IKCONFIG; this helper is called for both stages.
grep -qx 'CONFIG_LOG_BUF_SHIFT=22' "$CONFIG_FILE" || {
  echo "::error::S928B requires CONFIG_LOG_BUF_SHIFT=22 (4 MiB printk ring buffer)"
  grep -E '^CONFIG_LOG_BUF_SHIFT=' "$CONFIG_FILE" || true
  exit 1
}

# IPv6_NAT_FIX deliberately rewrites only the embedded IKCONFIG copy from y to
# n. The final build .config is checked strictly before packaging.
grep -Eq '^CONFIG_IP6_NF_NAT=(y|n)$' "$CONFIG_FILE" || {
  echo "::error::CONFIG_IP6_NF_NAT is absent from the final or embedded config"
  exit 1
}

for symbol in KFENCE KASAN UBSAN; do
  grep -qx "# CONFIG_${symbol} is not set" "$CONFIG_FILE" || {
    echo "::error::CONFIG_${symbol} is active or absent from the final config"
    exit 1
  }
done

for symbol in UH KDP RKP; do
  if grep -Eq "^CONFIG_${symbol}=(y|m)$" "$CONFIG_FILE"; then
    echo "::error::CONFIG_${symbol} is incompatible with KernelSU on Samsung DZG1"
    exit 1
  fi
  if grep -qx "# CONFIG_${symbol} is not set" "$CONFIG_FILE"; then
    continue
  fi
  echo "CONFIG_${symbol}=n (dependency-disabled; omitted by Kconfig)"
done

# Child KASAN modes can be omitted from a normalized .config when their parent
# is disabled. Either an explicit "not set" line or dependency-driven absence
# is n; any assigned value is rejected.
for symbol in KASAN_HW_TAGS KASAN_SW_TAGS KASAN_GENERIC; do
  if grep -qx "# CONFIG_${symbol} is not set" "$CONFIG_FILE"; then
    continue
  fi
  if grep -q "^CONFIG_${symbol}=" "$CONFIG_FILE"; then
    echo "::error::CONFIG_${symbol} has an unexpected value"
    grep "^CONFIG_${symbol}=" "$CONFIG_FILE"
    exit 1
  fi
  echo "CONFIG_${symbol}=n (dependency-disabled; omitted by Kconfig)"
done

if grep -Eq '^CONFIG_(KFENCE|KASAN(_[A-Z0-9_]+)?|UBSAN(_TRAP|_BOUNDS|_LOCAL_BOUNDS)?)=y$' "$CONFIG_FILE"; then
  echo "::error::Final kernel config still enables a daily-build sanitizer"
  grep -E '^CONFIG_(KFENCE|KASAN|UBSAN)' "$CONFIG_FILE" || true
  exit 1
fi

echo "Verified ${#REQUIRED[@]} S928B daily features in $CONFIG_FILE"
if [[ "$KMI_MODE" == "strict" ]]; then
  echo "Verified strict Samsung KMI layout: CONFIG_CGROUP_PIDS=n and CONFIG_LRU_GEN_STATS=n"
fi
echo "Verified CONFIG_LOG_BUF_SHIFT=22 (4 MiB printk ring buffer)"
echo "Verified CONFIG_KFENCE=n, CONFIG_KASAN=n and CONFIG_UBSAN=n"
echo "Verified CONFIG_UH=n, CONFIG_KDP=n and CONFIG_RKP=n for KernelSU compatibility"
echo "Verified CONFIG_MODULE_ALLOW_BTF_MISMATCH=y for Samsung DLKM compatibility"
echo "Verified no KASAN implementation is enabled; KMI is supplied by the inactive stub"
echo "Verified CONFIG_CFI_CLANG=y and CONFIG_SHADOW_CALL_STACK=y"
echo "Verified KStack offset randomization is enabled by default"
echo "Verified KVM is compiled; /dev/kvm additionally requires EL2/HYP from the bootloader"
