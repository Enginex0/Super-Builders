#!/usr/bin/env bash
set -euo pipefail

KERNEL_ROOT="${1:?kernel root}"
REPORT_DIR="${2:?report dir}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED_RELEASE='6.1.162-android14-11-34343818-abS928BXXU6ZZI4'
STOCK_MODVERSIONS="$SCRIPT_DIR/../e3q-zzi4-gunyah-qcom-stock-modversions.tsv"
ABI_LIST="$KERNEL_ROOT/common/android/abi_gki_aarch64"
QCOM_SRC="$KERNEL_ROOT/common/drivers/virt/gunyah/gunyah_qcom.c"
BACKING_SRC="$KERNEL_ROOT/common/drivers/virt/gunyah/cma_compat.c"
GUNYAH_MAKEFILE="$KERNEL_ROOT/common/drivers/virt/gunyah/Makefile"
FIRMWARE_MAKEFILE="$KERNEL_ROOT/common/drivers/firmware/Makefile"
QCOM_SCM_HEADER="$KERNEL_ROOT/common/include/linux/qcom_scm.h"

test -s "$STOCK_MODVERSIONS" || { echo '::error::Stock gunyah_qcom modversion baseline missing'; exit 1; }
test -s "$ABI_LIST" || { echo '::error::Final GKI ABI symbol list missing'; exit 1; }
grep -Eq '^[[:space:]]*gh_rm_get_vmid[[:space:]]*$' "$ABI_LIST" || {
  echo '::error::gh_rm_get_vmid is missing from final GKI KMI symbol list'; exit 1;
}

MODULE=""
declare -A SEEN=()
while IFS= read -r candidate; do
  [[ -s "$candidate" ]] || continue
  resolved=$(realpath "$candidate")
  [[ -z "${SEEN[$resolved]:-}" ]] || continue
  SEEN[$resolved]=1
  strings "$resolved" | grep -qF "vermagic=${EXPECTED_RELEASE}" || continue
  strings "$resolved" | grep -qF 'gh_rm_get_vmid' || continue
  strings "$resolved" | grep -qF 'qcom_scm_assign_mem' || continue
  if strings "$resolved" | grep -qF 'GH_QCOM_SCM'; then
    continue
  fi
  MODULE="$resolved"
  break
done < <(
  find -L "$KERNEL_ROOT/out/android14-6.1" "$KERNEL_ROOT/bazel-bin/common" \
    -type f -name 'gunyah_qcom.ko' -print 2>/dev/null || true
)

[[ -n "$MODULE" ]] || {
  echo '::error::Patched gunyah_qcom.ko with required imports was not found in kernel build outputs'
  find -L "$KERNEL_ROOT/out/android14-6.1" "$KERNEL_ROOT/bazel-bin/common" \
    -type f -name '*gunyah*qcom*.ko' -print 2>/dev/null | head -30 || true
  exit 1
}

# qcom-scm.ko is a build-only provider so modpost sees the same real
# qcom_scm_assign_mem export that Samsung supplies from vendor_boot at runtime.
# It is deliberately not packaged for flashing.
PROVIDER=""
declare -A PROVIDER_SEEN=()
while IFS= read -r candidate; do
  [[ -s "$candidate" ]] || continue
  resolved=$(realpath "$candidate")
  [[ -z "${PROVIDER_SEEN[$resolved]:-}" ]] || continue
  PROVIDER_SEEN[$resolved]=1
  strings "$resolved" | grep -qF "vermagic=${EXPECTED_RELEASE}" || continue
  readelf -Ws "$resolved" 2>/dev/null | grep -qE '[[:space:]]qcom_scm_assign_mem$' || continue
  PROVIDER="$resolved"
  break
done < <(
  find -L "$KERNEL_ROOT/out/android14-6.1" "$KERNEL_ROOT/bazel-bin/common" \
    -type f -name 'qcom-scm.ko' -print 2>/dev/null || true
)

[[ -n "$PROVIDER" ]] || {
  echo '::error::Build-only qcom-scm.ko provider with qcom_scm_assign_mem was not found'
  find -L "$KERNEL_ROOT/out/android14-6.1" "$KERNEL_ROOT/bazel-bin/common" \
    -type f -name 'qcom-scm.ko' -print 2>/dev/null | head -30 || true
  exit 1
}

MODULE_DIR="$REPORT_DIR/gunyah-qcom-module"
mkdir -p "$MODULE_DIR"
cp "$MODULE" "$MODULE_DIR/gunyah_qcom.ko"
sha256sum "$MODULE_DIR/gunyah_qcom.ko" > "$MODULE_DIR/gunyah_qcom.ko.sha256"
readelf -p .modinfo "$MODULE_DIR/gunyah_qcom.ko" > "$MODULE_DIR/modinfo.txt"
readelf -Ws "$MODULE_DIR/gunyah_qcom.ko" > "$MODULE_DIR/symbols.txt"
PROVIDER_SHA=$(sha256sum "$PROVIDER" | awk '{print $1}')
printf '%s  %s\n' "$PROVIDER_SHA" "$PROVIDER" > "$MODULE_DIR/qcom-scm-build-provider.sha256.txt"
git -C "$KERNEL_ROOT/common" diff -- \
  android/abi_gki_aarch64 \
  drivers/firmware/Makefile \
  drivers/virt/gunyah/gunyah_qcom.c \
  drivers/virt/gunyah/cma_compat.c \
  drivers/virt/gunyah/Makefile \
  modules.bzl > "$MODULE_DIR/source.diff"

# git diff can be empty after CI commits its generated tree. Save the actual
# final memory-path sources independently and validate them against the repair.
python3 "$SCRIPT_DIR/patch-e3q-gunyah-reclaim.py" "$KERNEL_ROOT/common" --check
mkdir -p "$MODULE_DIR/final-source"
for source_file in gunyah_qcom.c gunyah_platform_hooks.c rsc_mgr_rpc.c \
                   vm_mgr_mm.c vm_mgr.c vm_mgr.h e3q_mem_reclaim.h; do
  cp "$KERNEL_ROOT/common/drivers/virt/gunyah/$source_file" "$MODULE_DIR/final-source/$source_file"
done
(cd "$MODULE_DIR/final-source" && sha256sum *.c *.h) > "$MODULE_DIR/final-source.sha256"
printf '%s\n' 'E3Q_RECLAIM_CONTRACT=1' \
  'REQUIRES_MATCHING_KERNEL_AND_GUNYAH_QCOM=1' \
  'QUARANTINE_RECOVERY=REBOOT_ONLY' > "$MODULE_DIR/reclaim-contract.env"

strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF "vermagic=${EXPECTED_RELEASE}"
strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF 'modversions'
strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF 'aarch64'
strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF 'gh_rm_get_vmid'
strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF 'qcom_scm_assign_mem'
! strings "$MODULE_DIR/gunyah_qcom.ko" | grep -qF 'GH_QCOM_SCM'
grep -qF 'gh_rm_get_vmid' "$MODULE_DIR/symbols.txt"
grep -qF 'qcom_scm_assign_mem' "$MODULE_DIR/symbols.txt"
readelf -Ws "$PROVIDER" | grep -qE '[[:space:]]qcom_scm_assign_mem$'

# Parse ELF64 __versions. Every arm64 modversion_info record is 64 bytes:
# 8-byte little-endian CRC + 56-byte symbol name.
#
# Compatibility rule for a replacement module:
#   * every stock import that the replacement still uses must retain the exact
#     ZZI4 CRC;
#   * gh_rm_get_vmid is the only allowed new import and must be KMI-listed;
#   * stock imports that optimized/code-generated replacement code no longer
#     references are recorded as dropped dependencies, not treated as failures.
python3 - "$MODULE_DIR/gunyah_qcom.ko" "$STOCK_MODVERSIONS" \
  "$MODULE_DIR/modversions.tsv" "$MODULE_DIR/stock-import-compat.tsv" \
  "$MODULE_DIR/import-audit.env" <<'PY'
from pathlib import Path
import struct
import sys

module = Path(sys.argv[1])
baseline = Path(sys.argv[2])
report = Path(sys.argv[3])
compat_report = Path(sys.argv[4])
env_report = Path(sys.argv[5])
data = module.read_bytes()

if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    raise SystemExit("FATAL: gunyah_qcom.ko is not little-endian ELF64")

shoff = struct.unpack_from("<Q", data, 0x28)[0]
shentsize = struct.unpack_from("<H", data, 0x3A)[0]
shnum = struct.unpack_from("<H", data, 0x3C)[0]
shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
if not shoff or shentsize < 64 or not shnum or shstrndx >= shnum:
    raise SystemExit("FATAL: invalid ELF section table")

def sh(index):
    off = shoff + index * shentsize
    return (
        struct.unpack_from("<I", data, off)[0],
        struct.unpack_from("<Q", data, off + 24)[0],
        struct.unpack_from("<Q", data, off + 32)[0],
    )

_, str_off, str_size = sh(shstrndx)
strtab = data[str_off:str_off + str_size]

def cstr(buf, off):
    end = buf.find(b"\0", off)
    return buf[off:end if end >= 0 else len(buf)].decode("utf-8", "replace")

vers = None
for idx in range(shnum):
    name_off, sec_off, sec_size = sh(idx)
    if cstr(strtab, name_off) == "__versions":
        vers = data[sec_off:sec_off + sec_size]
        break
if vers is None or len(vers) % 64:
    raise SystemExit("FATAL: invalid or missing __versions section")

actual = {}
for off in range(0, len(vers), 64):
    rec = vers[off:off + 64]
    crc = struct.unpack_from("<Q", rec, 0)[0] & 0xffffffff
    name = rec[8:].split(b"\0", 1)[0].decode("utf-8", "strict")
    if name:
        actual[name] = crc

expected = {}
for raw in baseline.read_text().splitlines():
    if not raw or raw.startswith("#"):
        continue
    name, crc = raw.split("\t")[:2]
    expected[name] = int(crc, 16)

required_new = {"gh_rm_get_vmid"}
required_stock = {
    "module_layout",
    "qcom_scm_assign_mem",
    "gh_rm_register_platform_ops",
    "gh_rm_unregister_platform_ops",
}

retained = sorted(set(actual) & set(expected))
dropped = sorted(set(expected) - set(actual))
unexpected = sorted(set(actual) - set(expected) - required_new)
errors = []

for name in retained:
    stock_crc = expected[name]
    build_crc = actual[name]
    if build_crc != stock_crc:
        errors.append(
            f"CRC mismatch {name}: stock=0x{stock_crc:08x} build=0x{build_crc:08x}"
        )

for name in sorted(required_stock):
    if name not in actual:
        errors.append(f"missing required runtime stock import {name}")

for name in sorted(required_new):
    if name not in actual:
        errors.append(f"missing required patched import {name}")

if unexpected:
    errors.append("unexpected new imports: " + ",".join(unexpected))

if "_printk" in actual:
    errors.append("unexpected debug-only _printk import")

report.write_text(
    "symbol\tcrc\n"
    + "".join(f"{name}\t0x{crc:08x}\n" for name, crc in sorted(actual.items()))
)

compat_lines = ["status\tsymbol\tstock_crc\tbuild_crc\n"]
for name in retained:
    compat_lines.append(
        f"retained\t{name}\t0x{expected[name]:08x}\t0x{actual[name]:08x}\n"
    )
for name in dropped:
    compat_lines.append(f"dropped\t{name}\t0x{expected[name]:08x}\t-\n")
for name in sorted(required_new & set(actual)):
    compat_lines.append(f"new\t{name}\t-\t0x{actual[name]:08x}\n")
compat_report.write_text("".join(compat_lines))

dropped_csv = ",".join(dropped) if dropped else "none"
env_report.write_text(
    f"STOCK_BASELINE_COUNT={len(expected)}\n"
    f"STOCK_RETAINED_COUNT={len(retained)}\n"
    f"STOCK_DROPPED_COUNT={len(dropped)}\n"
    f"STOCK_DROPPED_IMPORTS={dropped_csv}\n"
)

if errors:
    raise SystemExit("FATAL: gunyah_qcom modversion audit failed: " + "; ".join(errors))

print(
    f"Verified {len(retained)}/{len(expected)} retained stock imports with exact CRCs; "
    f"dropped stock-only imports={dropped_csv}; "
    "gh_rm_get_vmid is the only allowed new import"
)
PY

# shellcheck disable=SC1090
source "$MODULE_DIR/import-audit.env"

grep -qF $'qcom_scm_assign_mem\t0xcdaced8a' "$MODULE_DIR/modversions.tsv"
grep -qF $'module_layout\t0xea759d7f' "$MODULE_DIR/modversions.tsv"
grep -qF 'gh_rm_get_vmid' "$MODULE_DIR/modversions.tsv"
! grep -qE '^_printk[[:space:]]' "$MODULE_DIR/modversions.tsv"

grep -qF 'gh_rm_get_vmid(rm, &self_vmid)' "$QCOM_SRC"
! grep -qF 'GH_QCOM_SCM' "$QCOM_SRC"
grep -qF '__free_page(nth_page(chunk->base, i));' "$BACKING_SRC"
! grep -qF 'free_contig_range(page_to_pfn(chunk->base), nr_pages)' "$BACKING_SRC"
grep -qF 'obj-m += gunyah_qcom.o # e3q vendor_boot live-test module; not packaged by AnyKernel' "$GUNYAH_MAKEFILE"
grep -qF 'obj-m += qcom-scm.o # e3q vendor_boot build-only provider; not packaged by AnyKernel' "$FIRMWARE_MAKEFILE"
grep -qF 'extern int qcom_scm_assign_mem(' "$QCOM_SCM_HEADER"
! grep -qF 'E3Q_GUNYAH_VENDOR_SCM_API' "$GUNYAH_MAKEFILE"
! grep -qF 'E3Q_GUNYAH_VENDOR_SCM_API' "$QCOM_SCM_HEADER"

CONFIG_FILE=""
for candidate in \
  "$KERNEL_ROOT/out/android14-6.1/common/.config" \
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64/.config"; do
  [[ -s "$candidate" ]] || continue
  CONFIG_FILE="$candidate"
  break
done
if [[ -z "$CONFIG_FILE" ]]; then
  while IFS= read -r candidate; do
    grep -qx 'CONFIG_ARM64=y' "$candidate" 2>/dev/null || continue
    CONFIG_FILE="$candidate"
    break
  done < <(
    find -L "$KERNEL_ROOT/bazel-bin/common" "$KERNEL_ROOT/out/android14-6.1" \
      -type f -name .config -print 2>/dev/null || true
  )
fi
[[ -n "$CONFIG_FILE" ]] || { echo '::error::Final config missing for module audit'; exit 1; }

# Keep Samsung's vendor_boot ownership model. Build-only obj-m targets above do
# not enable either Kconfig symbol in the final GKI configuration.
if grep -Eq '^CONFIG_GUNYAH_QCOM_PLATFORM=[ym]$' "$CONFIG_FILE"; then
  echo '::error::Final kernel config unexpectedly enables GUNYAH_QCOM_PLATFORM'
  exit 1
fi
if grep -Eq '^CONFIG_QCOM_SCM=[ym]$' "$CONFIG_FILE"; then
  echo '::error::Final kernel config unexpectedly enables QCOM_SCM'
  exit 1
fi

MODULE_SHA=$(awk '{print $1}' "$MODULE_DIR/gunyah_qcom.ko.sha256")
cat >> "$REPORT_DIR/summary.md" <<EOF

## Patched e3q Gunyah Qualcomm module

- Module: \`gunyah_qcom.ko\`
- SHA-256: \`${MODULE_SHA}\`
- Kernel release: \`${EXPECTED_RELEASE}\`
- Retained stock ZZI4 imports: \`${STOCK_RETAINED_COUNT}/${STOCK_BASELINE_COUNT}\`, all CRC-exact
- Dropped stock-only imports (not runtime dependencies): \`${STOCK_DROPPED_IMPORTS}\`
- New \`gh_rm_get_vmid\` import: present and KMI-listed
- \`qcom_scm_assign_mem\`: stock CRC \`0xcdaced8a\`
- Build-only \`qcom-scm.ko\` provider SHA-256: \`${PROVIDER_SHA}\` (not for flashing)
- Unexpected additional gunyah_qcom imports: none
- Debug-only \`_printk\` import: absent
- Final \`CONFIG_GUNYAH_QCOM_PLATFORM\` / \`CONFIG_QCOM_SCM\`: not enabled
- Contig teardown: per-page \`__free_page()\`; no \`free_contig_range()\` warning path
- Packaging: gunyah_qcom is CI/live-test artifact only; AnyKernel and vendor_boot remain untouched
EOF

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat >> "$GITHUB_STEP_SUMMARY" <<EOF

### Patched e3q gunyah_qcom module
- SHA-256: \`${MODULE_SHA}\`
- retained stock ZZI4 imports: \`${STOCK_RETAINED_COUNT}/${STOCK_BASELINE_COUNT}\`, all CRC-exact
- dropped stock-only imports: \`${STOCK_DROPPED_IMPORTS}\`
- gh_rm_get_vmid: imported + KMI-listed
- qcom_scm_assign_mem: stock CRC exact via build-only qcom-scm provider
- accidental/debug-only extra imports: none
- CONFIG_GUNYAH_QCOM_PLATFORM / CONFIG_QCOM_SCM remain disabled
- Saved inside Samsung DLKM CRC audit artifact for live ADB testing
EOF
fi

echo "Patched gunyah_qcom module audited: $MODULE (sha256=$MODULE_SHA; retained=${STOCK_RETAINED_COUNT}/${STOCK_BASELINE_COUNT}; dropped=${STOCK_DROPPED_IMPORTS})"
