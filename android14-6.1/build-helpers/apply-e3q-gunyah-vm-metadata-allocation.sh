#!/usr/bin/env bash
set -euo pipefail

KERNEL_TREE="${1:?usage: apply-e3q-gunyah-vm-metadata-allocation.sh <kernel-tree>}"
BASE_COMMIT="069aeb35a76f732dca8b2276d89e00319f320eac"
TMP_DIR="$(mktemp -d -t e3q-gunyah-large-memory.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Preserve the exact runtime-proven Gunyah pipeline from run 33793706535:
# IRQFD reservation/routing, bounded backing, 8192 safety guard, 512-entry
# RM MEM_APPEND batching, boot-context fallback, SCM VMID mapping, KMI allowance,
# qcom-scm provider and safe teardown. Apply the new large-memory metadata fix
# only after that immutable baseline has completed successfully.
BASE_HELPER_NAME="apply-e3q-gunyah-vm-metadata-allocation.sh"
BASE_HELPER="$TMP_DIR/$BASE_HELPER_NAME"
BASE_HELPER_URL="https://raw.githubusercontent.com/kaos2310/Super-Builders/${BASE_COMMIT}/android14-6.1/build-helpers"

# The immutable wrapper resolves these helpers relative to its own directory.
# Fetch the complete proven helper set beside it so nested CMA, QCOM/VMID and
# additive-KMI stages cannot fail later with a misleading missing-file error.
for helper in \
  "$BASE_HELPER_NAME" \
  'apply-e3q-gunyah-cma-compat.sh' \
  'apply-e3q-gunyah-qcom-vmid-compat.sh' \
  'allow-e3q-gunyah-rm-vmid-kmi.sh'; do
  curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
    "$BASE_HELPER_URL/$helper" \
    -o "$TMP_DIR/$helper"
  test -s "$TMP_DIR/$helper" || {
    echo "FATAL: immutable e3q Gunyah helper is empty: $helper" >&2
    exit 1
  }
  bash -n "$TMP_DIR/$helper"
done

for token in \
  'mapping->parcel.n_mem_entries > 8192' \
  'GH_DIAG rm_mem_share call begin' \
  'apply-e3q-gunyah-qcom-vmid-compat.sh' \
  'static u16 qcom_scm_map_vmid(u16 vmid)' \
  'Restored e3q 8192-total-entry Gunyah safety guard'; do
  grep -qF "$token" "$BASE_HELPER" || {
    echo "FATAL: immutable baseline helper missing expected token: $token" >&2
    exit 1
  }
done

bash "$BASE_HELPER" "$KERNEL_TREE"

GUNYAH_DIR="$KERNEL_TREE/drivers/virt/gunyah"
VM_MM="$GUNYAH_DIR/vm_mgr_mm.c"
VM_MGR="$GUNYAH_DIR/vm_mgr.c"
RM_RPC="$GUNYAH_DIR/rsc_mgr_rpc.c"
QCOM_SRC="$GUNYAH_DIR/gunyah_qcom.c"
BACKING_SRC="$GUNYAH_DIR/cma_compat.c"

for file in "$VM_MM" "$VM_MGR" "$RM_RPC" "$QCOM_SRC" "$BACKING_SRC"; do
  test -s "$file" || {
    echo "FATAL: Gunyah source missing before large-memory fix: $file" >&2
    exit 1
  }
done

# SM8650 can require large page-pointer and parcel-entry arrays. kcalloc() may
# require high-order physically contiguous allocations for these metadata arrays;
# kvcalloc() keeps normal kmalloc behavior for small allocations and falls back
# to vmalloc for larger ones. kvfree() is required for the corresponding frees.
python3 - "$VM_MM" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()
original = text

# Accept an already-patched source only if all final invariants are present.
already = (
    'mapping->pages = kvcalloc(' in text
    and 'parcel->mem_entries = kvcalloc(' in text
    and text.count('kvfree(mapping->pages);') >= 2
    and 'kvfree(mapping->parcel.mem_entries);' in text
)

if not already:
    if text.count('mapping->pages = kcalloc(') != 1:
        raise SystemExit(
            'FATAL: expected exactly one mapping->pages kcalloc allocation before SM8650 fix'
        )
    if text.count('parcel->mem_entries = kcalloc(') != 1:
        raise SystemExit(
            'FATAL: expected exactly one parcel->mem_entries kcalloc allocation before SM8650 fix'
        )
    if text.count('kfree(mapping->pages);') != 2:
        raise SystemExit(
            f'FATAL: expected two mapping->pages kfree sites, found {text.count("kfree(mapping->pages);")}'
        )
    if text.count('kfree(mapping->parcel.mem_entries);') != 1:
        raise SystemExit(
            'FATAL: expected one parcel.mem_entries kfree site before SM8650 fix'
        )

    text, n_pages = re.subn(
        r'mapping->pages = kcalloc\(mapping->npages, sizeof\(\*mapping->pages\),\s*GFP_KERNEL_ACCOUNT\);',
        'mapping->pages = kvcalloc(mapping->npages, sizeof(*mapping->pages),\\n'
        '\t\t\t\t  GFP_KERNEL_ACCOUNT);',
        text,
        count=1,
    )
    if n_pages != 1:
        raise SystemExit('FATAL: failed to rewrite mapping->pages allocation to kvcalloc')

    text, n_entries = re.subn(
        r'parcel->mem_entries = kcalloc\(parcel->n_mem_entries,\s*'
        r'sizeof\(parcel->mem_entries\[0\]\),\s*GFP_KERNEL_ACCOUNT\);',
        'parcel->mem_entries = kvcalloc(parcel->n_mem_entries,\\n'
        '\t\t\t\t       sizeof(parcel->mem_entries[0]),\\n'
        '\t\t\t\t       GFP_KERNEL_ACCOUNT);',
        text,
        count=1,
    )
    if n_entries != 1:
        raise SystemExit('FATAL: failed to rewrite parcel->mem_entries allocation to kvcalloc')

    text = text.replace('kfree(mapping->pages);', 'kvfree(mapping->pages);')
    text = text.replace(
        'kfree(mapping->parcel.mem_entries);',
        'kvfree(mapping->parcel.mem_entries);',
    )

checks = {
    'mapping pages kvcalloc': text.count('mapping->pages = kvcalloc(') == 1,
    'parcel entries kvcalloc': text.count('parcel->mem_entries = kvcalloc(') == 1,
    'mapping pages kvfree at reclaim+error': text.count('kvfree(mapping->pages);') == 2,
    'parcel entries kvfree': text.count('kvfree(mapping->parcel.mem_entries);') == 1,
    'old mapping kcalloc absent': 'mapping->pages = kcalloc(' not in text,
    'old parcel kcalloc absent': 'parcel->mem_entries = kcalloc(' not in text,
    'old mapping kfree absent': 'kfree(mapping->pages);' not in text,
    'old parcel kfree absent': 'kfree(mapping->parcel.mem_entries);' not in text,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit('FATAL: SM8650 Gunyah large-memory postcondition failed: ' + ', '.join(failed))

if text != original:
    path.write_text(text)
    print('Applied SM8650 Gunyah metadata allocation fix: kcalloc/kfree -> kvcalloc/kvfree')
else:
    print('SM8650 Gunyah metadata allocation fix already present and verified')
PY

# Preserve the previously proven runtime-critical state after the additional
# vm_mgr_mm.c transform. Fail closed if any earlier Gunyah fix disappeared.
for token in \
  'mapping->parcel.n_mem_entries > 8192' \
  'GH_DIAG mem_share refused' \
  'GH_DIAG mem_share begin' \
  'GH_DIAG mem_share end'; do
  grep -qF "$token" "$VM_MGR" || {
    echo "FATAL: post-large-memory vm_mgr.c lost required token: $token" >&2
    exit 1
  }
done

for token in \
  'GH_RM_RPC_MEM_APPEND' \
  'static int gh_rm_mem_append(' \
  'static int _gh_rm_mem_append(' \
  'GH_DIAG rm_append sequence begin' \
  'GH_DIAG rm_append batch begin' \
  'EXPORT_SYMBOL_GPL(gh_rm_get_vmid);'; do
  grep -qF "$token" "$RM_RPC" || {
    echo "FATAL: post-large-memory RM source lost required token: $token" >&2
    exit 1
  }
done

for token in \
  'static u16 qcom_scm_map_vmid(u16 vmid)' \
  'gh_rm_get_vmid(rm, &self_vmid)' \
  'src = BIT_ULL(qcom_scm_map_vmid(self_vmid));' \
  'new_perms[n].vmid = qcom_scm_map_vmid(vmid);' \
  'src |= BIT_ULL(qcom_scm_map_vmid(vmid));'; do
  grep -qF "$token" "$QCOM_SRC" || {
    echo "FATAL: post-large-memory gunyah_qcom.c lost SCM/VMID token: $token" >&2
    exit 1
  }
done

for token in \
  '#define GH_EXTENT_MIN_ORDER 3U' \
  '#define GH_EXTENT_LIMIT 8192UL' \
  'alloc_contig_pages(1UL << try_order, gfp, NUMA_NO_NODE, NULL)' \
  '__free_page(nth_page(chunk->base, i));'; do
  grep -qF "$token" "$BACKING_SRC" || {
    echo "FATAL: post-large-memory bounded backing lost required token: $token" >&2
    exit 1
  }
done

# Make patch-format/whitespace regressions visible before the expensive build.
git -C "$KERNEL_TREE" diff --check -- drivers/virt/gunyah/vm_mgr_mm.c
git -C "$KERNEL_TREE" diff -- drivers/virt/gunyah/vm_mgr_mm.c

echo 'e3q Gunyah preflight complete: prior RM/IRQFD/SCM-VMID pipeline preserved + SM8650 kvcalloc/kvfree large-memory metadata fix verified'
