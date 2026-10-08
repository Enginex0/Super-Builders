#!/usr/bin/env bash
set -euo pipefail

KERNEL_TREE="${1:?usage: apply-e3q-gunyah-qcom-vmid-compat.sh <kernel-tree>}"
BASE_COMMIT="d2cc27a6136839a9f4a62c3d45975d19ce20e0ae"
TMP_DIR="$(mktemp -d -t e3q-boot-context-fix.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

BASE_HELPER="$TMP_DIR/apply-e3q-gunyah-qcom-vmid-compat.sh"
curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
  "https://raw.githubusercontent.com/kaos2310/Super-Builders/${BASE_COMMIT}/android14-6.1/build-helpers/apply-e3q-gunyah-qcom-vmid-compat.sh" \
  -o "$BASE_HELPER"

test -s "$BASE_HELPER" || {
  echo 'FATAL: pinned boot-context helper is empty' >&2
  exit 1
}
bash -n "$BASE_HELPER"

# d2cc27a introduced the runtime-required boot-context backport. Adapt only
# source-shape assumptions that differ on the exact Samsung/AOSP tree used by
# this workflow. The outer vm-metadata helper owns the 8192-entry guard: it
# deliberately removes that guard before invoking this QCOM follow-up and
# restores + validates the exact saved block immediately afterwards. Therefore
# this nested helper must not reject the intentional temporary guard absence.
python3 - "$BASE_HELPER" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

old_import = "from pathlib import Path\nimport sys\n"
new_import = "from pathlib import Path\nimport re\nimport sys\n"
if old_import not in text:
    raise SystemExit("FATAL: pinned helper Python import anchor changed")
text = text.replace(old_import, new_import, 1)

# Samsung/AOSP aligns the RM opcode defines with tabs/extra spaces.
old = """if 'GH_RM_RPC_VM_SET_BOOT_CONTEXT' not in rpc:\n    anchor = '#define GH_RM_RPC_VM_GET_VMID 0x56000024\\n'\n    if anchor not in rpc:\n        raise SystemExit('FATAL: RM GET_VMID opcode anchor missing')\n    rpc = rpc.replace(anchor, anchor + '#define GH_RM_RPC_VM_SET_BOOT_CONTEXT 0x56000031\\n', 1)\n"""
new = """if 'GH_RM_RPC_VM_SET_BOOT_CONTEXT' not in rpc:\n    pattern = re.compile(\n        r'(?m)^#define[ \\t]+GH_RM_RPC_VM_GET_VMID[ \\t]+0x56000024[ \\t]*\\n'\n    )\n    matches = list(pattern.finditer(rpc))\n    if len(matches) != 1:\n        raise SystemExit(\n            f'FATAL: expected one RM GET_VMID opcode anchor, found {len(matches)}'\n        )\n    end = matches[0].end()\n    rpc = (\n        rpc[:end]\n        + '#define GH_RM_RPC_VM_SET_BOOT_CONTEXT 0x56000031\\n'\n        + rpc[end:]\n    )\n"""
if text.count(old) != 1:
    raise SystemExit(
        f"FATAL: expected one strict GET_VMID matcher in pinned helper, found {text.count(old)}"
    )
text = text.replace(old, new, 1)

# Match the upstream Gunyah boot-context xarray value representation.
for old_cast, new_cast in (
    ('(void *)(uintptr_t)boot_ctx->value', '(void *)boot_ctx->value'),
    ('(u64)(uintptr_t)entry', '(u64)entry'),
):
    if text.count(old_cast) != 1:
        raise SystemExit(
            f"FATAL: expected one boot-context cast {old_cast!r}, found {text.count(old_cast)}"
        )
    text = text.replace(old_cast, new_cast, 1)

# During this helper call the outer wrapper has intentionally removed only the
# 8192 guard block. Keep every other fail-closed assertion, but defer this one
# guard assertion to the outer wrapper which restores the exact saved text.
guard_check = "require_fixed 'mapping->parcel.n_mem_entries > 8192' \"$VM_SRC\" '8192 mem-share safety guard'\n"
if text.count(guard_check) != 1:
    raise SystemExit(
        f"FATAL: expected one nested 8192 guard assertion, found {text.count(guard_check)}"
    )
text = text.replace(
    guard_check,
    "echo 'e3q nested QCOM/boot-context validation: 8192 guard check deferred to outer restore gate'\n",
    1,
)

# Ensure the inner fail-closed audit still recognizes the inserted opcode and
# that all unrelated integrity gates remain present.
required = (
    'GH_RM_RPC_VM_SET_BOOT_CONTEXT 0x56000031',
    "require_fixed 'GH_DIAG mem_share begin'",
    "require_fixed 'GH_RM_RPC_MEM_APPEND'",
    "require_fixed 'GH_DIAG rm_append sequence begin'",
    "require_fixed 'static u16 qcom_scm_map_vmid(u16 vmid)'",
    "require_absent 'GH_QCOM_DIAG'",
)
missing = [token for token in required if token not in text]
if missing:
    raise SystemExit('FATAL: nested helper lost required integrity gates: ' + ', '.join(missing))

path.write_text(text)
PY

bash -n "$BASE_HELPER"

# Execute the complete d2cc27a QCOM + boot-context implementation. The caller
# restores the exact 8192 guard immediately after this returns, and performs
# its own final guard/MEM_APPEND/bounded-backing/SCM/KMI assertions before any
# kernel compilation starts.
bash "$BASE_HELPER" "$KERNEL_TREE"

GUNYAH_DIR="$KERNEL_TREE/drivers/virt/gunyah"
VM_SRC="$GUNYAH_DIR/vm_mgr.c"
VM_HDR="$GUNYAH_DIR/vm_mgr.h"
RM_RPC="$GUNYAH_DIR/rsc_mgr_rpc.c"
RM_HDR="$KERNEL_TREE/include/linux/gunyah_rsc_mgr.h"
UAPI_HDR="$KERNEL_TREE/include/uapi/linux/gunyah.h"

# The SM8650/e3q Resource Manager rejects VM_SET_BOOT_CONTEXT (0x56000031)
# with RM error -1, mapped by the Linux RM layer to -EOPNOTSUPP. Modern crosvm
# already treats a missing boot-context API as legacy-compatible only when the
# payload offset is zero. Mirror that compatibility in the kernel without
# weakening non-zero-offset or non-PC boot contexts: accept -EOPNOTSUPP only
# for PC[0] when the requested PC is exactly the base of the guest-RAM parcel
# that also contains the DTB. Every other context and every other RM error stays
# fail-closed.
python3 - "$VM_SRC" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

sig = 'static int gh_vm_fill_boot_context(struct gh_vm *ghvm)'
start = text.find(sig)
if start < 0:
    raise SystemExit('FATAL: gh_vm_fill_boot_context missing before legacy fallback patch')
brace = text.find('{', start)
if brace < 0:
    raise SystemExit('FATAL: gh_vm_fill_boot_context opening brace missing')

depth = 0
end = None
for pos in range(brace, len(text)):
    ch = text[pos]
    if ch == '{':
        depth += 1
    elif ch == '}':
        depth -= 1
        if depth == 0:
            end = pos + 1
            break
if end is None:
    raise SystemExit('FATAL: gh_vm_fill_boot_context is unterminated')

old = text[start:end]
if 'gh_vm_can_legacy_boot_context_fallback' in text:
    raise SystemExit('FATAL: legacy boot-context fallback unexpectedly present before patch')

new = '''static bool gh_vm_can_legacy_boot_context_fallback(struct gh_vm *ghvm,
\t\t\t\t\t\t unsigned long reg_set,
\t\t\t\t\t\t unsigned long reg_index,
\t\t\t\t\t\t u64 value)
{
\tstruct gh_vm_mem *mapping;

\tif (reg_set != REG_SET_PC || reg_index != 0)
\t\treturn false;

\tmapping = gh_vm_mem_find_by_addr(ghvm, ghvm->dtb_config.guest_phys_addr,
\t\t\t\t\t ghvm->dtb_config.size);
\tif (!mapping)
\t\treturn false;

\treturn value == mapping->guest_phys_addr;
}

static int gh_vm_fill_boot_context(struct gh_vm *ghvm)
{
\tunsigned long reg_set, reg_index, id;
\tvoid *entry;
\tu64 value;
\tint ret;

\txa_for_each(&ghvm->boot_context, id, entry) {
\t\treg_set = (id >> GH_VM_BOOT_CONTEXT_REG_SHIFT) & 0xff;
\t\treg_index = id & 0xff;
\t\tvalue = (u64)entry;
\t\tret = gh_rm_set_boot_context(ghvm->rm, ghvm->vmid, reg_set, reg_index,
\t\t\t\t\t     value);
\t\tif (ret == -EOPNOTSUPP &&
\t\t    gh_vm_can_legacy_boot_context_fallback(ghvm, reg_set, reg_index,
\t\t\t\t\t\t\t   value)) {
\t\t\tdev_warn(ghvm->parent,
\t\t\t\t "RM boot context unsupported; using legacy zero-offset PC\\n");
\t\t\tcontinue;
\t\t}
\t\tif (ret)
\t\t\treturn ret;
\t}

\treturn 0;
}'''

text = text[:start] + new + text[end:]
path.write_text(text)
PY

# Follow-on preflight: validate the complete boot-context source state now,
# before the expensive kernel build. This intentionally does not check the
# temporarily-removed 8192 guard; the caller restores and audits it next.
for file in "$VM_SRC" "$VM_HDR" "$RM_RPC" "$RM_HDR" "$UAPI_HDR"; do
  test -s "$file" || {
    echo "FATAL: boot-context preflight source missing: $file" >&2
    exit 1
  }
done

for token in \
  '#define GH_RM_RPC_VM_SET_BOOT_CONTEXT 0x56000031' \
  'struct gh_rm_vm_set_boot_context_req {' \
  'int gh_rm_set_boot_context(struct gh_rm *rm,' \
  'GH_RM_RPC_MEM_APPEND' \
  'GH_DIAG rm_append sequence begin'; do
  grep -qF "$token" "$RM_RPC" || {
    echo "FATAL: RM boot-context/MEM_APPEND preflight token missing: $token" >&2
    exit 1
  }
done

grep -qF 'int gh_rm_set_boot_context(struct gh_rm *rm, u16 vmid, u8 reg_set, u8 reg_idx, u64 value);' "$RM_HDR" || {
  echo 'FATAL: gh_rm_set_boot_context declaration missing' >&2
  exit 1
}

for token in \
  'enum gh_vm_boot_context_reg {' \
  'GH_VM_BOOT_CONTEXT_REG_SHIFT 8' \
  'struct gh_vm_boot_context {' \
  'GH_VM_SET_BOOT_CONTEXT'; do
  grep -qF "$token" "$UAPI_HDR" || {
    echo "FATAL: boot-context UAPI token missing: $token" >&2
    exit 1
  }
done

for token in \
  'struct xarray boot_context;' \
  '#include <linux/xarray.h>'; do
  grep -qF "$token" "$VM_HDR" || {
    echo "FATAL: VM-manager header boot-context token missing: $token" >&2
    exit 1
  }
done

for token in \
  'xa_init(&ghvm->boot_context);' \
  'static long gh_vm_set_boot_context(struct gh_vm *ghvm,' \
  'static bool gh_vm_can_legacy_boot_context_fallback(struct gh_vm *ghvm,' \
  'reg_set != REG_SET_PC || reg_index != 0' \
  'gh_vm_mem_find_by_addr(ghvm, ghvm->dtb_config.guest_phys_addr,' \
  'return value == mapping->guest_phys_addr;' \
  'ret == -EOPNOTSUPP' \
  'RM boot context unsupported; using legacy zero-offset PC' \
  'static int gh_vm_fill_boot_context(struct gh_vm *ghvm)' \
  'ret = gh_vm_fill_boot_context(ghvm);' \
  'case GH_VM_SET_BOOT_CONTEXT:' \
  'xa_destroy(&ghvm->boot_context);' \
  'GH_DIAG mem_share begin'; do
  grep -qF "$token" "$VM_SRC" || {
    echo "FATAL: VM-manager boot-context preflight token missing: $token" >&2
    exit 1
  }
done

# Verify that the generated gh_vm_start() actually applies boot context after
# RM VM_INIT and before hypervisor-resource discovery and RM VM_START. Also
# verify that the fallback cannot silently accept X/SP or an interior PC.
python3 - "$VM_SRC" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

required_fallback = [
    'if (reg_set != REG_SET_PC || reg_index != 0)',
    'ghvm->dtb_config.guest_phys_addr',
    'return value == mapping->guest_phys_addr;',
    'if (ret == -EOPNOTSUPP &&',
    'gh_vm_can_legacy_boot_context_fallback(ghvm, reg_set, reg_index,',
]
missing = [token for token in required_fallback if token not in text]
if missing:
    raise SystemExit('FATAL: unsafe/incomplete legacy boot-context fallback: ' + ', '.join(missing))

sig = 'static int gh_vm_start(struct gh_vm *ghvm)'
start = text.find(sig)
if start < 0:
    raise SystemExit('FATAL: gh_vm_start function missing during lifecycle audit')
brace = text.find('{', start)
if brace < 0:
    raise SystemExit('FATAL: gh_vm_start opening brace missing')
depth = 0
end = None
for pos in range(brace, len(text)):
    ch = text[pos]
    if ch == '{':
        depth += 1
    elif ch == '}':
        depth -= 1
        if depth == 0:
            end = pos + 1
            break
if end is None:
    raise SystemExit('FATAL: gh_vm_start function is unterminated')
block = text[start:end]

ordered = [
    ('VM_INIT', 'gh_rm_vm_init('),
    ('SET_BOOT_CONTEXT', 'gh_vm_fill_boot_context('),
    ('GET_HYP_RESOURCES', 'gh_rm_get_hyp_resources('),
    ('VM_START', 'gh_rm_vm_start('),
]
positions = []
for label, token in ordered:
    pos = block.find(token)
    if pos < 0:
        raise SystemExit(f'FATAL: gh_vm_start missing lifecycle token {label}: {token}')
    positions.append((label, pos))
if [pos for _, pos in positions] != sorted(pos for _, pos in positions):
    raise SystemExit('FATAL: Gunyah lifecycle order invalid: ' + ' -> '.join(f'{label}@{pos}' for label, pos in positions))
print('e3q Gunyah lifecycle verified: ' + ' -> '.join(label for label, _ in positions))
print('e3q Gunyah legacy boot-context fallback verified: EOPNOTSUPP only for PC[0] at DTB RAM parcel base')
PY

echo 'e3q Gunyah QCOM/boot-context preflight complete; safe zero-offset legacy fallback enabled; outer 8192 guard restore gate remains authoritative'
