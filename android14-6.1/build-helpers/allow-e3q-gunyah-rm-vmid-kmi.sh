#!/usr/bin/env bash
set -euo pipefail

KERNEL_TREE="${1:?usage: allow-e3q-gunyah-rm-vmid-kmi.sh <kernel-tree>}"
ABI_LIST="$KERNEL_TREE/android/abi_gki_aarch64"
RM_RPC="$KERNEL_TREE/drivers/virt/gunyah/rsc_mgr_rpc.c"
SYMBOL='gh_rm_get_vmid'

for f in "$ABI_LIST" "$RM_RPC"; do
  test -f "$f" || { echo "FATAL: required KMI source missing: $f" >&2; exit 1; }
done

grep -qF 'EXPORT_SYMBOL_GPL(gh_rm_get_vmid);' "$RM_RPC" || {
  echo 'FATAL: gh_rm_get_vmid is not GPL-exported by this kernel tree' >&2
  exit 1
}

python3 - "$ABI_LIST" "$SYMBOL" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
symbol = sys.argv[2]
lines = path.read_text().splitlines(keepends=True)

if any(line.strip() == symbol for line in lines):
    print(f"KMI symbol already present: {symbol}")
    raise SystemExit(0)

headers = [i for i, line in enumerate(lines) if line.strip() == "[abi_symbol_list]"]
if len(headers) != 1:
    raise SystemExit(f"FATAL: expected exactly one [abi_symbol_list] section, found {len(headers)}")
start = headers[0] + 1
end = len(lines)
for i in range(start, len(lines)):
    stripped = lines[i].strip()
    if re.fullmatch(r"\[[^\]]+\]", stripped):
        end = i
        break

# KMI symbol-list parsers ignore ordering, but keep the additive entry visually
# isolated and avoid rewriting Samsung's large audited list.
insert = [
    "# e3q Gunyah vendor_boot test module: dynamic RM VMID source mapping\n",
    f"  {symbol}\n",
]
lines[end:end] = insert
path.write_text("".join(lines))
print(f"Added additive KMI symbol: {symbol}")
PY

grep -Eq '^[[:space:]]*gh_rm_get_vmid[[:space:]]*$' "$ABI_LIST" || {
  echo 'FATAL: gh_rm_get_vmid was not retained in abi_gki_aarch64' >&2
  exit 1
}

# This is an additive export allowance only; existing Samsung CRCs/types are
# still enforced later by the exact 2469-symbol ZZHL strict DLKM audit.
echo 'e3q Gunyah KMI allowance verified: gh_rm_get_vmid is exported and listed'
