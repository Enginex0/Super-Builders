#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree}"
BOOTCONFIG="$COMMON_TREE/fs/proc/bootconfig.c"

[[ -s "$BOOTCONFIG" ]] || {
  echo "::error::SUSFS bootconfig source is missing: $BOOTCONFIG"
  exit 1
}

python3 - "$BOOTCONFIG" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
key = "susfs_is_fake_cmdline_or_bootconfig_buffer_set"
legacy = re.compile(
    r"static_branch_likely\(\s*&susfs_is_fake_cmdline_or_bootconfig_buffer_set\s*\)"
)
fixed = f"static_key_enabled(&{key})"

required = (
    "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG",
    f"extern struct static_key_false {key};",
    "susfs_spoof_cmdline_or_bootconfig(m);",
)
for marker in required:
    if marker not in text:
        raise SystemExit(f"missing SUSFS bootconfig marker: {marker}")

if fixed not in text:
    matches = list(legacy.finditer(text))
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one static_branch_likely bootconfig gate, found {len(matches)}"
        )
    text = legacy.sub(fixed, text, count=1)
    path.write_text(text, encoding="utf-8", newline="\n")
    text = path.read_text(encoding="utf-8")
    print("Applied SUSFS bootconfig runtime fix: static_branch_likely -> static_key_enabled")
else:
    print("SUSFS bootconfig runtime fix already present")

if text.count(fixed) != 1:
    raise SystemExit(f"expected one static_key_enabled bootconfig gate, found {text.count(fixed)}")
if legacy.search(text):
    raise SystemExit("legacy static_branch_likely bootconfig gate still present")

start = text.find("static int boot_config_proc_show")
if start < 0:
    raise SystemExit("boot_config_proc_show not found")
end = text.find("\n}", start)
if end < 0:
    raise SystemExit("boot_config_proc_show end not found")
body = text[start:end]
key_pos = body.find(fixed)
spoof_pos = body.find("susfs_spoof_cmdline_or_bootconfig(m);")
return_pos = body.find("return 0;", spoof_pos)
if not (0 <= key_pos < spoof_pos < return_pos):
    raise SystemExit("bootconfig spoof ordering is not key gate -> spoof -> return")

print("Verified SUSFS bootconfig runtime gate uses static_key_enabled and reaches spoof helper")
PY
