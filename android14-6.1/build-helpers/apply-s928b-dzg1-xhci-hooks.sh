#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

[[ -d "$COMMON_TREE" ]] || {
  echo "::error::Common kernel tree not found: $COMMON_TREE"
  exit 1
}

"$PYTHON_BIN" - "$COMMON_TREE" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
header = root / "include/trace/hooks/xhci.h"
vendor_hooks = root / "drivers/android/vendor_hooks.c"
xhci_plat = root / "drivers/usb/host/xhci-plat.c"
abi_list = root / "android/abi_gki_aarch64_galaxy"

for required in (vendor_hooks, xhci_plat, abi_list):
    if not required.is_file():
        raise SystemExit(f"required DZG1 integration target is missing: {required}")

header_text = """/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xhci
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_HOOK_XHCI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_XHCI_H
#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>
/*
 * Following tracepoints are not exported in tracefs and provide a
 * mechanism for vendor modules to hook and extend functionality
 */

DECLARE_HOOK(android_vh_xhci_suspend,
	TP_PROTO(struct device *dev, int *bypass),
	TP_ARGS(dev, bypass));

DECLARE_HOOK(android_vh_xhci_resume,
	TP_PROTO(struct device *dev, int *bypass),
	TP_ARGS(dev, bypass));

#endif /* _TRACE_HOOK_XHCI_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
"""

if header.exists():
    current = header.read_text()
    for hook in ("android_vh_xhci_suspend", "android_vh_xhci_resume"):
        if hook not in current:
            raise SystemExit(f"existing xhci hook header is incompatible: {hook} missing")
    if "#include <linux/tracepoint.h>" not in current:
        anchor = "#define _TRACE_HOOK_XHCI_H\n"
        if current.count(anchor) != 1:
            raise SystemExit("existing xhci hook header guard changed")
        current = current.replace(
            anchor,
            anchor + "\n#include <linux/tracepoint.h>\n",
            1,
        )
        header.write_text(current)
else:
    header.parent.mkdir(parents=True, exist_ok=True)
    header.write_text(header_text)


def insert_after_once(text: str, anchor: str, addition: str, description: str) -> str:
    if addition.strip() in text:
        return text
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(f"{description}: expected one anchor, found {count}: {anchor!r}")
    return text.replace(anchor, anchor + addition, 1)


vendor = vendor_hooks.read_text()
vendor = insert_after_once(
    vendor,
    "#include <trace/hooks/usb.h>\n",
    "#include <trace/hooks/xhci.h>\n",
    "xhci vendor-hook include",
)
vendor = insert_after_once(
    vendor,
    "EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_usb_dev_resume);\n",
    "EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_xhci_suspend);\n"
    "EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_xhci_resume);\n",
    "xhci vendor-hook exports",
)
vendor_hooks.write_text(vendor)

plat = xhci_plat.read_text()
if "#include <trace/hooks/xhci.h>" not in plat:
    usb_hook_include = "#include <trace/hooks/usb.h>\n"
    local_include = '#include "xhci.h"\n'
    if plat.count(usb_hook_include) == 1:
        plat = plat.replace(
            usb_hook_include,
            usb_hook_include + "#include <trace/hooks/xhci.h>\n",
            1,
        )
    elif plat.count(local_include) == 1:
        # Android 14/6.1 2025-09 predates the USB vendor-hook include in
        # xhci-plat.c. Keep the hook beside the local XHCI includes.
        plat = plat.replace(
            local_include,
            "#include <trace/hooks/xhci.h>\n\n" + local_include,
            1,
        )
    else:
        raise SystemExit("xhci platform hook include anchors changed")


def function_block(text: str, signature: str) -> tuple[int, int, str]:
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f"missing function: {signature}")
    end = text.find("\n}\n", start)
    if end < 0:
        raise SystemExit(f"unterminated function: {signature}")
    end += len("\n}\n")
    return start, end, text[start:end]


def update_function(text: str, signature: str, updater) -> str:
    start, end, block = function_block(text, signature)
    updated = updater(block)
    return text[:start] + updated + text[end:]


def update_suspend(block: str) -> str:
    if "trace_android_vh_xhci_suspend(dev, &bypass);" not in block:
        if "\tint ret;\n" not in block:
            raise SystemExit("xhci runtime suspend no longer has the expected ret declaration")
        block = block.replace("\tint ret;\n", "\tint ret;\n\tint bypass = 0;\n", 1)
        anchor = "\treturn xhci_suspend(xhci, true);\n"
        if block.count(anchor) != 1:
            raise SystemExit("xhci runtime suspend return path changed")
        block = block.replace(
            anchor,
            "\ttrace_android_vh_xhci_suspend(dev, &bypass);\n"
            "\tif (bypass)\n"
            "\t\treturn 0;\n\n" + anchor,
            1,
        )
    return block


def update_resume(block: str) -> str:
    if "trace_android_vh_xhci_resume(dev, &bypass);" not in block:
        anchor_decl = "\tstruct xhci_hcd *xhci = hcd_to_xhci(hcd);\n"
        if block.count(anchor_decl) != 1:
            raise SystemExit("xhci runtime resume declaration path changed")
        block = block.replace(anchor_decl, anchor_decl + "\tint bypass = 0;\n", 1)
        return_lines = [line for line in block.splitlines(keepends=True)
                        if line.startswith("\treturn xhci_resume(xhci,")]
        if len(return_lines) != 1:
            raise SystemExit("xhci runtime resume return path changed")
        anchor = return_lines[0]
        block = block.replace(
            anchor,
            "\ttrace_android_vh_xhci_resume(dev, &bypass);\n"
            "\tif (bypass)\n"
            "\t\treturn 0;\n\n" + anchor,
            1,
        )
    return block


plat = update_function(
    plat,
    "static int __maybe_unused xhci_plat_runtime_suspend(struct device *dev)",
    update_suspend,
)
plat = update_function(
    plat,
    "static int __maybe_unused xhci_plat_runtime_resume(struct device *dev)",
    update_resume,
)
xhci_plat.write_text(plat)

abi = abi_list.read_text()
abi_groups = (
    (
        "  __traceiter_android_vh_wq_lockup_pool\n",
        (
            "__traceiter_android_rvh_nf_conn_alloc",
            "__traceiter_android_rvh_nf_conn_free",
            "__traceiter_android_vh_xhci_resume",
            "__traceiter_android_vh_xhci_suspend",
        ),
    ),
    (
        "  __tracepoint_android_vh_wq_lockup_pool\n",
        (
            "__tracepoint_android_rvh_nf_conn_alloc",
            "__tracepoint_android_rvh_nf_conn_free",
            "__tracepoint_android_vh_xhci_resume",
            "__tracepoint_android_vh_xhci_suspend",
        ),
    ),
)
for anchor, symbols in abi_groups:
    missing = [symbol for symbol in symbols if f"  {symbol}\n" not in abi]
    if not missing:
        continue
    if abi.count(anchor) != 1:
        raise SystemExit(f"Samsung Galaxy ABI insertion anchor changed: {anchor.strip()}")
    abi = abi.replace(anchor, anchor + "".join(f"  {symbol}\n" for symbol in missing), 1)
abi_list.write_text(abi)

checks = {
    header: (
        "#include <linux/tracepoint.h>",
        "DECLARE_HOOK(android_vh_xhci_suspend,",
        "DECLARE_HOOK(android_vh_xhci_resume,",
        "TP_PROTO(struct device *dev, int *bypass)",
    ),
    vendor_hooks: (
        "#include <trace/hooks/xhci.h>",
        "EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_xhci_suspend);",
        "EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_xhci_resume);",
    ),
    xhci_plat: (
        "trace_android_vh_xhci_suspend(dev, &bypass);",
        "trace_android_vh_xhci_resume(dev, &bypass);",
    ),
    abi_list: tuple(symbol for _, symbols in abi_groups for symbol in symbols),
}
for path, needles in checks.items():
    text = path.read_text()
    for needle in needles:
        count = text.count(needle)
        if needle == "TP_PROTO(struct device *dev, int *bypass)":
            if count != 2:
                raise SystemExit(f"{path}: expected two exact hook prototypes, found {count}")
        elif count != 1:
            raise SystemExit(f"{path}: expected one {needle!r}, found {count}")
PY

echo "Applied S928BXXS6DZG1 Samsung vendor hooks and Galaxy KMI exports"
