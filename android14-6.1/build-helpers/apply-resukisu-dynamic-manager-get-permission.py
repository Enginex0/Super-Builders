#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

HANDLER_NEEDLE = """    int ret = ksu_handle_dynamic_manager(&cmd);\n"""
HANDLER_REPLACEMENT = """    /*\n     * KSU_IOCTL_DYNAMIC_MANAGER carries both read and write operations.\n     * The manager UI legitimately uses GET without first becoming uid 0,\n     * while SET/SET_SYNCHRONOUS/WIPE change kernel manager identity state.\n     * Keep those mutating operations root-only even though the dispatcher\n     * now lets a registered manager reach this handler.\n     */\n    if (cmd.operation != DYNAMIC_MANAGER_OP_GET && !only_root()) {\n        pr_warn(\"dynamic_manager: mutating operation %u denied for uid=%d\\n\",\n                cmd.operation, ksu_get_uid_t(current_uid()));\n        return -EPERM;\n    }\n\n    int ret = ksu_handle_dynamic_manager(&cmd);\n"""

TABLE_NEEDLE = """    { \n        .cmd = KSU_IOCTL_DYNAMIC_MANAGER,\n        .name = \"SET_DYNAMIC_MANAGER\",\n        .handler = do_dynamic_manager,\n        .perm_check = only_root \n    },\n"""
TABLE_REPLACEMENT = """    { \n        .cmd = KSU_IOCTL_DYNAMIC_MANAGER,\n        .name = \"DYNAMIC_MANAGER\",\n        .handler = do_dynamic_manager,\n        .perm_check = manager_or_root \n    },\n"""

MARKER = "KSU_IOCTL_DYNAMIC_MANAGER carries both read and write operations"


def fail(msg: str) -> None:
    raise SystemExit(f"ERROR: {msg}")


def verify(dispatch_text: str, feature_text: str) -> None:
    required_dispatch = [
        MARKER,
        "cmd.operation != DYNAMIC_MANAGER_OP_GET && !only_root()",
        '.name = "DYNAMIC_MANAGER"',
        ".perm_check = manager_or_root",
    ]
    for item in required_dispatch:
        if item not in dispatch_text:
            fail(f"post-patch dispatch verification missing: {item}")

    dynamic_block_start = dispatch_text.find(".cmd = KSU_IOCTL_DYNAMIC_MANAGER")
    dynamic_block_end = dispatch_text.find("},", dynamic_block_start)
    if dynamic_block_start < 0 or dynamic_block_end < 0:
        fail("dynamic-manager dispatch table entry not found after patch")
    dynamic_block = dispatch_text[dynamic_block_start:dynamic_block_end]
    if ".perm_check = only_root" in dynamic_block:
        fail("dynamic-manager dispatcher is still root-only")
    if ".perm_check = manager_or_root" not in dynamic_block:
        fail("dynamic-manager dispatcher does not use manager_or_root")

    handler_start = dispatch_text.find("static int do_dynamic_manager")
    handler_end = dispatch_text.find("static int do_get_managers", handler_start)
    if handler_start < 0 or handler_end < 0:
        fail("do_dynamic_manager handler bounds not found")
    handler = dispatch_text[handler_start:handler_end]
    if "cmd.operation != DYNAMIC_MANAGER_OP_GET && !only_root()" not in handler:
        fail("handler does not retain root-only guard for mutating operations")
    if "return -EPERM;" not in handler:
        fail("handler does not fail closed for non-root mutating operations")
    if "ksu_handle_dynamic_manager(&cmd)" not in handler:
        fail("handler no longer calls ksu_handle_dynamic_manager")

    required_feature = [
        "case DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS:",
        "case DYNAMIC_MANAGER_OP_SET:",
        "case DYNAMIC_MANAGER_OP_GET:",
        "case DYNAMIC_MANAGER_OP_WIPE:",
    ]
    for item in required_feature:
        if item not in feature_text:
            fail(f"dynamic-manager feature verification missing: {item}")

    # Guard against silently changing the semantics we are protecting.
    if "dynamic_manager.is_set = 1;" not in feature_text:
        fail("dynamic-manager SET path no longer marks configuration active")
    if "dynamic_manager.is_set = 0;" not in feature_text:
        fail("dynamic-manager WIPE path no longer clears configuration")


def patch_dispatch(ksu_root: Path) -> None:
    dispatch = ksu_root / "kernel" / "supercall" / "dispatch.c"
    feature = ksu_root / "kernel" / "feature" / "dynamic_manager.c"
    if not dispatch.is_file():
        fail(f"missing ReSukiSU dispatch source: {dispatch}")
    if not feature.is_file():
        fail(f"missing ReSukiSU dynamic-manager feature source: {feature}")

    dispatch_text = dispatch.read_text(encoding="utf-8")
    feature_text = feature.read_text(encoding="utf-8")

    if MARKER in dispatch_text:
        verify(dispatch_text, feature_text)
        print(f"ReSukiSU dynamic-manager permission fix already present: {dispatch}")
        return

    if dispatch_text.count(HANDLER_NEEDLE) != 1:
        fail(
            "expected exactly one dynamic-manager handler call, "
            f"found {dispatch_text.count(HANDLER_NEEDLE)}"
        )
    if dispatch_text.count(TABLE_NEEDLE) != 1:
        fail(
            "expected exactly one root-only dynamic-manager table entry, "
            f"found {dispatch_text.count(TABLE_NEEDLE)}"
        )

    patched = dispatch_text.replace(HANDLER_NEEDLE, HANDLER_REPLACEMENT, 1)
    patched = patched.replace(TABLE_NEEDLE, TABLE_REPLACEMENT, 1)
    verify(patched, feature_text)
    dispatch.write_text(patched, encoding="utf-8")
    print(f"Applied operation-aware ReSukiSU dynamic-manager permission fix: {dispatch}")
    print(f"Verified mutating operation semantics in: {feature}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ksu_root", type=Path, help="Checked-out ReSukiSU source directory")
    args = parser.parse_args()
    patch_dispatch(args.ksu_root)


if __name__ == "__main__":
    main()
