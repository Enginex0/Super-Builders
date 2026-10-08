#!/usr/bin/env python3
"""Fail-closed e3q Gunyah ownership/reclaim repair, applied after pinned helpers."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "gunyah-reclaim"
MARKER = "/* E3Q_RECLAIM_V1_APPLIED */"


def span(text, signature):
    if text.count(signature) != 1:
        raise ValueError(f"Expected one function: {signature}")
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        depth += (text[pos] == "{") - (text[pos] == "}")
        if not depth:
            return start, pos + 1
    raise ValueError(f"Unterminated function: {signature}")


def function(text, signature):
    a, b = span(text, signature)
    return text[a:b]


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Expected unique anchor: {old[:100]!r}")
    return text.replace(old, new, 1)


def replace_function(text, signature, body):
    a, b = span(text, signature)
    return text[:a] + body + text[b:]


def templates():
    return {name: (ASSETS / name).read_text() for name in
            ("qcom.c", "platform.c", "reclaim.c", "e3q_mem_reclaim.h")}


def validate(files):
    t = templates()
    for name in ("qcom.c", "platform.c", "reclaim.c"):
        signatures = {
            "qcom.c": [("gunyah_qcom.c", "static int qcom_scm_gh_rm_restore("),
                       ("gunyah_qcom.c", "static int qcom_scm_gh_rm_pre_mem_share("),
                       ("gunyah_qcom.c", "static int qcom_scm_gh_rm_post_mem_reclaim(")],
            "platform.c": [("gunyah_platform_hooks.c", "int gh_rm_platform_pre_mem_share("),
                           ("gunyah_platform_hooks.c", "int gh_rm_platform_post_mem_reclaim(")],
            "reclaim.c": [("rsc_mgr_rpc.c", "int gh_rm_mem_reclaim("),
                          ("vm_mgr_mm.c", "static bool gh_vm_mem_reclaim_mapping(")],
        }[name]
        for dest, signature in signatures:
            if function(files[dest], signature) != function(t[name], signature):
                raise ValueError(f"Reclaim body drift: {dest}:{signature}")
    if files["e3q_mem_reclaim.h"] != t["e3q_mem_reclaim.h"]:
        raise ValueError("Private contract header drift")
    required = {
        "gunyah_qcom.c": [".android_backport_reserved1 = E3Q_RECLAIM_COOKIE"],
        "rsc_mgr_rpc.c": ["E3Q_STATE(p) = E3Q_RM_OWNED;", "E3Q_POISON(p) = 1;",
                          "!resp || resp_size != sizeof(*resp)"],
        "vm_mgr_mm.c": ["if (gh_vm_mem_reclaim_mapping(ghvm, mapping))", "atomic_set(&gh_reclaim_blocked, 1)"],
        "vm_mgr.c": ["list_add_tail(&ghvm->quarantine_node, &gh_quarantined_vms);",
                     "if (!list_empty(&ghvm->memory_mappings)) {", "gh_vm_mem_is_blocked()"],
    }
    for name, tokens in required.items():
        for token in tokens:
            if token not in files[name]:
                raise ValueError(f"Missing invariant {name}: {token}")
    if "QCOM_SCM_VMID_HLOS" in files["gunyah_qcom.c"]:
        raise ValueError("Fixed HLOS reclaim target remains")
    if "gh_rm_mem_reclaim(rm, p);" in files["rsc_mgr_rpc.c"]:
        raise ValueError("Unchecked append rollback remains")


def transform(files):
    f = dict(files)
    marked = [name for name, text in f.items() if MARKER in text]
    if marked:
        if len(marked) != 6:
            raise ValueError("Partial reclaim patch: refuse to continue")
        validate(f)
        return f
    t = templates()
    for name in ("gunyah_qcom.c", "gunyah_platform_hooks.c", "rsc_mgr_rpc.c", "vm_mgr_mm.c"):
        f[name] = '#include "e3q_mem_reclaim.h"\n' + f[name]
    q = f["gunyah_qcom.c"]
    for signature in ("static int qcom_scm_gh_rm_pre_mem_share(", "static int qcom_scm_gh_rm_post_mem_reclaim("):
        q = replace_function(q, signature, function(t["qcom.c"], signature))
    anchor = "static int qcom_scm_gh_rm_pre_mem_share("
    q = q.replace(anchor, function(t["qcom.c"], "static int qcom_scm_gh_rm_restore(") + "\n\n" + anchor, 1)
    q = replace(q, ".post_mem_reclaim = qcom_scm_gh_rm_post_mem_reclaim,",
                ".post_mem_reclaim = qcom_scm_gh_rm_post_mem_reclaim,\n"
                "\t.android_backport_reserved1 = E3Q_RECLAIM_COOKIE,")
    f["gunyah_qcom.c"] = q
    for signature in ("int gh_rm_platform_pre_mem_share(", "int gh_rm_platform_post_mem_reclaim("):
        f["gunyah_platform_hooks.c"] = replace_function(f["gunyah_platform_hooks.c"], signature, function(t["platform.c"], signature))
    rpc = f["rsc_mgr_rpc.c"]
    rpc = replace(rpc, "\t\tgh_rm_platform_post_mem_reclaim(rm, p);\n\t\treturn ret;",
                  "\t\t/* RM acceptance is unknown without a handle: no unsafe rollback. */\n"
                  "\t\tE3Q_POISON(p) = 1;\n\t\tgh_vm_mem_block_new();\n"
                  "\t\tE3Q_STATE(p) = E3Q_QUARANTINED;\n\t\treturn ret;")
    rpc = replace(rpc, "\tp->mem_handle = le32_to_cpu(*resp);",
                  "\tif (!resp || resp_size != sizeof(*resp) ||\n"
                  "\t    le32_to_cpu(*resp) == GH_MEM_HANDLE_INVAL) {\n"
                  "\t\tkfree(resp);\n\t\tE3Q_POISON(p) = 1;\n\t\tgh_vm_mem_block_new();\n"
                  "\t\tE3Q_STATE(p) = E3Q_QUARANTINED;\n\t\treturn -EPROTO;\n\t}\n"
                  "\tE3Q_STATE(p) = E3Q_RM_OWNED;\n\tp->mem_handle = le32_to_cpu(*resp);")
    rpc = replace(rpc, "\t\tif (ret) {\n\t\t\tgh_rm_mem_reclaim(rm, p);\n"
                  "\t\t\tp->mem_handle = GH_MEM_HANDLE_INVAL;\n\t\t}",
                  "\t\t/* Keep the handle and RM state on APPEND failure. VM teardown\n"
                  "\t\t * performs checked reclaim after reset, exactly once. */")
    rpc = replace_function(rpc, "int gh_rm_mem_reclaim(", function(t["reclaim.c"], "int gh_rm_mem_reclaim("))
    f["rsc_mgr_rpc.c"] = rpc
    mm = f["vm_mgr_mm.c"]
    block = """static atomic_t gh_reclaim_blocked = ATOMIC_INIT(0);

void gh_vm_mem_block_new(void)
{
	atomic_set(&gh_reclaim_blocked, 1);
}

bool gh_vm_mem_is_blocked(void)
{
	return atomic_read(&gh_reclaim_blocked) != 0;
}

"""
    mm = replace_function(mm, "static void gh_vm_mem_reclaim_mapping(",
                          block + function(t["reclaim.c"], "static bool gh_vm_mem_reclaim_mapping("))
    mm = replace(mm, "\t\tgh_vm_mem_reclaim_mapping(ghvm, mapping);\n\t\tkfree(mapping);",
                 "\t\tif (gh_vm_mem_reclaim_mapping(ghvm, mapping))\n\t\t\tkfree(mapping);")
    f["vm_mgr_mm.c"] = mm
    h = f["vm_mgr.h"]
    h = replace(h, "\tstruct work_struct free_work;", "\tstruct work_struct free_work;\n\tstruct list_head quarantine_node;")
    h = replace(h, "void gh_vm_mem_reclaim(struct gh_vm *ghvm);", "void gh_vm_mem_reclaim(struct gh_vm *ghvm);\n"
                "void gh_vm_mem_block_new(void);\nbool gh_vm_mem_is_blocked(void);")
    f["vm_mgr.h"] = h
    vm = f["vm_mgr.c"]
    vm = replace(vm, "static DEFINE_XARRAY(gh_vm_functions);", "static DEFINE_XARRAY(gh_vm_functions);\n"
                 "static LIST_HEAD(gh_quarantined_vms);\nstatic DEFINE_MUTEX(gh_quarantine_lock);")
    vm = replace(vm, "\tINIT_WORK(&ghvm->free_work, gh_vm_free);", "\tINIT_WORK(&ghvm->free_work, gh_vm_free);\n"
                 "\tINIT_LIST_HEAD(&ghvm->quarantine_node);")
    vm = replace(vm, "\tgh_vm_mem_reclaim(ghvm);", "\tgh_vm_mem_reclaim(ghvm);\n"
                 "\tif (!list_empty(&ghvm->memory_mappings)) {\n"
                 "\t\t/* Keep pins, metadata, mm, RM and module references until reboot.\n"
                 "\t\t * No automatic retry and no reuse of this VMID. */\n"
                 "\t\tmutex_lock(&gh_quarantine_lock);\n"
                 "\t\tlist_add_tail(&ghvm->quarantine_node, &gh_quarantined_vms);\n"
                 "\t\tmutex_unlock(&gh_quarantine_lock);\n"
                 "\t\tdev_err(ghvm->parent, \"GH_RECLAIM VM quarantined; new VMs blocked until reboot\\n\");\n"
                 "\t\treturn;\n\t}")
    vm = replace(vm, "\tdown_write(&ghvm->status_lock);\n\tif (ghvm->vm_status != GH_RM_VM_STATUS_NO_STATE) {",
                 "\tif (gh_vm_mem_is_blocked())\n\t\treturn -EUCLEAN;\n\n"
                 "\tdown_write(&ghvm->status_lock);\n\tif (ghvm->vm_status != GH_RM_VM_STATUS_NO_STATE) {") if "\tdown_write(&ghvm->status_lock);\n\tif (ghvm->vm_status != GH_RM_VM_STATUS_NO_STATE) {" in vm else replace(vm,
                 "\tpr_info(\"GH_DIAG vm_start enter", "\tif (gh_vm_mem_is_blocked()) {\n"
                 "\t\tup_write(&ghvm->status_lock);\n\t\treturn -EUCLEAN;\n\t}\n"
                 "\tpr_info(\"GH_DIAG vm_start enter")
    f["vm_mgr.c"] = vm
    for name in list(f):
        if name != "e3q_mem_reclaim.h":
            f[name] = MARKER + "\n" + f[name]
    f["e3q_mem_reclaim.h"] = t["e3q_mem_reclaim.h"]
    validate(f)
    return f


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.kernel / "drivers/virt/gunyah"
    names = ("gunyah_qcom.c", "gunyah_platform_hooks.c", "rsc_mgr_rpc.c", "vm_mgr_mm.c", "vm_mgr.c", "vm_mgr.h")
    current = {name: (root / name).read_text() for name in names}
    if (root / "e3q_mem_reclaim.h").exists():
        current["e3q_mem_reclaim.h"] = (root / "e3q_mem_reclaim.h").read_text()
    if args.check:
        validate(current)
        print("E3Q reclaim v1: final source contracts verified")
        return
    result = transform(current)  # Validate everything before the first write.
    for name, text in result.items():
        (root / name).write_text(text)
    (root / "e3q-reclaim-source-hashes.json").write_text(json.dumps(
        {name: hashlib.sha256(text.encode()).hexdigest() for name, text in sorted(result.items())}, indent=2) + "\n")
    print("E3Q reclaim v1 applied: owner symmetry, checked reclaim, quarantine, module contract gate")


if __name__ == "__main__":
    main()
