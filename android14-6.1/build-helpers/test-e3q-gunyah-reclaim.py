#!/usr/bin/env python3
"""Transformation checks plus compiled exact-C ownership fault injection."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("reclaim", HERE / "patch-e3q-gunyah-reclaim.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
ASSETS = HERE / "gunyah-reclaim"
parser = argparse.ArgumentParser()
parser.add_argument("--kernel", type=Path)
args, unittest_args = parser.parse_known_args()


def baseline():
    result = {p.name: p.read_text() for p in (ASSETS / "fixtures").glob("*") if p.suffix in (".c", ".h")}
    expected = json.loads((ASSETS / "fixtures/sha256.json").read_text())
    assert {n: hashlib.sha256(t.encode()).hexdigest() for n, t in result.items()} == expected
    return result


def exact_c(files):
    parts = [(ASSETS / "test-shim.h").read_text(), files["e3q_mem_reclaim.h"]]
    for name, signature in (
        ("gunyah_qcom.c", "static int qcom_scm_gh_rm_restore("),
        ("gunyah_qcom.c", "static int qcom_scm_gh_rm_pre_mem_share("),
        ("gunyah_qcom.c", "static int qcom_scm_gh_rm_post_mem_reclaim("),
        ("gunyah_platform_hooks.c", "int gh_rm_platform_pre_mem_share("),
        ("gunyah_platform_hooks.c", "int gh_rm_platform_post_mem_reclaim("),
        ("rsc_mgr_rpc.c", "int gh_rm_mem_reclaim("),
        ("rsc_mgr_rpc.c", "static int gh_rm_mem_lend_common("),
        ("vm_mgr_mm.c", "static bool gh_vm_mem_reclaim_mapping("),
    ):
        parts.append(patch.function(files[name], signature))
    parts.append((ASSETS / "test-main.c").read_text())
    return "\n\n".join(parts)


class Tests(unittest.TestCase):
    def test_transformation_idempotent(self):
        fixed = patch.transform(baseline())
        self.assertEqual(patch.transform(fixed), fixed)

    def test_partial_patch_rejected(self):
        source = baseline()
        source["vm_mgr.c"] = patch.MARKER + source["vm_mgr.c"]
        with self.assertRaises(ValueError):
            patch.transform(source)

    def test_body_drift_rejected(self):
        fixed = patch.transform(baseline())
        fixed["gunyah_qcom.c"] = fixed["gunyah_qcom.c"].replace("E3Q_POISON(mem_parcel) = 1;", "E3Q_POISON(mem_parcel) = 0;")
        with self.assertRaises(ValueError):
            patch.transform(fixed)

    def test_original_pin_flags_and_safety_guard_preserved(self):
        source = baseline()
        fixed = patch.transform(source)
        for token in ("gup_flags = FOLL_LONGTERM;", "gup_flags |= FOLL_WRITE;", "pin_user_pages_fast("):
            self.assertIn(token, fixed["vm_mgr_mm.c"])
        for token in ("mapping->parcel.n_mem_entries > 8192", "GH_DIAG mem_share begin"):
            self.assertIn(token, fixed["vm_mgr.c"])
        self.assertIn("#define GH_RM_MAX_MEM_ENTRIES\t512", fixed["rsc_mgr_rpc.c"])

    def test_quarantine_retains_lifetime_and_blocks_start(self):
        fixed = patch.transform(baseline())
        free = patch.function(fixed["vm_mgr.c"], "static void gh_vm_free(struct work_struct *work)\n{")
        self.assertLess(free.index("gh_vm_mem_reclaim(ghvm)"), free.index("list_add_tail"))
        self.assertLess(free.index("list_add_tail"), free.index("gh_rm_dealloc_vmid"))
        self.assertIn("return;", free[free.index("list_add_tail"):free.index("gh_rm_dealloc_vmid")])
        self.assertIn("gh_vm_mem_is_blocked()", fixed["vm_mgr.c"])

    def test_exact_compiled_c(self):
        cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
        if not cc:
            if os.environ.get("CI"):
                self.fail("C compiler is mandatory for reclaim preflight")
            self.skipTest("No local C compiler; exact C is mandatory in CI")
        files = patch.transform(baseline())
        if args.kernel:
            root = args.kernel / "drivers/virt/gunyah"
            files = {name: (root / name).read_text() for name in files}
            patch.validate(files)
        with tempfile.TemporaryDirectory(prefix="e3q-reclaim-") as tmp:
            c = Path(tmp) / "test.c"
            exe = Path(tmp) / "test"
            c.write_text(exact_c(files))
            subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(c), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main(argv=[__file__] + unittest_args, verbosity=2)
