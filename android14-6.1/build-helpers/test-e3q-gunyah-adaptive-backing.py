#!/usr/bin/env python3
"""Offline regression tests for the exact post-baseline adaptive transformation."""
from pathlib import Path
from contextlib import contextmanager
import importlib.util
import hashlib
import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "adaptive", HERE / "patch-e3q-gunyah-adaptive-backing.py")
adaptive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adaptive)


@contextmanager
def fixture_directory(prefix):
    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix=prefix) as directory:
            yield directory
        return
    # Windows restricted-token hosts cannot reopen Python's mode-0700 temp dirs.
    # Use inherited permissions in an explicitly chosen test-only parent instead.
    parent = Path(os.environ.get("E3Q_TEST_TEMP_ROOT", tempfile.gettempdir())).resolve()
    directory = parent / (prefix + uuid.uuid4().hex)
    directory.mkdir(mode=0o755)
    try:
        yield str(directory)
    finally:
        resolved = directory.resolve()
        if resolved.parent != parent or not resolved.name.startswith(prefix) or directory.is_symlink():
            raise RuntimeError(f"unsafe test cleanup path: {directory}")
        shutil.rmtree(resolved)


def baseline():
    generator = (HERE / "apply-e3q-gunyah-cma-compat.sh").read_text()
    # This is exactly the generator fetched by the active immutable baseline.
    expected = "8e366c8e439d6f24c5ca913214c6de8c2425c6b67091f83a77aea92b86ca38e8"
    if hashlib.sha256(generator.encode()).hexdigest() != expected:
        raise ValueError("fixture generator differs from pinned 069aeb35 baseline")
    source = generator.split("<<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0] + "\n"
    # Exact ownership-reference transform from the pinned f314a327 QCOM helper.
    source = adaptive.replace_once(source, "\tunsigned long nr_pages;\n\n",
                                    "\tunsigned long nr_pages;\n\tunsigned long i;\n\n")
    return adaptive.replace_once(source,
        "\tif (chunk->contig)\n\t\tfree_contig_range(page_to_pfn(chunk->base), nr_pages);\n"
        "\telse\n\t\t__free_pages(chunk->base, chunk->order);",
        "\tif (chunk->contig) {\n\t\tfor (i = 0; i < nr_pages; i++)\n"
        "\t\t\t__free_page(nth_page(chunk->base, i));\n\t} else {\n"
        "\t\t__free_pages(chunk->base, chunk->order);\n\t}")


def required_order(remaining, slots):
    if not remaining or not slots:
        raise ValueError("empty page/slot budget")
    average = (remaining + slots - 1) // slots
    order = 0
    while (1 << order) < average and order < 6:
        order += 1
    return order


def allocate_model(pages, largest_available_order, seed=0):
    remaining, chunks = pages, 0
    capacity = min(pages, 8192)
    randomizer = random.Random(seed)
    while remaining:
        if chunks >= capacity:
            return False, chunks
        slots = capacity - chunks
        order = required_order(remaining, slots)
        if order > largest_available_order or (1 << order) > remaining:
            return False, chunks
        maximum = min(6, remaining.bit_length() - 1, largest_available_order)
        order = randomizer.randint(order, maximum)
        remaining -= 1 << order
        chunks += 1
        assert remaining >= 0 and chunks <= capacity <= 8192
    return True, chunks


class Tests(unittest.TestCase):
    def test_transform_and_idempotence(self):
        result = adaptive.transform(baseline())
        adaptive.validate(result)
        self.assertEqual(adaptive.transform(result), result)

    def test_safety_and_unrelated_code_preserved(self):
        original = baseline()
        result = adaptive.transform(original)
        for start, end in (("static void gh_extent_free_one", "static void gh_extent_free_chunks"),
                           ("static int gh_extent_release", "long gh_cma_compat_create_mem_fd")):
            self.assertEqual(original[original.index(start):original.index(end)],
                             result[result.index(start):result.index(end)])
        self.assertEqual(re.findall(r"const gfp_t gfp = .*?;", original, re.S),
                         re.findall(r"const gfp_t gfp = .*?;", result, re.S))
        self.assertIn("if (!size || !PAGE_ALIGNED(size) || size > SZ_512M)", result)
        self.assertNotIn("free_contig_range(page_to_pfn(chunk->base), nr_pages)", result)

    def test_fail_closed_on_unfinished_or_changed_baseline(self):
        with self.assertRaises(ValueError):
            adaptive.transform(baseline().replace("__free_page(nth_page(chunk->base, i));", "unsafe();"))
        with self.assertRaises(ValueError):
            adaptive.transform(baseline().replace("#define GH_EXTENT_LIMIT 8192UL", "#define GH_EXTENT_LIMIT 16384UL"))
        with self.assertRaises(ValueError):
            adaptive.transform(baseline().replace("gh_extent_alloc_buddy(remaining, &order)", "changed_call()"))

    def test_request_abi_unchanged(self):
        original, result = baseline(), adaptive.transform(baseline())
        # Compare the actual pre-allocation validation code, not just a model.
        start, end = "\tif (copy_from_user(&size", "\tbuf = kzalloc("
        old_checks = original[original.index(start):original.index(end)]
        new_checks = result[result.index(start):result.index(end)]
        self.assertEqual(old_checks.replace("GH_EXTENT_MIN_PAGES", "GH_EXTENT_ABI_MIN_PAGES"), new_checks)
        old_pages = 1 << int(re.search(r"#define GH_EXTENT_MIN_ORDER (\d+)U", original)[1])
        new_pages = int(re.search(r"#define GH_EXTENT_ABI_MIN_PAGES (\d+)UL", result)[1])
        for pages in range(0, 131073):
            old_accepts = pages > 0 and pages % old_pages == 0 and (pages + old_pages - 1) // old_pages <= 8192
            new_accepts = pages > 0 and pages % new_pages == 0 and (pages + new_pages - 1) // new_pages <= 8192
            self.assertEqual(old_accepts, new_accepts)
        self.assertEqual(required_order(32768, 8192), 2)  # 128 MiB -> 16 KiB.
        self.assertEqual(required_order(65536, 8192), 3)  # 256 MiB -> 32 KiB.

    def test_fragmented_128_and_256_mib_limits(self):
        self.assertEqual(allocate_model(32768, 2), (True, 8192))
        self.assertEqual(allocate_model(65536, 3), (True, 8192))
        self.assertEqual(allocate_model(65536, 2), (False, 0))
        self.assertEqual(allocate_model(32768, 1), (False, 0))
        self.assertEqual(required_order(51496, 8192 - 865), 3)

    def test_random_allocation_sequences(self):
        for pages in (8, 24, 512, 2048, 8192, 16384, 32768, 49152, 65536):
            for seed in range(20):
                success, chunks = allocate_model(pages, 6, seed)
                self.assertTrue(success, (pages, seed, chunks))
                self.assertLessEqual(chunks, 8192)

    def test_cli_preserves_parcel_guard_and_refuses_missing_guard(self):
        with fixture_directory("e3q-adaptive-test-") as temp:
            root = Path(temp)
            directory = root / "drivers/virt/gunyah"
            directory.mkdir(parents=True)
            backing = directory / "cma_compat.c"
            vm = directory / "vm_mgr.c"
            backing.write_text(baseline())
            guard = "if (mapping->parcel.n_mem_entries > 8192) { return -E2BIG; }\n"
            vm.write_text(guard)
            command = [os.sys.executable, str(HERE / "patch-e3q-gunyah-adaptive-backing.py"), str(root)]
            subprocess.run(command, check=True, capture_output=True)
            first = backing.read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(backing.read_bytes(), first)
            self.assertEqual(vm.read_text(), guard)
            vm.write_text("/* absent guard */\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(backing.read_bytes(), first)

    def test_compile_exact_c_order_function(self):
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
        if not compiler:
            if os.environ.get("CI"):
                self.fail("CI must compile and execute the exact C budget function")
            self.skipTest("no local C compiler; required in CI")
        source = adaptive.transform(baseline())
        start = source.index("static unsigned int gh_extent_required_order(")
        end = source.index("static struct page *gh_extent_alloc_buddy", start)
        harness = """#include <assert.h>
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define GH_EXTENT_MAX_ORDER 6U
""" + source[start:end] + """
int main(void) {
    unsigned long pages, slots;
    assert(gh_extent_required_order(32768, 8192) == 2);
    assert(gh_extent_required_order(65536, 8192) == 3);
    for (pages = 1; pages <= 65536; pages++) {
        for (slots = 1; slots <= 8192; slots = slots * 2 + 1) {
            unsigned long avg = DIV_ROUND_UP(pages, slots);
            unsigned int order = gh_extent_required_order(pages, slots);
            assert(order <= 6);
            if (avg <= 64) {
                assert((1UL << order) >= avg);
                assert(order == 0 || (1UL << (order - 1)) < avg);
            }
        }
    }
    return 0;
}
"""
        with fixture_directory("e3q-adaptive-c-") as temp:
            root = Path(temp)
            code, binary = root / "budget.c", root / "budget-test"
            code.write_text(harness)
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(code), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
