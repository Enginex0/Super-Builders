#!/usr/bin/env python3
"""Run exact production UID-policy C, source and Image-attestation regression tests.

Host/wasm tests use credential mocks; they are not device or full-kernel tests.
"""
import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("uidgate", HERE / "apply.py")
port = importlib.util.module_from_spec(spec)
spec.loader.exec_module(port)


def rejected(callback):
    try:
        callback()
    except (RuntimeError, ValueError, OSError):
        return
    raise RuntimeError("Mutation unexpectedly accepted")


def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Command failed: {command[0]}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def harness(header, enabled):
    # Only substitute the kernel credential API; compile the literal shipped
    # header, including its CONFIG-dependent policy and current-UID wrapper.
    return ("#define bool _Bool\n#define true 1\n#define false 0\n"
            "static unsigned int mock_uid;\n"
            "typedef struct { unsigned int val; } kuid_t;\n"
            "static kuid_t current_uid(void) { return (kuid_t){mock_uid}; }\n"
            + ("#define CONFIG_KSU_SUSFS_UID_GATED_HIDING 1\n" if enabled else "")
            + header.replace("#include <linux/cred.h>", "") + "\n"
            + r'''
static int checks;
#define CHECK(x) do { ++checks; if (!(x)) return __LINE__; } while (0)
int test_count(void) { return checks; }
int test_main(void)
{
	unsigned int user, appid, flag, registered, owner;
	const unsigned int users[] = {0, 1, 10, 999, 21474};
	const unsigned int ids[] = {0, 1, 1000, 2000, 9999, 10000, 19999,
		20000, 29999, 89999, 90000, 98999, 99000, 99999};
	checks = 0;
	for (user = 0; user < sizeof(users)/sizeof(users[0]); ++user) {
		for (appid = 0; appid < sizeof(ids)/sizeof(ids[0]); ++appid) {
			bool expected = true;
			mock_uid = users[user] * 100000U + ids[appid];
#ifdef CONFIG_KSU_SUSFS_UID_GATED_HIDING
			expected = ids[appid] >= 10000U;
#endif
			CHECK(susfs_uid_gate_for_uid(mock_uid) == expected);
			CHECK(susfs_uid_gate_current() == expected);
			/* Additional restriction must never grant hiding by itself. */
			for (flag = 0; flag < 2; ++flag)
				for (registered = 0; registered < 2; ++registered)
					for (owner = 0; owner < 2; ++owner) {
						bool baseline = flag && registered && !owner;
						CHECK((susfs_uid_gate_current() && baseline) ==
						      (expected && baseline));
					}
		}
	}
	/* Credential transitions are evaluated at the consumer, not cached. */
	mock_uid = 110000U;
	CHECK(susfs_uid_gate_current());
	mock_uid = 101000U;
#ifdef CONFIG_KSU_SUSFS_UID_GATED_HIDING
	CHECK(!susfs_uid_gate_current());
	CHECK(!susfs_uid_gate_for_uid((unsigned int)-1));
#else
	CHECK(susfs_uid_gate_current());
	CHECK(susfs_uid_gate_for_uid((unsigned int)-1));
#endif
	return 0;
}
#ifndef WASM_TEST
int main(void) { return test_main() ? 1 : 0; }
#endif
''')


def compile_run(code, name, args, expect_failure=False):
    source = args.work_dir / (name + ".c")
    source.write_text(code, encoding="utf-8", newline="\n")
    base = [args.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if args.wasm:
        output = args.work_dir / (name + ".wasm")
        run(base + ["--target=wasm32", "-DWASM_TEST", "-nostdlib", "-Wl,--no-entry",
                    "-Wl,--export=test_main", "-Wl,--export=test_count", source, "-o", output])
        runner = args.work_dir / "run.cjs"
        runner.write_text("const fs=require('fs'); WebAssembly.instantiate(fs.readFileSync(process.argv[2]),{}).then(({instance})=>{"
                          "console.log(JSON.stringify({line:instance.exports.test_main(),checks:instance.exports.test_count()}));"
                          "}).catch(e=>{console.error(e);process.exit(1)});\n")
        result = json.loads(run([args.node, runner, output]))
        failed = result["line"] != 0
    else:
        output = args.work_dir / name
        run(base + [source, "-o", output])
        completed = subprocess.run([str(output)], capture_output=True, text=True)
        failed = completed.returncode != 0
        result = {"exit": completed.returncode}
    if failed != expect_failure:
        raise RuntimeError(f"{name}: unexpected exact-C result {result}")
    if args.aarch64_check:
        run(base + ["--target=aarch64-linux-android", "-DWASM_TEST", "-ffreestanding",
                    "-c", source, "-o", args.work_dir / (name + "-arm64.o")])
    return result


def consumer_harness(common, header):
    boot = (common / "fs/proc/bootconfig.c").read_text()
    a, b = port.body_span(boot, "boot_config_proc_show")
    defs = (common / "include/linux/susfs_def.h").read_text()
    c, d = port.body_span(defs, "susfs_is_current_proc_umounted_app")
    macro = re.search(r"#define SUSFS_IS_INODE_SUS_MAP\(inode\).*?(?=\n\n)", defs, re.S)[0]
    return ("#define bool _Bool\n#define true 1\n#define false 0\n"
            "#define CONFIG_KSU_SUSFS_UID_GATED_HIDING 1\n"
            "#define CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG 1\n"
            "static unsigned int mock_uid;\n"
            "typedef struct { unsigned int val; } kuid_t;\n"
            "static kuid_t current_uid(void) { return (kuid_t){mock_uid}; }\n"
            + header.replace("#include <linux/cred.h>", "") + r'''
struct seq_file { const char *output; };
static char *saved_boot_config = "original";
static bool susfs_is_fake_cmdline_or_bootconfig_buffer_set = true;
#define static_branch_likely(p) (*(p))
#define static_key_enabled(p) (*(p))
static void seq_puts(struct seq_file *m, const char *s) { m->output = s; }
static void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m) { m->output = "fake"; }
static int boot_config_proc_show(struct seq_file *m, void *v __attribute__((unused)))
''' + boot[a:b] + r'''
#define likely(x) (x)
#define unlikely(x) (x)
#define TIF_PROC_UMOUNTED 1
static bool unmounted;
static bool test_thread_flag(int flag) { return flag == TIF_PROC_UMOUNTED && unmounted; }
static bool susfs_is_current_proc_umounted_app(void)
''' + defs[c:d] + r'''
#define AS_FLAGS_SUS_MAP 1
struct address_space { unsigned long flags; };
struct inode { struct address_space *i_mapping; };
static bool test_bit(int bit, unsigned long *flags) { return !!(*flags & (1UL << bit)); }
''' + macro + r'''
static int checks;
#define CHECK(x) do { ++checks; if (!(x)) return __LINE__; } while (0)
int test_count(void) { return checks; }
int test_main(void)
{
	struct seq_file m = {0};
	struct address_space mapping = {1UL << AS_FLAGS_SUS_MAP};
	struct inode inode = {&mapping};
	struct inode *node = &inode;
	unsigned int i;
	const unsigned int ids[] = {0, 1000, 2000, 100000, 101000, 102000, 110000};
	checks = 0;
	unmounted = true;
	for (i = 0; i < sizeof(ids)/sizeof(ids[0]); ++i) {
		mock_uid = ids[i];
		CHECK(boot_config_proc_show(&m, 0) == 0);
		CHECK(m.output && m.output[0] == (i == 6 ? 'f' : 'o'));
		CHECK(!!(SUSFS_IS_INODE_SUS_MAP(node)) == (i == 6));
	}
	/* Read-time credential transition, and existing policy still required. */
	mock_uid = 0;
	CHECK(boot_config_proc_show(&m, 0) == 0 && m.output[0] == 'o');
	mock_uid = 110000;
	susfs_is_fake_cmdline_or_bootconfig_buffer_set = false;
	CHECK(boot_config_proc_show(&m, 0) == 0 && m.output[0] == 'o');
	unmounted = false;
	CHECK(!(SUSFS_IS_INODE_SUS_MAP(node)));
	unmounted = true;
	mapping.flags = 0;
	CHECK(!(SUSFS_IS_INODE_SUS_MAP(node)));
	node = 0;
	CHECK(!(SUSFS_IS_INODE_SUS_MAP(node)));
	return 0;
}
#ifndef WASM_TEST
int main(void) { return test_main() ? 1 : 0; }
#endif
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", type=Path)
    parser.add_argument("--ksu", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--wasm", action="store_true")
    parser.add_argument("--node", default="node")
    parser.add_argument("--aarch64-check", action="store_true")
    args = parser.parse_args()
    if bool(args.common) != bool(args.ksu):
        parser.error("--common and --ksu must be used together")
    args.work_dir = args.work_dir.resolve()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    header = (HERE / "susfs_uid_gate.h").read_text()
    results = {"kind": "mocked exact production C; not a device test", "exact_c": {}}
    for enabled in (False, True):
        name = "enabled" if enabled else "disabled"
        results["exact_c"][name] = compile_run(harness(header, enabled), name, args)
    mutations = {
        "multiuser-system-leak": ("uid % 100000U", "uid"),
        "off-by-one": (">= 10000U", "> 10000U"),
        "invalid-uid": ("uid != (unsigned int)-1 && ", ""),
    }
    for name, (old, new) in mutations.items():
        changed = port.once(header, old, new, name)
        results["exact_c"][name] = compile_run(harness(changed, True), name, args, expect_failure=True)

    # Attestation must reject a config-only claim, a missing feature string,
    # a disabled embedded config, duplicate settings, and an unmarked Image.
    valid = port.SYMBOL + "=y\nCONFIG_KSU_SUSFS=y\n"
    port.require_config(valid)
    for invalid in (valid.replace("=y", "=n"), valid + valid, valid + "# " + port.SYMBOL + " is not set\n", ""):
        rejected(lambda: port.require_config(invalid))
    config = args.work_dir / "test.config"
    image = args.work_dir / "test.Image"
    config.write_text(valid)
    def fake_image(cfg, feature=True):
        return (b"IKCFG_ST" + gzip.compress(cfg.encode()) + b"IKCFG_ED" +
                (port.SYMBOL.encode() + b"\n\0" if feature else b""))
    image.write_bytes(fake_image(valid))
    port.attest({}, config, image)
    for blob in (b"", fake_image(valid, False), fake_image(valid.replace("=y", "=n")),
                 fake_image(valid) + fake_image(valid)):
        image.write_bytes(blob)
        rejected(lambda: port.attest({}, config, image))
    sample = 'bool f(int n)\n{ /* } */ if(n) { return true; } return false; }'
    start, end = port.body_span(sample, "f")
    assert sample[start:end].startswith("{") and sample[end-1] == "}"
    rejected(lambda: port.body_span(sample + "\n" + sample, "f"))
    rejected(lambda: port.once("anchor anchor", "anchor", "changed", "test"))
    results["attestation_negative_cases"] = 8

    if args.common:
        state = port.verify(args.common, args.ksu)
        assert port.apply(args.common, args.ksu) == state  # Verified no-op.
        files = port.read_tree(args.common, args.ksu)
        for path, name in state["scopes"]:
            a, b = port.body_span(files[path], name)
            changed = dict(files)
            changed[path] = files[path][:a+1] + " /* drift */ " + files[path][a+1:]
            assert port.scope_hashes(changed, state["scopes"]) != state["scope_sha256"]
        results["source_scopes_checked"] = len(state["scopes"])
        results["protected_thread_and_redirect_functions"] = sum(map(len, port.PROTECTED.values()))
        consumer_code = consumer_harness(args.common, header)
        results["exact_c"]["bootconfig-and-sus-map"] = compile_run(consumer_code, "consumers", args)
        # The config-only tests would not catch this empty-procfile regression.
        wrong_fallback = port.once(consumer_code, "seq_puts(m, saved_boot_config);", "seq_puts(m, \"\");", "bootconfig fallback")
        results["exact_c"]["empty-bootconfig"] = compile_run(wrong_fallback, "empty-bootconfig", args, expect_failure=True)
    (args.work_dir / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    print("PASS: UID gate exact-C, credential boundaries, mutation and Image-attestation tests")


if __name__ == "__main__":
    main()
