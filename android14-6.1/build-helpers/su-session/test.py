#!/usr/bin/env python3
"""Compile and execute the actual patched C functions with kernel API fault mocks."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
from unittest.mock import patch as mock_patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("su_session_apply", HERE / "apply.py")
port = importlib.util.module_from_spec(spec)
spec.loader.exec_module(port)


def extract(text, name, array=False):
    # Mask comments and literals without changing offsets or line boundaries.
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    masked = re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m[0]), text, flags=re.S)
    signature = (r"^static const struct ksu_ioctl_cmd_map " + name + r"\[\]\s*=\s*\{") if array else (
        r"^(?:static\s+)?(?:inline\s+)?(?:int|bool|long|void)\s+" + name + r"\([^;{]*\)\s*\{")
    matches = list(re.finditer(signature, masked, re.M))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one definition of {name}, found {len(matches)}")
    match = matches[0]
    pos = match.end()
    depth = 1
    while depth:
        depth += (masked[pos] == "{") - (masked[pos] == "}")
        pos += 1
    if array:
        assert text[pos] == ";"
        pos += 1
    return text[match.start():pos]


def sources(common, ksu):
    read = lambda name: (ksu / name).read_text(encoding="utf-8")
    compat = read("kernel/feature/sucompat.c")
    supercall = read("kernel/supercall/supercall.c")
    dispatch = read("kernel/supercall/dispatch.c")
    header = read("kernel/supercall/supercall.h")
    table = extract(dispatch, "ksu_ioctl_handlers", array=True)
    commands = re.findall(r"\.cmd\s*=\s*(KSU_IOCTL_\w+)", table)
    handlers = [n for n in re.findall(r"\.handler\s*=\s*(\w+)", table) if n != "NULL"]
    values = {
        "PROFILE": extract(read("kernel/policy/app_profile.c"), "escape_with_root_profile"),
        "SUCOMPAT": "\n\n".join(extract(compat, n) for n in (
            "do_ksu_handle_execveat_sucompat", "ksu_handle_execveat_init", "ksu_handle_execve_common",
            "ksu_handle_execve", "ksu_handle_execveat", "ksu_handle_execveat_su_session", "ksu_handle_execveat_sucompat")),
        "INSTALL": "\n\n".join(extract(supercall, n) for n in (
            "ksu_install_fd_with_context", "ksu_install_fd", "ksu_install_su_fd", "ksu_is_su_session_fd")),
        "DISPATCH_STUBS": "\n".join(f"#define {n} {i+1}" for i, n in enumerate(commands)) + "\n" +
            "\n".join(f"static int {n}(void *p) {{ return 123; }}" for n in handlers),
        "SUPERCALL_TYPES": "\n".join(re.findall(r"^typedef .*;$", header, re.M)) + "\n" +
            re.search(r"struct ksu_ioctl_cmd_map \{.*?\};", header, re.S)[0],
        "DISPATCH": table + "\n" + extract(dispatch, "ksu_supercall_handle_ioctl"),
        "WRAPPER": extract(read("kernel/infra/file_wrapper.c"), "ksu_install_file_wrapper"),
        "EXEC": extract((common / "fs/exec.c").read_text(), "do_execveat_common"),
    }
    template = (HERE / "harness.c.in").read_text()
    for name, code in values.items():
        assert template.count(f"@@{name}@@") == 1
        template = template.replace(f"@@{name}@@", code)
    assert "@@" not in template
    return template


def run(command):
    result = subprocess.run([str(c) for c in command], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command[0]}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def webview_sources(ksu):
    policy = (ksu / "kernel/policy/allowlist.c").read_text()
    umount = (ksu / "kernel/feature/kernel_umount.c").read_text()
    setuid = (ksu / "kernel/hook/setuid_hook.c").read_text()
    values = {"VALID": extract(policy, "profile_valid"),
              "POLICY": extract(policy, "ksu_uid_should_umount"),
              "SET_POLICY": extract(policy, "ksu_set_webview_zygote_umount"),
              "FEATURE": extract(umount, "webview_zygote_umount_feature_get") + "\n" + extract(umount, "webview_zygote_umount_feature_set"),
              "UMOUNT": extract(umount, "ksu_handle_umount"),
              "NEXT": extract(setuid, "handle_zygote_next_setresuid"),
              "SETUID": extract(setuid, "ksu_handle_setuid"),
              "PRUNE": extract(policy, "ksu_prune_allowlist")}
    text = (HERE / "webview.c.in").read_text()
    for key, value in values.items():
        assert text.count(f"@@{key}@@") == 1
        text = text.replace(f"@@{key}@@", value)
    return text


def compile_run(code, name, args, root, expect_failure=False):
    src = root / f"{name}.c"
    src.write_text(code, encoding="utf-8", newline="\n")
    base = [args.cc, "-std=gnu11", "-O1", "-fno-builtin", "-Werror=implicit-function-declaration"]
    if args.wasm:
        binary = root / f"{name}.wasm"
        run(base + ["--target=wasm32", "-DWASM_TEST", "-nostdlib", "-Wl,--no-entry",
                    "-Wl,--export=test_main", "-Wl,--export=test_count", src, "-o", binary])
        runner = root / "run.cjs"
        runner.write_text("const fs=require('fs'); WebAssembly.instantiate(fs.readFileSync(process.argv[2]), {}).then(({instance})=>{"
                          "let line=instance.exports.test_main(); console.log(JSON.stringify({failure_line:line,checks:instance.exports.test_count()}));"
                          "}).catch(e=>{console.error(e);process.exit(1)});\n")
        result = json.loads(run([args.node, runner, binary]))
        failed = result["failure_line"] != 0
        if failed != expect_failure:
            raise RuntimeError(f"{name}: unexpected C test result {result}")
        print(f"{name}: {result['checks']} checks, failure_line={result['failure_line']}"
              + (" (expected mutation rejection)" if expect_failure else ""))
        return result
    binary = root / name
    run(base + [src, "-o", binary])
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    if bool(result.returncode) != expect_failure:
        raise RuntimeError(f"{name}: {result.stdout}\n{result.stderr}")
    print(f"{name}: {result.stdout.strip()}" + (" (expected mutation rejection)" if expect_failure else ""))
    return {"output": result.stdout.strip()}


def expect_reject(call, label):
    try:
        call()
    except RuntimeError:
        print(f"application: {label} rejected")
        return
    raise RuntimeError(f"Expected rejection: {label}")


def fixture_and_application_checks(common, ksu, root):
    targets = [(ksu, root / "ksu", HERE / "resukisu-35119-su-session.patch"),
               (common, root / "common", HERE / "gki-6.1-su-session.patch")]
    for original, fixture, patch in targets:
        fixture.mkdir()
        port.git(fixture, "init", "--quiet")
        for name in re.findall(r"^\+\+\+ b/(.+)$", patch.read_text(), re.M):
            dest = fixture / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((original / name).read_text(), encoding="utf-8", newline="\n")
        # Accept pristine or fully patched input, but always exercise application.
        if port.patch_state(fixture, patch) == "applied":
            port.git(fixture, "apply", "--reverse", "--whitespace=nowarn", str(patch))
    kc, cc = root / "ksu", root / "common"
    expect_reject(lambda: port.validate_identity(cc, kc, port.SUSFS_PIN), "missing/wrong ReSukiSU HEAD")
    expect_reject(lambda: port.apply_pair(cc, kc, True), "verify on unapplied sources")
    originals = {p: p.read_bytes() for r in (cc, kc) for p in r.rglob("*.c")}
    real_git = port.git
    def failed_second_apply(where, *args, **kwargs):
        if where == cc and args[:2] == ("apply", "--whitespace=nowarn"):
            raise RuntimeError("Injected failure applying second tree")
        return real_git(where, *args, **kwargs)
    with mock_patch.object(port, "git", side_effect=failed_second_apply):
        expect_reject(lambda: port.apply_pair(cc, kc), "injected second-tree write failure")
    assert all(p.read_bytes() == data for p, data in originals.items())
    print("application: rollback restored both source trees byte-for-byte")
    assert port.apply_pair(cc, kc) == "applied"
    assert port.apply_pair(cc, kc) == "already applied"
    assert port.apply_pair(cc, kc, True) == "already applied"
    print("application: clean apply, repeat apply and verify-only passed")
    kernel_patch = HERE / "gki-6.1-su-session.patch"
    port.git(cc, "apply", "--reverse", str(kernel_patch))
    before = (cc / "fs/exec.c").read_bytes()
    expect_reject(lambda: port.apply_pair(cc, kc), "partial cross-tree application")
    assert before == (cc / "fs/exec.c").read_bytes()
    port.git(cc, "apply", str(kernel_patch))
    path = kc / "kernel/supercall/supercall.c"
    before = path.read_bytes()
    path.write_bytes(before.replace(b"ksu_su_session_cookie", b"corrupted_cookie"))
    expect_reject(lambda: port.apply_pair(cc, kc), "source drift")
    path.write_bytes(before)
    return cc, kc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", type=Path, required=True)
    parser.add_argument("--ksu", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--wasm", action="store_true", help="Run freestanding C as WebAssembly under Node on Windows")
    parser.add_argument("--node", default="node")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--aarch64-check", action="store_true", help="Also compile the actual C harness for the 64-bit target")
    args = parser.parse_args()
    head = port.git(args.ksu, "rev-parse", "HEAD").stdout.strip()
    if head != port.RESUKISU_PIN:
        parser.error(f"Expected ReSukiSU {port.RESUKISU_PIN}, got {head}")
    root = args.work_dir.resolve() / ("su-session-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    common, ksu = fixture_and_application_checks(args.common, args.ksu, root)
    code = sources(common, ksu)
    result = compile_run(code, "production", args, root)
    webview = webview_sources(ksu)
    webview_result = compile_run(webview, "webview", args, root)
    policy_disabled = compile_run("#define CONFIG_KSU_DISABLE_POLICY 1\n" + webview, "webview-policy-disabled", args, root)
    if args.aarch64_check:
        run([args.cc, "--target=aarch64-linux-android", "-DWASM_TEST", "-ffreestanding", "-fno-builtin",
             "-std=gnu11", "-Werror=implicit-function-declaration", "-c", root / "production.c", "-o", root / "production-aarch64.o"])
        print("production: AArch64 object compilation passed")
        run([args.cc, "--target=aarch64-linux-android", "-DWASM_TEST", "-ffreestanding", "-fno-builtin",
             "-std=gnu11", "-Werror=implicit-function-declaration", "-c", root / "webview.c", "-o", root / "webview-aarch64.o"])
        print("webview: AArch64 object compilation passed")
    mutations = {
        "mutant-exec-failure": ("is_su_session && retval >= 0", "is_su_session"),
        "mutant-unscoped-permissions": ("ksu_ioctl_handlers[i].allow_su_session && ksu_is_su_session_fd(filp)", "ksu_is_su_session_fd(filp)"),
        "mutant-ucounts-failure": ("ret = set_cred_ucounts(cred);", "set_cred_ucounts(cred);"),
        "mutant-missing-revert": ("revert_creds(old_cred);", "/* omitted revert */"),
    }
    for name, (old, new) in mutations.items():
        assert code.count(old) == 1, name
        compile_run(code.replace(old, new), name, args, root, expect_failure=True)
    # Moving installation ahead of bprm_execve would lose it during CLOEXEC cleanup.
    old = "retval = bprm_execve(bprm, fd, filename, flags);"
    moved = code.replace(old, "retval = 0;")
    marker = "out_free:\n"
    assert moved.count(marker) == 1
    moved = moved.replace(marker, old + "\n" + marker)
    compile_run(moved, "mutant-premature-install", args, root, expect_failure=True)
    web_mutations = {
        "mutant-webview-prune": (" || uid == WEBVIEW_ZYGOTE_UID;", ";"),
        "mutant-boot-overwrite": ("if (!READ_ONCE(ksu_boot_completed))", "if (false)"),
        "mutant-webview-zygote-next": ("if (ksu_uid_should_umount(new_uid))", "if (false)"),
        "mutant-webview-root-profile": ("profile->allow_su || strcmp(profile->key", "false || strcmp(profile->key"),
    }
    for name, (old, new) in web_mutations.items():
        assert webview.count(old) == 1, name
        compile_run(webview.replace(old, new), name, args, root, expect_failure=True)
    (root / "result.json").write_text(json.dumps({"base": head, "production": result,
        "webview": webview_result, "webview_policy_disabled": policy_disabled,
        "mutations_rejected": 9, "aarch64_object": args.aarch64_check,
        "limitation": "Mocks verify control flow and cleanup; no complete kernel build or device test."}, indent=2) + "\n")
    print(f"PASS: application gates, exact-C fault tests and nine mutation controls; results: {root}")


if __name__ == "__main__":
    main()
