#!/usr/bin/env python3
"""Execute actual generated C with kernel-API fault mocks; never a device test."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("session35137",HERE/"apply.py")
port=importlib.util.module_from_spec(spec)
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
            "ksu_handle_execve", "ksu_handle_execveat", "ksu_handle_execveat_su_session", "ksu_handle_execveat_sucompat",
            "ksu_handle_post_execve")),
        "INSTALL": "\n\n".join(extract(supercall, n) for n in (
            "ksu_install_fd_with_permissions", "ksu_install_fd", "ksu_install_su_fd", "ksu_is_su_session_fd")),
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
    policy=(ksu/"kernel/policy/allowlist.c").read_text()
    setuid=(ksu/"kernel/hook/setuid_hook.c").read_text()
    values={"VALID":extract(policy,"profile_valid"),
            "POLICY":extract(policy,"ksu_uid_should_umount"),
            "NEXT":extract(setuid,"handle_zygote_next_setresuid"),
            "PRUNE":extract(policy,"ksu_prune_allowlist")}
    text=(HERE/"webview.c.in").read_text()
    for key, value in values.items():
        assert text.count(f"@@{key}@@")==1
        text=text.replace(f"@@{key}@@",value)
    return text


def kstat_sources(common):
    header=(common/"include/linux/susfs.h").read_text()
    source=(common/"fs/susfs.c").read_text()
    layout="\n".join(re.findall(r"^#define KSTAT_SPOOF_[^\n]+",header,re.M))
    for name in ("st_susfs_sus_kstat", "st_susfs_sus_kstat_hlist", "st_susfs_sus_kstat_redirect"):
        layout += "\n" + re.search(r"^struct "+name+r" \{.*?^};",header,re.M|re.S)[0]
    values={"LAYOUT":layout,
            "REGISTRATION":"\n".join(extract(source,n) for n in ("susfs_prepare_redirect_entry","susfs_add_sus_kstat_redirect")),
            "LOOKUP":"\n".join(extract(source,n) for n in ("susfs_sus_kstat_spoof_vfs_statfs","susfs_sus_kstat_spoof_proc_fd_seq_show"))}
    text=(HERE/"kstat.c.in").read_text()
    for key,value in values.items():
        assert text.count(f"@@{key}@@")==1
        text=text.replace(f"@@{key}@@",value)
    return text


def verify_vfs(common):
    stat=(common/"fs/stat.c").read_text()
    opened=(common/"fs/open.c").read_text()
    statx=extract(stat,"vfs_statx")
    readlink=extract(stat,"do_readlinkat")
    access=extract(opened,"do_faccessat")
    openat=extract(opened,"do_sys_openat2")
    for name,body in (("statx",statx),("readlink",readlink),("access",access),("openat",openat)):
        if "extern bool susfs_" in body:
            raise RuntimeError(f"SUSFS declaration relocated into {name}")
    if statx.count("zeromount_stat_hook(dfd, filename, stat, request_mask, flags)") != 1 or "zeromount_stat_hook" in readlink:
        raise RuntimeError("ZeroMount call is not scoped to vfs_statx")
    for body,first,second in (
        (statx,"susfs_check_unicode_bypass(filename->uptr)","zeromount_stat_hook(dfd"),
        (statx,"susfs_is_hidden_name(_d->d_name.name", "vfs_getattr(&path"),
        (readlink,"susfs_check_unicode_bypass(pathname)","user_path_at_empty("),
        (access,"susfs_is_hidden_name(_d->d_name.name","inode = d_backing_inode(path.dentry)"),
        (openat,"susfs_check_unicode_bypass(filename)","tmp = getname(filename)")):
        if body.count(first) != 1 or body.count(second) != 1 or body.index(first) >= body.index(second):
            raise RuntimeError(f"Incorrect Enhanced VFS hook order: {first}")
    print("PASS: Enhanced/ZeroMount hooks retain their function scope and lookup ordering")


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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common",type=Path,required=True)
    parser.add_argument("--ksu",type=Path,required=True)
    parser.add_argument("--work-dir",type=Path,required=True)
    parser.add_argument("--cc",default="cc")
    parser.add_argument("--wasm",action="store_true")
    parser.add_argument("--node",default="node")
    parser.add_argument("--aarch64-check",action="store_true")
    args=parser.parse_args()
    port.validate_identity(args.common,args.ksu,port.SUSFS_PIN)
    port.verify(args.common,args.ksu)
    verify_vfs(args.common)
    root=args.work_dir.resolve()/('session35137-'+uuid.uuid4().hex)
    root.mkdir(parents=True)
    code=sources(args.common,args.ksu)
    result=compile_run(code,"production",args,root)
    webview=webview_sources(args.ksu)
    web_result=compile_run(webview,"webview",args,root)
    kstat=kstat_sources(args.common)
    kstat_result=compile_run(kstat,"kstat",args,root)
    if args.aarch64_check:
        for name in ["production","webview","kstat"]:
            run([args.cc,"--target=aarch64-linux-android","-DWASM_TEST","-ffreestanding",
                 "-fno-builtin","-std=gnu11","-Werror=implicit-function-declaration",
                 "-c",root/f"{name}.c","-o",root/f"{name}-aarch64.o"])
        print("PASS: session, WebView and KSTAT C compile for AArch64")
    kstat_mutations={
        "missing-device":("entry->target_dev = inode->i_sb->s_dev;", "entry->target_dev = 0;"),
        "missing-mount":("entry->spoofed_mnt_id = virtual_entry->spoofed_mnt_id;", "entry->spoofed_mnt_id = 0;"),
        "missing-statfs":("entry->spoofed_kstatfs = virtual_entry->spoofed_kstatfs;", "entry->spoofed_kstatfs.f_blocks = 0;"),
        "unhandled-virtual-error":("} else if (info.err != -ENOENT) {", "} else if (false) {"),
        "leaked-path":("path_put(&real_path);", "(void)0;"),
        "wrong-ctime-bit":("#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)", "#define KSTAT_SPOOF_CTIME_TV_SEC (1 < 8)"),
    }
    for name,(old,new) in kstat_mutations.items():
        assert kstat.count(old)==1,name
        compile_run(kstat.replace(old,new),"kstat-"+name,args,root,expect_failure=True)
    mutations={
        "failed-exec":("is_su_session && retval >= 0","is_su_session"),
        "ordinary-exec":("is_su_session && retval >= 0","retval >= 0"),
        "ucounts-error":("ret = set_cred_ucounts(cred);","set_cred_ucounts(cred);"),
        "unscoped-ioctl":("ksu_ioctl_handlers[i].allow_su_session && ksu_is_su_session_fd(filp)","ksu_is_su_session_fd(filp)"),
        "ksud-missing":("out:\n    ret = 0;","out:\n    if (is_su_session) *is_su_session = true;\n    ret = 0;"),
        "stale-exec-flag":("clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);", "(void)0;"),
        "legacy-unscoped":("if (likely(!is_su_session))", "if (false)"),
    }
    for name,(old,new) in mutations.items():
        assert code.count(old)==1,name
        compile_run(code.replace(old,new),name,args,root,expect_failure=True)
    before="retval = bprm_execve(bprm, fd, filename, flags);"
    moved=code.replace(before,"retval = 0;")
    assert moved.count("out_free:\n")==1
    moved=moved.replace("out_free:\n",before+"\nout_free:\n")
    compile_run(moved,"premature-fd",args,root,expect_failure=True)
    for name,old,new in [
        ("webview-prune"," || uid == WEBVIEW_ZYGOTE_UID;",";"),
        ("webview-next","if (ksu_uid_should_umount(new_uid))","if (false)"),
        ("webview-root","profile->allow_su || strcmp(profile->key","false || strcmp(profile->key")]:
        assert webview.count(old)==1,name
        compile_run(webview.replace(old,new),name,args,root,expect_failure=True)
    # Wrong pins and repeated application must leave exact source bytes intact.
    paths=[args.common/"fs/exec.c"]+[args.ksu/n for n in port.SOURCE_FILES]
    saved={p:p.read_bytes() for p in paths}
    expect_reject(lambda:port.validate_identity(args.common,args.ksu,"0"*40),"wrong SUSFS pin")
    expect_reject(lambda:port.apply(args.common,args.ksu),"repeat application")
    assert all(p.read_bytes()==data for p,data in saved.items())
    result={"resukisu_commit":port.RESUKISU_PIN,"susfs_commit":port.SUSFS_PIN,
            "production":result,"webview":web_result,"kstat":kstat_result,"mutations_rejected":17,
            "aarch64_object":args.aarch64_check,
            "limitation":"Kernel API mocks; complete build and exact-Image device test are separate."}
    (root/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS: exact-C fault tests, seventeen negative controls and rejection rollback checks")

if __name__=="__main__":
    main()
