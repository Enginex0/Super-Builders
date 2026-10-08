#!/usr/bin/env python3
"""Exact-pin ReSukiSU UAPI4 adaptation of upstream SUSFS 2.3.0's su-session hook.

Reference semantics: successful run 34262304602 (35119), carried by run
34402588266 (35127). The native UAPI4 driver and ksud stay source-identical.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys

RESUKISU_PIN = "3380d41f2043644d0ef6c0e0e91be6b229024d00"
SUSFS_PIN = "887928223bf685113f32837d5282117c9e4a04ca"
SOURCE_FILES = ("kernel/feature/sucompat.c", "kernel/feature/sucompat.h",
                "kernel/policy/app_profile.c", "kernel/policy/allowlist.c",
                "kernel/hook/setuid_hook.c")

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8")

def validate_identity(common, ksu, susfs_commit):
    if git(ksu, "rev-parse", "HEAD").strip() != RESUKISU_PIN:
        raise RuntimeError("ReSukiSU 35137 pin mismatch")
    if susfs_commit != SUSFS_PIN:
        raise RuntimeError("SUSFS 2.3.0 pin mismatch")
    if not re.search(r"KERNEL_SU_UAPI_VERSION\s*=\s*4\s*;", (ksu / "uapi/supercall.h").read_text()):
        raise RuntimeError("Native UAPI4 required")
    names = git(ksu, "ls-tree", "-r", "--name-only", "HEAD", "--", "uapi").splitlines()
    names += ["kernel/supercall/supercall.c", "userspace/ksud/src/android/ksucalls.rs"]
    for name in names:
        if (ksu / name).read_text(encoding="utf-8") != git(ksu, "show", f"HEAD:{name}"):
            raise RuntimeError(f"Native UAPI4 source changed: {name}")
    if '#define SUSFS_VERSION "v2.3.0"' not in (common / "include/linux/susfs.h").read_text():
        raise RuntimeError("SUSFS v2.3.0 header required")

def transform(common, ksu):
    exec_path = common / "fs/exec.c"
    sucompat_path = ksu / "kernel/feature/sucompat.c"
    sucompat_h_path = ksu / "kernel/feature/sucompat.h"
    app_profile_path = ksu / "kernel/policy/app_profile.c"
    allowlist_path = ksu / "kernel/policy/allowlist.c"
    setuid_path = ksu / "kernel/hook/setuid_hook.c"
    upstream_fix = SUSFS_PIN
    paths = [exec_path, sucompat_path, sucompat_h_path, app_profile_path, allowlist_path, setuid_path]


    def replace_once(text, old, new, label):
        count = text.count(old)
        if count != 1:
            raise RuntimeError(f"{label}: expected exactly one source match, found {count}")
        return text.replace(old, new, 1)


    def sub_once(text, pattern, replacement, label, flags=0):
        if len(list(re.finditer(pattern, text, flags))) != 1:
            raise RuntimeError(f"{label}: source is missing or ambiguous")
        updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
        if count != 1:
            raise RuntimeError(f"{label}: expected exactly one source match, found {count}")
        return updated

    # ---------------------------------------------------------------------------
    # 1. Linux 6.1 exec path: use the proven 35119 local-session design.
    #    Keep the explicit session decision local to this do_execveat_common()
    #    invocation. Upstream 052ca277 also gates the legacy SUSFS post-exec
    #    path with TIF; preserve that guard below and consume the flag once.
    # ---------------------------------------------------------------------------
    exec_src = exec_path.read_text(encoding="utf-8")
    if "ksu_handle_execveat_su_session" in exec_src:
        raise RuntimeError("already patched exec source; use --verify-only")
    exec_src = sub_once(
        exec_src,
        r"extern struct static_key_true ksu_su_compat_enabled;\s*\n"
        r"extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\s*\n"
        r"extern bool __ksu_is_allow_uid_for_current\(uid_t uid\);\s*\n"
        r"extern int ksu_handle_execveat\(int \*fd, struct filename \*\*filename_ptr, void \*argv,\s*\n"
        r"\s*void \*envp, int \*flags\);\s*\n"
        r"extern int ksu_handle_execveat_sucompat\(int \*fd, struct filename \*\*filename_ptr, void \*argv,\s*\n"
        r"\s*void \*envp, int \*flags\);",
        "extern struct static_key_true ksu_su_compat_enabled;\n"
        "extern bool ksu_handle_execveat_su_session(int *fd, struct filename **filename_ptr,\n"
        "\t\t\t\tvoid *argv, void *envp, int *flags);",
        "adapt latest SUSFS declarations", flags=re.MULTILINE,
    )
    exec_src = sub_once(
        exec_src,
        r"extern int ksu_handle_post_execveat_sucompat\(int \*fd, struct filename \*\*filename_ptr, void \*argv,\s*\n"
        r"\s*void \*envp, int \*flags, int \*retval\);",
        "extern int ksu_install_su_fd(void);",
        "replace generic KernelSU post-exec declaration", flags=re.MULTILINE,
    )
    exec_src = sub_once(
        exec_src,
        r"if \(static_branch_likely\(&ksu_su_compat_enabled\)\) \{\s*\n"
        r"\s*if \(static_branch_unlikely\(&susfs_is_sdcard_android_data_not_decrypted\)\) \{\s*\n"
        r"\s*is_su_session = !ksu_handle_execveat\(&fd, &filename, &argv, &envp, &flags\);\s*\n"
        r"\s*\} else \{\s*\n"
        r"\s*is_su_session = !ksu_handle_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags\);\s*\n"
        r"\s*\}\s*\n\s*\}",
        "if (static_branch_likely(&ksu_su_compat_enabled)) {\n"
        "\t\tis_su_session = ksu_handle_execveat_su_session(&fd, &filename, &argv,\n"
        "\t\t\t\t\t\t\t     &envp, &flags);\n\t}",
        "explicit ReSukiSU session decision", flags=re.MULTILINE,
    )
    # Keep the success guard at the direct ReSukiSU UAPI4 installation site.
    # The latest generic SUSFS patch delegates that guard to its KernelSU wrapper.
    exec_src = replace_once(
        exec_src,
        "\tif (unlikely(is_su_session))\n"
        "\t\t(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);",
        '\tif (unlikely(is_su_session && retval >= 0)) {\n'
        '\t\tint su_fd = ksu_install_su_fd();\n\n'
        '\t\tif (su_fd < 0)\n'
        '\t\t\tpr_warn("ReSukiSU: su-session FD installation failed: %d\\n", su_fd);\n'
        '\t}',
        "retain latest SUSFS post-success installation",
    )

    # ---------------------------------------------------------------------------
    # 2. ReSukiSU 35137 sucompat: return an explicit session boolean, propagate
    #    profile failures, and only recognize a session after KSUD_PATH is selected.
    # ---------------------------------------------------------------------------
    su = sucompat_path.read_text(encoding="utf-8")

    su = replace_once(
        su,
        "static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, struct user_arg_ptr *argv)\n{\n"
        "    struct ksu_sulog_pending_event *pending_sucompat = NULL;\n"
        "    struct path kpath;\n"
        "    bool is_allowed = ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid()));",
        "static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, struct user_arg_ptr *argv,\n"
        "                                                    bool *is_su_session)\n{\n"
        "    struct ksu_sulog_pending_event *pending_sucompat = NULL;\n"
        "    struct path kpath;\n"
        "    int ret;\n"
        "    bool is_allowed = ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid()));",
        "extend sucompat pre-handler with explicit session result",
    )

    su = replace_once(
        su,
        "    pr_info(\"do_execveat_common su found\\n\");\n\n"
        "    escape_with_root_profile();\n\n"
        "    pending_sucompat = ksu_sulog_capture_sucompat_manual(filename, *argv, GFP_KERNEL);",
        "    pr_info(\"do_execveat_common su found\\n\");\n\n"
        "    pending_sucompat = ksu_sulog_capture_sucompat_manual(filename, *argv, GFP_KERNEL);\n\n"
        "    /* Match the proven 35119 port: a rejected root profile must never\n"
        "     * become a scoped su session. */\n"
        "    if (test_thread_flag(TIF_KSU_DISABLE_ESCAPE_WITH_ROOT)) {\n"
        "        ret = -EPERM;\n"
        "        goto out_log;\n"
        "    }\n"
        "    ret = escape_with_root_profile();\n"
        "    if (ret)\n"
        "        goto out_log;",
        "propagate root-profile failure",
    )

    su = replace_once(
        su,
        "    path_put(&kpath);\n"
        "    memcpy((void *)filename, ksud_path, sizeof(ksud_path));\n"
        "out:\n"
        "    ksu_sulog_emit_pending(pending_sucompat, 0, GFP_KERNEL);\n"
        "    // always flag that, to avoid old version of susfs hang in boot\n"
        "    set_thread_flag(TIF_PROC_IN_KSU_EXECVE);\n"
        "    return 0;",
        "    path_put(&kpath);\n"
        "    memcpy((void *)filename, ksud_path, sizeof(ksud_path));\n"
        "    if (is_su_session)\n"
        "        *is_su_session = true;\n"
        "    else\n"
        "        set_thread_flag(TIF_PROC_IN_KSU_EXECVE);\n"
        "out:\n"
        "    ret = 0;\n"
        "out_log:\n"
        "    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);\n"
        "    return ret;",
        "recognize only a real ksud su session",
    )

    su = replace_once(
        su,
        "int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)\n{\n"
        "    struct ksu_sulog_pending_event *pending_root_execve = NULL;",
        "static int ksu_handle_execve_common(int *fd, const char *filename, void *argv, void *envp, int *flags,\n"
        "                                    bool *is_su_session)\n{\n"
        "    struct ksu_sulog_pending_event *pending_root_execve = NULL;\n\n"
        "    if (is_su_session)\n"
        "        *is_su_session = false;",
        "introduce common exec handler",
    )

    su = replace_once(
        su,
        "    int ret = do_ksu_handle_execveat_sucompat(fd, filename, argv);",
        "    int ret = do_ksu_handle_execveat_sucompat(fd, filename, argv, is_su_session);",
        "pass explicit session result",
    )

    needle = "    return ret;\n}\n\nint ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)"
    replacement = (
        "    return ret;\n}\n\n"
        "int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)\n"
        "{\n"
        "    return ksu_handle_execve_common(fd, filename, argv, envp, flags, NULL);\n"
        "}\n\n"
        "int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)"
    )
    su = replace_once(su, needle, replacement, "restore legacy exec wrapper")

    post_old = """int ksu_handle_post_execve(int *fd, const char *filename, void *argv, void *envp, int *flags, int *retval)
    {
        if (likely(!test_thread_flag(TIF_PROC_IN_KSU_EXECVE))) {
            return -EINVAL;
        }
    #ifndef KSU_COMPAT_HAS_SUSFS_INSTALL_SU_FD_DIRECT_CALL
        ksu_install_su_fd();
    #endif
        // #ifdef KSU_COMPAT_NO_POST_EXECVE_HOOK
        //     return 0;
        // #endif
        // TODO Implement tmpfd of ksud when KSU_COMPAT_NO_POST_EXECVE_HOOK is not defined
        return 0;
    }"""
    post_new = """int ksu_handle_post_execve(int *fd, const char *filename, void *argv, void *envp, int *flags, int *retval)
    {
        bool is_su_session = test_thread_flag(TIF_PROC_IN_KSU_EXECVE);

        /* Never let the transient session flag survive an exec attempt. */
        if (is_su_session)
            clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);
        if (likely(!is_su_session))
            return -EINVAL;
    #ifndef KSU_COMPAT_HAS_SUSFS_INSTALL_SU_FD_DIRECT_CALL
        /* Keep the success condition here too for non-SUSFS/manual hook users. */
        if (likely(retval && *retval >= 0)) {
            int su_fd = ksu_install_su_fd();

            if (su_fd < 0)
                pr_warn("ReSukiSU: post-exec su-session FD installation failed: %d\\n", su_fd);
        }
    #endif
        return 0;
    }"""
    post_old = post_old.replace("\n    ", "\n")
    post_new = post_new.replace("\n    ", "\n")
    su = replace_once(su, post_old, post_new, "harden legacy post-exec handler")

    marker = "#ifdef CONFIG_KSU_SUSFS\nint ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)"
    insert = """#ifdef CONFIG_KSU_SUSFS
    bool ksu_handle_execveat_su_session(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
    {
        bool is_su_session = false;

        if (!filename_ptr || IS_ERR_OR_NULL(*filename_ptr))
            return false;
        if (ksu_handle_execve_common(fd, (*filename_ptr)->name, argv, envp, flags, &is_su_session))
            return false;
        return is_su_session;
    }

    int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)"""
    insert = insert.replace("\n    ", "\n")
    su = replace_once(su, marker, insert, "add explicit SUSFS session API")

    # ---------------------------------------------------------------------------
    # 3. Header declaration for the explicit session API.
    # ---------------------------------------------------------------------------
    suh = sucompat_h_path.read_text(encoding="utf-8")
    suh = replace_once(
        suh,
        "#ifdef CONFIG_KSU_SUSFS\nint ksu_handle_faccessat",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "bool ksu_handle_execveat_su_session(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);\n"
        "int ksu_handle_faccessat",
        "declare explicit SUSFS session API",
    )

    # ---------------------------------------------------------------------------
    # 4. UAPI-neutral correctness from the successful 35119 native port:
    #    propagate set_cred_ucounts() failure instead of returning success.
    # ---------------------------------------------------------------------------
    app = app_profile_path.read_text(encoding="utf-8")
    app = replace_once(
        app,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)\n"
        "    if (set_cred_ucounts(cred)) {\n"
        "        goto out_abort_creds;\n"
        "    }\n"
        "#endif",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)\n"
        "    ret = set_cred_ucounts(cred);\n"
        "    if (ret) {\n"
        "        goto out_abort_creds;\n"
        "    }\n"
        "#endif",
        "propagate set_cred_ucounts failure",
    )

    # ---------------------------------------------------------------------------
    # 5. WebView UID 1053: 35137 manager exposes a real profile for it. Preserve
    #    that profile, forbid root grants, and make zygote_next consult it.
    # ---------------------------------------------------------------------------
    allow = allowlist_path.read_text(encoding="utf-8")
    allow = replace_once(
        allow,
        "    if (profile->version != KSU_APP_PROFILE_VER) {\n"
        "        pr_info(\"Unsupported profile version: %d\\n\", profile->version);\n"
        "        return false;\n"
        "    }\n\n"
        "    if (profile->allow_su) {",
        "    if (profile->version != KSU_APP_PROFILE_VER) {\n"
        "        pr_info(\"Unsupported profile version: %d\\n\", profile->version);\n"
        "        return false;\n"
        "    }\n\n"
        "    /* WebView is a system service profile, never a root-granting app. */\n"
        "    if (profile->curr_uid == WEBVIEW_ZYGOTE_UID &&\n"
        "        (profile->allow_su || strcmp(profile->key, \"webview_zygote\") != 0)) {\n"
        "        return false;\n"
        "    }\n\n"
        "    if (profile->allow_su) {",
        "validate WebView profile identity",
    )
    allow = replace_once(
        allow,
        "        bool is_preserved_uid = uid == KSU_APP_PROFILE_PRESERVE_UID;",
        "        bool is_preserved_uid = uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID;",
        "preserve WebView profile during pruning",
    )

    setuid = setuid_path.read_text(encoding="utf-8")
    setuid = replace_once(
        setuid,
        "    // Check if spawned process is normal user app and needs to be umounted\n"
        "    // Now app_profile for webview_zygote is available in KernelSU manager\n"
        "    if (likely(is_appuid(new_uid) && ksu_uid_should_umount(new_uid))) {",
        "    /* UID 1053 is outside is_appuid(); use the same UAPI4 profile the\n"
        "     * 35137 manager already exposes for WebView Zygote. */\n"
        "    if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID)) {\n"
        "        if (ksu_uid_should_umount(new_uid)) {\n"
        "            susfs_set_current_proc_no_su();\n"
        "            susfs_set_current_proc_umounted();\n"
        "            susfs_set_current_proc_umounted_for_zygote_next();\n"
        "            goto do_susfs_work;\n"
        "        }\n"
        "        susfs_set_current_proc_no_su();\n"
        "        return 0;\n"
        "    }\n\n"
        "    // Check if spawned process is normal user app and needs to be umounted\n"
        "    if (likely(is_appuid(new_uid) && ksu_uid_should_umount(new_uid))) {",
        "apply WebView profile to zygote_next",
    )

    # ---------------------------------------------------------------------------
    # Fail-closed verification before writing any source file.
    # ---------------------------------------------------------------------------
    checks = [
        (exec_src, "bool is_su_session = false;", "fs/exec local session state"),
        (exec_src, "is_su_session = ksu_handle_execveat_su_session", "fs/exec scoped pre-handler"),
        (exec_src, "is_su_session && retval >= 0", "retval >= 0 success guard"),
        (exec_src, "int su_fd = ksu_install_su_fd();", "post-success UAPI4 FD install"),
        (su, "bool ksu_handle_execveat_su_session(", "explicit 35137 session API"),
        (su, "*is_su_session = true;", "KSUD-only session recognition"),
        (su, "ret = escape_with_root_profile();", "root-profile error propagation"),
        (su, "clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);", "legacy-hook stale flag cleanup"),
        (su, "retval && *retval >= 0", "legacy post-exec success guard"),
        (app, "ret = set_cred_ucounts(cred);", "ucount error propagation"),
        (allow, "strcmp(profile->key, \"webview_zygote\") != 0", "WebView identity validation"),
        (allow, "uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID", "WebView prune preservation"),
        (setuid, "if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID))", "WebView zygote_next handling"),
    ]
    for text, marker, label in checks:
        if marker not in text:
            raise RuntimeError(f"verification failed: {label}")

    if "ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval)" in exec_src:
        raise RuntimeError("old unscoped 35137 post-exec bridge survived in fs/exec.c")
    if exec_src.count("int su_fd = ksu_install_su_fd();") != 1:
        raise RuntimeError("expected exactly one direct scoped FD install in fs/exec.c")
    if exec_src.find("is_su_session && retval >= 0") < exec_src.find("retval = bprm_execve(bprm, fd, filename, flags);"):
        raise RuntimeError("success-only su FD install is not after bprm_execve")

    # 35137 UAPI4 userspace must natively understand the scoped driver name; do not
    # apply the old 35119 optional UAPI2 ksud patch.
    ksucalls = sucompat_path.parents[2] / "userspace/ksud/src/android/ksucalls.rs"
    if not ksucalls.is_file():
        raise RuntimeError("35137 ksud source is missing")
    ksud_text = ksucalls.read_text(encoding="utf-8")
    if 'SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]"' not in ksud_text:
        raise RuntimeError("35137 userspace does not recognize [ksu_driver_su]")

    exec_path.write_text(exec_src, encoding="utf-8", newline="\n")
    sucompat_path.write_text(su, encoding="utf-8", newline="\n")
    sucompat_h_path.write_text(suh, encoding="utf-8", newline="\n")
    app_profile_path.write_text(app, encoding="utf-8", newline="\n")
    allowlist_path.write_text(allow, encoding="utf-8", newline="\n")
    setuid_path.write_text(setuid, encoding="utf-8", newline="\n")

    print(
        "ReSukiSU 35137 UAPI4 native su-session port applied: "
        f"35119 semantics + SUSFS {upstream_fix}; upstream base 88792822"
    )


def verify(common, ksu):
    exec_path = common / "fs/exec.c"
    source = exec_path.read_text(encoding="utf-8")
    su_path = ksu / "kernel/feature/sucompat.c"
    suh_path = ksu / "kernel/feature/sucompat.h"
    app_path = ksu / "kernel/policy/app_profile.c"
    allow_path = ksu / "kernel/policy/allowlist.c"
    setuid_path = ksu / "kernel/hook/setuid_hook.c"
    ksud_path = ksu / "userspace/ksud/src/android/ksucalls.rs"

    su = su_path.read_text(encoding="utf-8")
    suh = suh_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")
    allow = allow_path.read_text(encoding="utf-8")
    setuid = setuid_path.read_text(encoding="utf-8")
    ksud = ksud_path.read_text(encoding="utf-8")

    fixed_warn = r'pr_warn("ReSukiSU: su-session FD installation failed: %d\n", su_fd);'
    if source.count(fixed_warn) != 1 or r'pr_warn(\"' in source or r'pr_warn(\"' in su:
        raise RuntimeError("Invalid generated C warning")
    if "is_su_session = !ksu_handle_execveat" in source:
        raise RuntimeError("Ambiguous integer return used as session decision")
    execs = list(re.finditer(r"retval\s*=\s*bprm_execve\(bprm, fd, filename, flags\);", source))
    if len(execs) != 1:
        raise RuntimeError(f"expected exactly one bprm_execve assignment, found {len(execs)}")
    if source.count("bool is_su_session = false;") != 1:
        raise RuntimeError("missing unique local is_su_session state")
    if source.count("is_su_session = ksu_handle_execveat_su_session") != 1:
        raise RuntimeError("missing unique scoped pre-exec session decision")
    if source.count("int su_fd = ksu_install_su_fd();") != 1:
        raise RuntimeError("missing unique direct UAPI4 scoped-FD install")
    if source.count("is_su_session && retval >= 0") != 1:
        raise RuntimeError("missing exact is_su_session && retval >= 0 guard")
    if "ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval)" in source:
        raise RuntimeError("bootloop-prone unscoped post-exec bridge is still present")

    success_pos = source.find("is_su_session && retval >= 0")
    install_pos = source.find("int su_fd = ksu_install_su_fd();")
    if not (execs[0].end() < success_pos < install_pos):
        raise RuntimeError("scoped-FD ordering is not bprm_execve -> success/session guard -> install")

    required_su = (
        "bool ksu_handle_execveat_su_session(",
        "*is_su_session = true;",
        "ret = escape_with_root_profile();",
        "clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);",
        "retval && *retval >= 0",
    )
    for marker in required_su:
        if marker not in su:
            raise RuntimeError(f"ReSukiSU session contract missing: {marker}")
    if "bool ksu_handle_execveat_su_session(" not in suh:
        raise RuntimeError("ReSukiSU session API declaration missing")
    if "ret = set_cred_ucounts(cred);" not in app:
        raise RuntimeError("set_cred_ucounts failure is not propagated")
    if 'strcmp(profile->key, "webview_zygote") != 0' not in allow:
        raise RuntimeError("WebView UID 1053 profile identity is not constrained")
    if "uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID" not in allow:
        raise RuntimeError("WebView UID 1053 profile is not preserved during prune")
    if "if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID))" not in setuid:
        raise RuntimeError("zygote_next does not consult the WebView UID 1053 profile")
    if 'SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]"' not in ksud:
        raise RuntimeError("35137 UAPI4 ksud lacks native scoped driver support")

    print("Verified 35137 native UAPI4 session gate: real ksud session + retval >= 0 + scoped FD")
    print("Verified generated C quoting: no malformed pr_warn escaped quotes remain")
    print("Verified UAPI-neutral 35119 carryovers: ucounts + WebView UID 1053 consistency")

def apply(common, ksu):
    paths = [common / "fs/exec.c"] + [ksu / name for name in SOURCE_FILES]
    backup = {path: path.read_bytes() for path in paths}
    try:
        transform(common, ksu)
        verify(common, ksu)
    except BaseException:
        for path, content in backup.items():
            path.write_bytes(content)
        raise

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", required=True, type=Path)
    parser.add_argument("--ksu", required=True, type=Path)
    parser.add_argument("--susfs-commit", required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--vmlinux", type=Path)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    common, ksu = args.common.resolve(), args.ksu.resolve()
    validate_identity(common, ksu, args.susfs_commit)
    if args.verify_only:
        verify(common, ksu)
    else:
        apply(common, ksu)
    receipt = {"resukisu_version":35137, "resukisu_commit":RESUKISU_PIN,
               "susfs_version":"v2.3.0", "susfs_commit":SUSFS_PIN, "uapi":4,
               "base_run":34684249719, "reference_run":34262304602,
               "session_policy":"explicit ksud session and successful exec before FD install",
               "source_sha256":{name:sha(ksu/name) for name in SOURCE_FILES},
               "exec_sha256":sha(common/"fs/exec.c"),
               "runtime_test":"not performed; requires booting this exact Image"}
    artifact_args = [args.config, args.image, args.vmlinux, args.receipt]
    if any(artifact_args) and not all(artifact_args):
        parser.error("Artifact audit requires config, image, vmlinux and receipt together")
    if args.config:
        config = args.config.read_text()
        required = ["CONFIG_KSU", "CONFIG_KSU_SUSFS", "CONFIG_ZEROMOUNT",
                    "CONFIG_KSU_SUSFS_SUS_MAP", "CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT",
                    "CONFIG_KSU_SUSFS_UNICODE_FILTER", "CONFIG_KSU_SUSFS_HIDDEN_NAME"]
        for name in required:
            if not re.search(r"^"+name+r"=y$", config, re.M):
                raise RuntimeError(f"Final config missing {name}=y")
        # KSU_VERSION is a numeric C macro; its decimal spelling is not
        # guaranteed to survive in the compressed Image. Prove 35137 from
        # the exact pinned source history plus the Kbuild formula instead.
        commit_count = int(git(ksu, "rev-list", "--count", "HEAD").strip())
        kbuild = (ksu / "kernel/Kbuild").read_text(encoding="utf-8")
        version_prefix = "KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + "
        version_lines = [line for line in kbuild.splitlines()
                         if line.startswith(version_prefix) and line.endswith(")")]
        if len(version_lines) != 1:
            raise RuntimeError(f"Expected one ReSukiSU KSU_VERSION formula, found {len(version_lines)}")
        try:
            version_offset = int(version_lines[0][len(version_prefix):-1])
        except ValueError as exc:
            raise RuntimeError(f"Invalid ReSukiSU KSU_VERSION formula: {version_lines[0]}") from exc
        compiled_version = 30000 + commit_count + version_offset
        if compiled_version != 35137:
            raise RuntimeError(
                f"ReSukiSU version formula mismatch: commits={commit_count} "
                f"offset={version_offset} result={compiled_version} expected=35137"
            )

        image = args.image.read_bytes()
        for marker in [b"v2.3.0", b"6.1.162-android14-11-34343818-abS928BXXU6ZZI4"]:
            if marker not in image:
                raise RuntimeError(f"Image identity missing {marker!r}")
        symbols = subprocess.check_output([args.nm, "--defined-only", str(args.vmlinux)], text=True)
        names = ["ksu_install_su_fd", "ksu_handle_execveat_su_session", "susfs_add_sus_kstat_redirect",
                 "susfs_add_sus_map", "susfs_init", "zeromount_init"]
        for name in names:
            if len(re.findall(r"^[0-9a-fA-F]+ [tT] " + name + r"$", symbols, re.M)) != 1:
                raise RuntimeError(f"Expected exactly one compiled function: {name}")
        receipt.update(config_sha256=sha(args.config), image_sha256=sha(args.image),
                       vmlinux_sha256=sha(args.vmlinux), compiled_symbols=names)
        receipt.update(resukisu_commit_count=commit_count,
                       resukisu_version_offset=version_offset,
                       resukisu_compiled_version=compiled_version)

        args.receipt.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8", newline="\n")
        print("PASS: final config, Image identity, ReSukiSU version formula, unique compiled functions and package attestation")

if __name__ == "__main__":
    main()
