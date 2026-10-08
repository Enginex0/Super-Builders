#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree is required}"
KSU_TREE="${2:?ReSukiSU tree is required}"

EXPECTED_RESUKISU_COMMIT="23a40c0f1dc047ee73a1dfd70a3f14df70021cac"
EXPECTED_SUSFS_BASE="5727f79e3a7175cfb0e1a754fc2ed78eaf866237"
UPSTREAM_SUSFS_FIX="153f88df3be2501d2d33364f8fe05247aecb3cef"
REFERENCE_PORT="ReSukiSU-35119-SUSFS-Native-v2"

[[ "${RESUKISU_VERSION_CODE:-}" == "35127" ]] || {
  echo "::error::ReSukiSU 35127 native port invoked for version ${RESUKISU_VERSION_CODE:-<unset>}"
  exit 1
}
[[ "${SUSFS_PINNED_COMMIT:-}" == "$EXPECTED_SUSFS_BASE" ]] || {
  echo "::error::Unexpected SUSFS base: ${SUSFS_PINNED_COMMIT:-<unset>}; expected $EXPECTED_SUSFS_BASE"
  exit 1
}
[[ -d "$COMMON_TREE" && -d "$KSU_TREE" ]] || {
  echo "::error::Kernel source trees are missing"
  exit 1
}

ACTUAL_RESUKISU_COMMIT=$(git -C "$KSU_TREE" rev-parse HEAD)
[[ "$ACTUAL_RESUKISU_COMMIT" == "$EXPECTED_RESUKISU_COMMIT" ]] || {
  echo "::error::ReSukiSU pin mismatch: expected $EXPECTED_RESUKISU_COMMIT, got $ACTUAL_RESUKISU_COMMIT"
  exit 1
}

python3 - \
  "$COMMON_TREE/fs/exec.c" \
  "$KSU_TREE/kernel/feature/sucompat.c" \
  "$KSU_TREE/kernel/feature/sucompat.h" \
  "$KSU_TREE/kernel/policy/app_profile.c" \
  "$KSU_TREE/kernel/policy/allowlist.c" \
  "$KSU_TREE/kernel/hook/setuid_hook.c" \
  "$UPSTREAM_SUSFS_FIX" "$REFERENCE_PORT" <<'PY'
from pathlib import Path
import re
import sys

exec_path = Path(sys.argv[1])
sucompat_path = Path(sys.argv[2])
sucompat_h_path = Path(sys.argv[3])
app_profile_path = Path(sys.argv[4])
allowlist_path = Path(sys.argv[5])
setuid_path = Path(sys.argv[6])
upstream_fix = sys.argv[7]
reference_port = sys.argv[8]

paths = [exec_path, sucompat_path, sucompat_h_path, app_profile_path, allowlist_path, setuid_path]
for path in paths:
    if not path.is_file():
        raise SystemExit(f"required source file is missing: {path}")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return text.replace(old, new, 1)


def sub_once(text, pattern, replacement, label, flags=0):
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return updated

# ---------------------------------------------------------------------------
# 1. Linux 6.1 exec path: use the proven 35119 local-session design.
#    CONFIG_KSU_SUSFS is its own ReSukiSU hook choice, so a MANUAL_HOOK-only
#    TIF check cannot scope the post-exec call. Keep the session decision local
#    to this do_execveat_common() invocation instead.
# ---------------------------------------------------------------------------
exec_src = exec_path.read_text(encoding="utf-8")

if "ksu_handle_execveat_su_session" in exec_src or "is_su_session && retval >= 0" in exec_src:
    raise SystemExit("fs/exec.c already contains a su-session direct port; refusing mixed state")

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
    "\t\t\t\tvoid *argv, void *envp, int *flags);\n"
    "extern int ksu_install_su_fd(void);",
    "replace SUSFS exec declarations",
    flags=re.MULTILINE,
)

exec_src = sub_once(
    exec_src,
    r"(static int do_execveat_common\([^\{]+\{\s*\n\s*struct linux_binprm \*bprm;\s*\n\s*int retval;)",
    r"\1\n#ifdef CONFIG_KSU_SUSFS\n\tbool is_su_session = false;\n#endif",
    "add local su-session state",
    flags=re.DOTALL,
)

exec_src = sub_once(
    exec_src,
    r"if \(static_branch_likely\(&ksu_su_compat_enabled\)\) \{\s*\n"
    r"\s*if \(static_branch_unlikely\(&susfs_is_sdcard_android_data_not_decrypted\)\)\s*\n"
    r"\s*ksu_handle_execveat\(&fd, &filename, &argv, &envp, &flags\);\s*\n"
    r"\s*else\s*\n"
    r"\s*ksu_handle_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags\);\s*\n"
    r"\s*\}",
    "if (static_branch_likely(&ksu_su_compat_enabled)) {\n"
    "\t\tis_su_session = ksu_handle_execveat_su_session(&fd, &filename, &argv,\n"
    "\t\t\t\t\t\t\t     &envp, &flags);\n"
    "\t}",
    "replace ambiguous SUSFS pre-exec dispatch",
    flags=re.MULTILINE,
)

exec_src = sub_once(
    exec_src,
    r"(^[ \t]*retval\s*=\s*bprm_execve\(bprm, fd, filename, flags\);\s*$)",
    r"\1\n#ifdef CONFIG_KSU_SUSFS\n"
    r"\t/* 35119-proven / SUSFS 153f88df semantics: install the scoped UAPI4\n"
    r"\t * driver FD only after a real ksud su session successfully execs. */\n"
    r"\tif (unlikely(is_su_session && retval >= 0)) {\n"
    r"\t\tint su_fd = ksu_install_su_fd();\n\n"
    r"\t\tif (su_fd < 0)\n"
    r"\t\t\tpr_warn(\"ReSukiSU: su-session FD installation failed: %d\\n\", su_fd);\n"
    r"\t}\n"
    r"#endif",
    "install scoped FD after successful exec",
    flags=re.MULTILINE,
)

# ---------------------------------------------------------------------------
# 2. ReSukiSU 35127 sucompat: return an explicit session boolean, propagate
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
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "    // flag for post execve hook, mostly: bprm_committed_creds LSM hooks\n"
    "    // no need care in susfs, susfs completed everything\n"
    "    set_thread_flag(TIF_PROC_IN_KSU_EXECVE);\n"
    "#endif\n"
    "    return 0;",
    "    path_put(&kpath);\n"
    "    memcpy((void *)filename, ksud_path, sizeof(ksud_path));\n"
    "    if (is_su_session)\n"
    "        *is_su_session = true;\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "    else\n"
    "        set_thread_flag(TIF_PROC_IN_KSU_EXECVE);\n"
    "#endif\n"
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
#ifdef CONFIG_KSU_MANUAL_HOOK
    if (likely(!test_thread_flag(TIF_PROC_IN_KSU_EXECVE))) {
        return -EINVAL;
    }
#endif
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
#ifdef CONFIG_KSU_MANUAL_HOOK
    bool is_su_session = test_thread_flag(TIF_PROC_IN_KSU_EXECVE);

    /* Never let the transient session flag survive an exec attempt. */
    if (is_su_session)
        clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);
    if (likely(!is_su_session))
        return -EINVAL;
#endif
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
# 5. WebView UID 1053: 35127 manager exposes a real profile for it. Preserve
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
    "     * 35127 manager already exposes for WebView Zygote. */\n"
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
    (su, "bool ksu_handle_execveat_su_session(", "explicit 35127 session API"),
    (su, "*is_su_session = true;", "KSUD-only session recognition"),
    (su, "ret = escape_with_root_profile();", "root-profile error propagation"),
    (su, "clear_thread_flag(TIF_PROC_IN_KSU_EXECVE);", "manual-hook stale flag cleanup"),
    (su, "retval && *retval >= 0", "legacy post-exec success guard"),
    (app, "ret = set_cred_ucounts(cred);", "ucount error propagation"),
    (allow, "strcmp(profile->key, \"webview_zygote\") != 0", "WebView identity validation"),
    (allow, "uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID", "WebView prune preservation"),
    (setuid, "if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID))", "WebView zygote_next handling"),
]
for text, marker, label in checks:
    if marker not in text:
        raise SystemExit(f"verification failed: {label}")

if "ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval)" in exec_src:
    raise SystemExit("old unscoped 35127 post-exec bridge survived in fs/exec.c")
if exec_src.count("int su_fd = ksu_install_su_fd();") != 1:
    raise SystemExit("expected exactly one direct scoped FD install in fs/exec.c")
if exec_src.find("is_su_session && retval >= 0") < exec_src.find("retval = bprm_execve(bprm, fd, filename, flags);"):
    raise SystemExit("success-only su FD install is not after bprm_execve")

# 35127 UAPI4 userspace must natively understand the scoped driver name; do not
# apply the old 35119 optional UAPI2 ksud patch.
ksucalls = sucompat_path.parents[2] / "userspace/ksud/src/android/ksucalls.rs"
if not ksucalls.is_file():
    raise SystemExit("35127 ksud source is missing")
ksud_text = ksucalls.read_text(encoding="utf-8")
if 'SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]"' not in ksud_text:
    raise SystemExit("35127 userspace does not recognize [ksu_driver_su]")

exec_path.write_text(exec_src, encoding="utf-8")
sucompat_path.write_text(su, encoding="utf-8")
sucompat_h_path.write_text(suh, encoding="utf-8")
app_profile_path.write_text(app, encoding="utf-8")
allowlist_path.write_text(allow, encoding="utf-8")
setuid_path.write_text(setuid, encoding="utf-8")

print(
    "ReSukiSU 35127 UAPI4 native su-session port applied: "
    f"35119 semantics + SUSFS {upstream_fix}; stable base 5727f79e"
)
PY

# ReSukiSU's SUSFS compatibility probe must now detect the deliberate direct
# post-success install and disable its unscoped fallback installation.
grep -qF 'ksu_handle_execveat_su_session' "$COMMON_TREE/fs/exec.c"
grep -qF 'is_su_session && retval >= 0' "$COMMON_TREE/fs/exec.c"
grep -qF 'int su_fd = ksu_install_su_fd();' "$COMMON_TREE/fs/exec.c"
grep -qF 'grep -q "ksu_install_su_fd" $(srctree)/fs/exec.c' "$KSU_TREE/kernel/tools/susfs_compat.mk"
grep -qF 'bool ksu_handle_execveat_su_session' "$KSU_TREE/kernel/feature/sucompat.c"
grep -qF 'ret = set_cred_ucounts(cred);' "$KSU_TREE/kernel/policy/app_profile.c"
grep -qF 'uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID' "$KSU_TREE/kernel/policy/allowlist.c"
grep -qF 'if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID))' "$KSU_TREE/kernel/hook/setuid_hook.c"
grep -qF 'SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]"' "$KSU_TREE/userspace/ksud/src/android/ksucalls.rs"

echo "Verified ReSukiSU 35127 UAPI4 native session port against $REFERENCE_PORT and SUSFS $EXPECTED_SUSFS_BASE"
