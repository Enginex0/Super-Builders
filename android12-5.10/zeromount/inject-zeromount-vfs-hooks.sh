#!/bin/bash
# inject-zeromount-vfs-hooks.sh - Inject all ZeroMount VFS hooks
#
# Consolidated injection for stat, namei, readdir, dpath, statfs, xattr.
# Each subsystem is a self-contained function; execution order matters.
#
# Usage: ./inject-zeromount-vfs-hooks.sh <kernel-source-dir>
#   e.g. ./inject-zeromount-vfs-hooks.sh /path/to/common

set -e

KERNEL_DIR="${1:?Usage: $0 <kernel-source-dir>}"

if [ ! -d "$KERNEL_DIR/fs" ]; then
    echo "Error: $KERNEL_DIR/fs not found. Pass the kernel source root."
    exit 1
fi

# --- Shared helpers ---

check_already_injected() {
    local file="$1"
    local marker="$2"
    if grep -q "$marker" "$file"; then
        echo "File already contains ZeroMount hooks ($marker found). Skipping."
        return 0
    fi
    return 1
}

# --- stat.c ---

inject_stat() {
    local STAT_FILE="$KERNEL_DIR/fs/stat.c"
    local MARKER="CONFIG_ZEROMOUNT"

    if [ ! -f "$STAT_FILE" ]; then
        echo "Error: File not found: $STAT_FILE"
        return 1
    fi

    echo "Injecting ZeroMount stat hooks into: $STAT_FILE"

    if check_already_injected "$STAT_FILE" "$MARKER"; then
        return 0
    fi

    if ! grep -q '#include <linux/uaccess.h>' "$STAT_FILE"; then
        echo "Error: Cannot find #include <linux/uaccess.h>"
        return 1
    fi

    if ! grep -q 'static int vfs_statx' "$STAT_FILE"; then
        echo "Error: Cannot find 'static int vfs_statx' function"
        return 1
    fi

    cp "$STAT_FILE" "${STAT_FILE}.bak"

    echo "  [1/2] Injecting zeromount.h include..."
    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$STAT_FILE"

    echo "  [2/2] Injecting hook into vfs_statx..."

    # Add forward declaration and inline hook function before vfs_statx
    sed -i '/^static int vfs_statx(/i\
#ifdef CONFIG_ZEROMOUNT\
/* ZeroMount stat hook for relative path intercept */\
static inline int zeromount_stat_hook(int dfd, const char __user *filename, \
                                      struct kstat *stat, unsigned int request_mask, \
                                      unsigned int flags) {\
    if (zm_is_recursive()) return -ENOENT;\
    if (filename) {\
        char kname[NAME_MAX + 1];\
        long copied = strncpy_from_user(kname, filename, sizeof(kname));\
        if (copied > 0 && kname[0] != '"'"'/'"'"') {\
            char *abs_path = zeromount_build_absolute_path(dfd, kname);\
            if (abs_path) {\
                char *resolved = zeromount_resolve_path(abs_path);\
                if (resolved) {\
                    struct path zm_path;\
                    int zm_ret;\
                    zm_enter();\
                    zm_ret = kern_path(resolved, (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW, &zm_path);\
                    zm_exit();\
                    kfree(resolved);\
                    kfree(abs_path);\
                    if (zm_ret == 0) {\
                        zm_ret = vfs_getattr(&zm_path, stat, request_mask,\
                                             (flags & AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0);\
                        path_put(&zm_path);\
                        return zm_ret;\
                    }\
                } else {\
                    kfree(abs_path);\
                }\
            }\
        }\
    }\
    return -ENOENT;\
}\
#endif' "$STAT_FILE"

    # Also inject the call into vfs_statx after variable declarations
    awk '
BEGIN { state = 0; injected = 0 }

# Match start of vfs_statx function
/^static int vfs_statx\(/ { state = 1 }

# Once inside vfs_statx, look for "int error;" line to inject call
state == 1 && /^[[:space:]]*int error;/ && !injected {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t/* Try ZeroMount hook for relative paths */"
    print "\tif (filename && dfd != AT_FDCWD) {"
    print "\t\tint zm_ret = zeromount_stat_hook(dfd, filename, stat, request_mask, flags);"
    print "\t\tif (zm_ret != -ENOENT)"
    print "\t\t\treturn zm_ret;"
    print "\t}"
    print "#endif"
    print ""
    injected = 1
    next
}

# Exit state on closing brace at start of line (function end)
state == 1 && /^}$/ { state = 0 }

{ print }

END {
    if (!injected) {
        print "INJECTION_FAILED" > "/dev/stderr"
        exit 1
    }
}
' "$STAT_FILE" > "${STAT_FILE}.tmp" || {
        echo "Error: awk injection failed"
        mv "${STAT_FILE}.bak" "$STAT_FILE"
        rm -f "${STAT_FILE}.tmp"
        return 1
    }

    mv "${STAT_FILE}.tmp" "$STAT_FILE"

    echo ""
    echo "Verifying injection..."

    local ERRORS=0

    if ! grep -q '#include <linux/zeromount.h>' "$STAT_FILE"; then
        echo "  [FAIL] zeromount.h include not found"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] zeromount.h include"
    fi

    if ! grep -q 'zeromount_stat_hook' "$STAT_FILE"; then
        echo "  [FAIL] zeromount_stat_hook function not found"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] zeromount_stat_hook function"
    fi

    if ! grep -q 'zeromount_build_absolute_path' "$STAT_FILE"; then
        echo "  [FAIL] zeromount_build_absolute_path call not found"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] zeromount_build_absolute_path call"
    fi

    if ! grep -q 'zeromount_resolve_path' "$STAT_FILE"; then
        echo "  [FAIL] zeromount_resolve_path call not found"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] zeromount_resolve_path call"
    fi

    echo ""
    if [ "$ERRORS" -eq 0 ]; then
        echo "ZeroMount stat hooks injection complete. Backup at ${STAT_FILE}.bak"
    else
        echo "Injection completed with $ERRORS verification failures."
        echo "Review the output and ${STAT_FILE}.bak if needed."
        return 1
    fi
}

# --- namei.c ---

inject_namei() {
    local TARGET="$KERNEL_DIR/fs/namei.c"
    local MARKER="CONFIG_ZEROMOUNT"

    if [[ ! -f "$TARGET" ]]; then
        echo "Error: File not found: $TARGET"
        return 1
    fi

    echo "Injecting ZeroMount hooks into: $TARGET"

    if check_already_injected "$TARGET" "$MARKER"; then
        return 0
    fi

    cp "$TARGET" "${TARGET}.bak"

    echo "  [1/4] Injecting zeromount.h include..."
    sed -i '/#include "mount.h"/a\
\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"

    if ! grep -q "zeromount.h" "$TARGET"; then
        echo "Error: Failed to inject include directive"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "  [2/4] Injecting getname_flags() hook..."

    sed -i '/audit_getname(result);/{
N
/\n[[:space:]]*return result;/s/audit_getname(result);/audit_getname(result);\
\
#ifdef CONFIG_ZEROMOUNT\
	if (!IS_ERR(result)) {\
		result = zeromount_getname_hook(result);\
	}\
#endif\
/
}' "$TARGET"

    if ! grep -q "zeromount_getname_hook" "$TARGET"; then
        echo "Error: Failed to inject getname_flags() hook"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "  [3/4] Injecting generic_permission() hook..."

    sed -i '/^int generic_permission(struct inode \*inode, int mask)$/,/^}$/{
/^{$/,/int ret;/{
/int ret;/a\
\
#ifdef CONFIG_ZEROMOUNT\
	if (zeromount_is_injected_file(inode)) {\
		if (mask \& MAY_WRITE)\
			return -EACCES;\
		return 0;\
	}\
\
	if (S_ISDIR(inode->i_mode) \&\& zeromount_is_traversal_allowed(inode, mask)) {\
		return 0;\
	}\
#endif
}
}' "$TARGET"

    if ! grep -A20 "^int generic_permission" "$TARGET" | grep -q "zeromount_is_injected_file"; then
        echo "Error: Failed to inject generic_permission() hook"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "  [4/4] Injecting inode_permission() hook..."

    sed -i '/^int inode_permission(struct inode \*inode, int mask)$/,/^}$/{
/^{$/,/int retval;/{
/int retval;/a\
\
#ifdef CONFIG_ZEROMOUNT\
	if (zeromount_is_injected_file(inode)) {\
		if (mask \& MAY_WRITE)\
			return -EACCES;\
		return 0;\
	}\
\
	if (S_ISDIR(inode->i_mode) \&\& zeromount_is_traversal_allowed(inode, mask)) {\
		return 0;\
	}\
#endif
}
}' "$TARGET"

    if ! grep -A20 "^int inode_permission" "$TARGET" | grep -q "zeromount_is_injected_file"; then
        echo "Error: Failed to inject inode_permission() hook"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "ZeroMount namei.c hooks injected successfully."
}

# --- readdir.c ---

inject_readdir() {
    local READDIR_FILE="$KERNEL_DIR/fs/readdir.c"

    if [ ! -f "$READDIR_FILE" ]; then
        echo "Error: File not found: $READDIR_FILE"
        return 1
    fi

    echo "Injecting ZeroMount readdir hooks into: $READDIR_FILE"

    if grep -q "CONFIG_ZEROMOUNT" "$READDIR_FILE"; then
        echo "File already contains ZeroMount hooks. Skipping."
        return 0
    fi

    if ! grep -q '#include <linux/uaccess.h>' "$READDIR_FILE"; then
        echo "Error: Cannot find #include <linux/uaccess.h>"
        return 1
    fi

    if ! grep -q 'SYSCALL_DEFINE3(getdents64,' "$READDIR_FILE"; then
        echo "Error: Cannot find SYSCALL_DEFINE3(getdents64,"
        return 1
    fi

    cp "$READDIR_FILE" "${READDIR_FILE}.bak"

    echo "  [1/4] Injecting zeromount.h include..."
    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$READDIR_FILE"

    echo "  [2/4] Injecting hooks into getdents..."
    awk '
BEGIN { state = 0 }

/^SYSCALL_DEFINE3\(getdents,/ { state = 1 }
state == 1 && /^SYSCALL_DEFINE3\(getdents64,/ { state = 0 }

state == 1 && /^[[:space:]]*int error;[[:space:]]*$/ && !var_done {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tint initial_count = count;"
    print "#endif"
    var_done = 1
    next
}

state == 1 && /return -EBADF;/ && !skip_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tif (f.file->f_pos >= ZEROMOUNT_MAGIC_POS) {"
    print "\t\terror = 0;"
    print "\t\tgoto skip_real_iterate;"
    print "\t}"
    print "#endif"
    skip_done = 1
    next
}

state == 1 && /error = buf\.error;/ && !inject_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "skip_real_iterate:"
    print "\tif (error >= 0 && !signal_pending(current)) {"
    print "\t\tzeromount_inject_dents(f.file, (void __user **)&dirent, &count, &f.file->f_pos);"
    print "\t\terror = initial_count - count;"
    print "\t\tgoto zm_out;"
    print "\t}"
    print "#endif"
    inject_done = 1
    next
}

# Place label before fdput_pos so zeromount can skip the original epilogue
state == 1 && /fdput_pos\(f\);/ && !out_done {
    print "#ifdef CONFIG_ZEROMOUNT"
    print "zm_out:"
    print "#endif"
    print
    out_done = 1
    next
}

{ print }
' "$READDIR_FILE" > "${READDIR_FILE}.tmp" && mv "${READDIR_FILE}.tmp" "$READDIR_FILE"

    echo "  [3/4] Injecting hooks into getdents64..."
    awk '
BEGIN { state = 0 }

/^SYSCALL_DEFINE3\(getdents64,/ { state = 1 }
state == 1 && /^COMPAT_SYSCALL_DEFINE3\(getdents,/ { state = 0 }
state == 1 && /^}$/ { state = 0 }

state == 1 && /^[[:space:]]*int error;[[:space:]]*$/ && !var_done {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tint initial_count = count;"
    print "#endif"
    var_done = 1
    next
}

state == 1 && /return -EBADF;/ && !skip_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tif (f.file->f_pos >= ZEROMOUNT_MAGIC_POS) {"
    print "\t\terror = 0;"
    print "\t\tgoto skip_real_iterate;"
    print "\t}"
    print "#endif"
    skip_done = 1
    next
}

state == 1 && /error = buf\.error;/ && !inject_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "skip_real_iterate:"
    print "\tif (error >= 0 && !signal_pending(current)) {"
    print "\t\tzeromount_inject_dents64(f.file, (void __user **)&dirent, &count, &f.file->f_pos);"
    print "\t\terror = initial_count - count;"
    print "\t\tgoto zm_out;"
    print "\t}"
    print "#endif"
    inject_done = 1
    next
}

state == 1 && /fdput_pos\(f\);/ && !out_done {
    print "#ifdef CONFIG_ZEROMOUNT"
    print "zm_out:"
    print "#endif"
    print
    out_done = 1
    next
}

{ print }
' "$READDIR_FILE" > "${READDIR_FILE}.tmp" && mv "${READDIR_FILE}.tmp" "$READDIR_FILE"

    echo "  [4/4] Injecting hooks into compat_getdents..."
    awk '
BEGIN { state = 0 }

/^COMPAT_SYSCALL_DEFINE3\(getdents,/ { state = 1 }
state == 1 && /^}$/ { state = 0 }

state == 1 && /^[[:space:]]*int error;[[:space:]]*$/ && !var_done {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tint initial_count = count;"
    print "#endif"
    var_done = 1
    next
}

state == 1 && /return -EBADF;/ && !skip_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tif (f.file->f_pos >= ZEROMOUNT_MAGIC_POS) {"
    print "\t\terror = 0;"
    print "\t\tgoto skip_real_iterate;"
    print "\t}"
    print "#endif"
    skip_done = 1
    next
}

state == 1 && /error = buf\.error;/ && !inject_done {
    print
    print ""
    print "#ifdef CONFIG_ZEROMOUNT"
    print "skip_real_iterate:"
    print "\tif (error >= 0 && !signal_pending(current)) {"
    print "\t\tzeromount_inject_dents(f.file, (void __user **)&dirent, &count, &f.file->f_pos);"
    print "\t\terror = initial_count - count;"
    print "\t\tgoto zm_out;"
    print "\t}"
    print "#endif"
    inject_done = 1
    next
}

state == 1 && /fdput_pos\(f\);/ && !out_done {
    print "#ifdef CONFIG_ZEROMOUNT"
    print "zm_out:"
    print "#endif"
    print
    out_done = 1
    next
}

{ print }
' "$READDIR_FILE" > "${READDIR_FILE}.tmp" && mv "${READDIR_FILE}.tmp" "$READDIR_FILE"

    echo ""
    echo "Verifying injection..."

    local ERRORS=0

    if ! grep -q '#include <linux/zeromount.h>' "$READDIR_FILE"; then
        echo "  [FAIL] zeromount.h include not found"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] zeromount.h include"
    fi

    local INITIAL_COUNT
    INITIAL_COUNT=$(grep -c 'int initial_count = count;' "$READDIR_FILE" || true)
    if [ "$INITIAL_COUNT" -ne 3 ]; then
        echo "  [FAIL] Expected 3 initial_count declarations, found $INITIAL_COUNT"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 3 initial_count declarations"
    fi

    local SKIP_LABELS
    SKIP_LABELS=$(grep -c '^skip_real_iterate:' "$READDIR_FILE" || true)
    if [ "$SKIP_LABELS" -ne 3 ]; then
        echo "  [FAIL] Expected 3 skip_real_iterate labels, found $SKIP_LABELS"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 3 skip_real_iterate labels"
    fi

    local INJECT64
    INJECT64=$(grep -c 'zeromount_inject_dents64' "$READDIR_FILE" || true)
    if [ "$INJECT64" -ne 1 ]; then
        echo "  [FAIL] Expected 1 zeromount_inject_dents64 call, found $INJECT64"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 1 zeromount_inject_dents64 call"
    fi

    local INJECT32
    INJECT32=$(grep -c 'zeromount_inject_dents(' "$READDIR_FILE" || true)
    if [ "$INJECT32" -ne 2 ]; then
        echo "  [FAIL] Expected 2 zeromount_inject_dents calls, found $INJECT32"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 2 zeromount_inject_dents calls"
    fi

    local MAGIC_POS
    MAGIC_POS=$(grep -c 'ZEROMOUNT_MAGIC_POS' "$READDIR_FILE" || true)
    if [ "$MAGIC_POS" -ne 3 ]; then
        echo "  [FAIL] Expected 3 ZEROMOUNT_MAGIC_POS checks, found $MAGIC_POS"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 3 ZEROMOUNT_MAGIC_POS checks"
    fi

    local ZM_OUT_LABELS
    ZM_OUT_LABELS=$(grep -c '^zm_out:' "$READDIR_FILE" || true)
    if [ "$ZM_OUT_LABELS" -ne 3 ]; then
        echo "  [FAIL] Expected 3 zm_out labels, found $ZM_OUT_LABELS"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [OK] 3 zm_out labels"
    fi

    echo ""
    if [ "$ERRORS" -eq 0 ]; then
        echo "ZeroMount readdir hooks injection complete. Backup at ${READDIR_FILE}.bak"
    else
        echo "Injection completed with $ERRORS verification failures. Restoring backup."
        mv "${READDIR_FILE}.bak" "$READDIR_FILE"
        return 1
    fi
}

# --- d_path.c ---

inject_dpath() {
    local TARGET="$KERNEL_DIR/fs/d_path.c"
    local MARKER="CONFIG_ZEROMOUNT"

    if [[ ! -f "$TARGET" ]]; then
        echo "Error: File not found: $TARGET"
        return 1
    fi

    echo "Injecting ZeroMount hooks into: $TARGET"

    if check_already_injected "$TARGET" "$MARKER"; then
        return 0
    fi

    cp "$TARGET" "${TARGET}.bak"

    echo "  [1/2] Injecting zeromount.h include..."
    sed -i '/#include "mount.h"/a\
\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"

    if ! grep -q "zeromount.h" "$TARGET"; then
        echo "Error: Failed to inject include directive"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "  [2/2] Injecting d_path() virtual path spoofing hook..."

    # d_path function signature and local vars:
    #   char *d_path(const struct path *path, char *buf, int buflen)
    #   {
    #       char *res = buf + buflen;
    #       struct path root;
    #       int error;
    #
    # We inject after "int error;" to spoof virtual paths for injected files.
    # F3: uses zeromount_get_static_vpath (no kstrdup/kfree needed)

    awk '
    /^char \*d_path\(const struct path \*path, char \*buf, int buflen\)$/ {
        in_dpath = 1
    }
    in_dpath && /^	int error;$/ {
        print $0
        print ""
        print "#ifdef CONFIG_ZEROMOUNT"
        print "\tif (path->dentry && d_backing_inode(path->dentry)) {"
        print "\t\tconst char *v_path = zeromount_get_static_vpath(d_backing_inode(path->dentry));"
        print ""
        print "\t\tif (v_path) {"
        print "\t\t\tint len = strlen(v_path);"
        print "\t\t\tif (buflen < len + 1)"
        print "\t\t\t\treturn ERR_PTR(-ENAMETOOLONG);"
        print "\t\t\t*--res = '"'"'\\0'"'"';"
        print "\t\t\tres -= len;"
        print "\t\t\tmemcpy(res, v_path, len);"
        print "\t\t\treturn res;"
        print "\t\t}"
        print "\t}"
        print "#endif"
        print ""
        in_dpath = 0
        next
    }
    { print }
    ' "$TARGET" > "${TARGET}.tmp" && mv "${TARGET}.tmp" "$TARGET"

    if ! grep -q "zeromount_get_static_vpath" "$TARGET"; then
        echo "Error: Failed to inject d_path() hook"
        mv "${TARGET}.bak" "$TARGET"
        return 1
    fi

    echo "ZeroMount d_path.c hooks injected successfully."
}

# --- statfs.c ---

inject_statfs() {
    local TARGET="$KERNEL_DIR/fs/statfs.c"

    echo "[INFO] ZeroMount statfs hook injection"
    echo "[INFO] Target: $TARGET"

    if [ ! -f "$TARGET" ]; then
        echo "[ERROR] Target file not found: $TARGET"
        return 1
    fi

    if grep -q "zeromount_spoof_statfs" "$TARGET"; then
        echo "[INFO] Hooks already present - skipping"
        return 0
    fi

    cp "$TARGET" "${TARGET}.orig"

    echo "[INFO] Injecting include..."
    sed -i '/#include "internal\.h"/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"

    if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
        echo "[ERROR] Failed to inject include"
        mv "${TARGET}.orig" "$TARGET"
        return 1
    fi
    echo "[OK] Include injected"

    echo "[INFO] Injecting user_statfs hook..."

    # awk state machine: only inject inside user_statfs() function
    awk '
BEGIN { in_user_statfs = 0; var_injected = 0; call_injected = 0 }

# Enter user_statfs function (matches "int user_statfs(" at function definition)
/^int user_statfs\(/ { in_user_statfs = 1 }

# Exit on next function definition or closing brace at column 0
in_user_statfs && /^[a-z].*\(/ && !/^int user_statfs/ { in_user_statfs = 0 }
in_user_statfs && /^}$/ { in_user_statfs = 0 }

# Inject variable declaration after "if (!error) {" inside user_statfs only
in_user_statfs && /if \(!error\) \{/ && !var_injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tint spoofed;"
    print "#endif"
    var_injected = 1
    next
}

# Inject call after "error = vfs_statfs(&path, st);" inside user_statfs only
in_user_statfs && /error = vfs_statfs\(&path, st\);/ && !call_injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tspoofed = zeromount_spoof_statfs(pathname, st);"
    print "\t\t(void)spoofed;"
    print "#endif"
    call_injected = 1
    next
}

{ print }
' "$TARGET" > "${TARGET}.tmp" && mv "${TARGET}.tmp" "$TARGET"

    if ! grep -q 'zeromount_spoof_statfs' "$TARGET"; then
        echo "[ERROR] Failed to inject user_statfs hook"
        mv "${TARGET}.orig" "$TARGET"
        return 1
    fi
    echo "[OK] user_statfs hook injected"

    rm -f "${TARGET}.orig"

    echo "[SUCCESS] ZeroMount statfs hooks injected"
    echo "  - Include: <linux/zeromount.h>"
    echo "  - Hook: user_statfs() -> zeromount_spoof_statfs(pathname, st)"
}

# --- xattr.c ---

inject_xattr() {
    local TARGET="$KERNEL_DIR/fs/xattr.c"

    echo "[INFO] ZeroMount xattr hook injection"
    echo "[INFO] Target: $TARGET"

    if [ ! -f "$TARGET" ]; then
        echo "[ERROR] Target file not found: $TARGET"
        return 1
    fi

    if grep -q "zeromount_spoof_xattr" "$TARGET"; then
        echo "[INFO] Hooks already present - skipping"
        return 0
    fi

    cp "$TARGET" "${TARGET}.orig"

    echo "[INFO] Injecting include..."
    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"

    if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
        echo "[ERROR] Failed to inject include"
        mv "${TARGET}.orig" "$TARGET"
        return 1
    fi
    echo "[OK] Include injected"

    echo "[INFO] Injecting vfs_getxattr hook..."

    # awk state machine handles split function signatures (return type on separate line)
    awk '
BEGIN { in_vfs_getxattr = 0; injected = 0; held_line = "" }

# Hold "ssize_t" alone on a line to check next line
/^ssize_t$/ && held_line == "" {
    held_line = $0
    next
}

# Process line after held ssize_t
held_line != "" {
    if (/^vfs_getxattr\(/) {
        in_vfs_getxattr = 1
    }
    print held_line
    held_line = ""
}

# Also handle single-line signature: "ssize_t vfs_getxattr("
/^ssize_t vfs_getxattr\(/ { in_vfs_getxattr = 1 }

# Find opening brace of function body
in_vfs_getxattr && /^\{$/ && !injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tssize_t zm_ret;"
    print "\tzm_ret = zeromount_spoof_xattr(dentry, name, value, size);"
    print "\tif (zm_ret != -EOPNOTSUPP)"
    print "\t\treturn zm_ret;"
    print "#endif"
    injected = 1
    in_vfs_getxattr = 0
    next
}

{ print }

END {
    if (held_line != "") print held_line
}
' "$TARGET" > "${TARGET}.tmp" && mv "${TARGET}.tmp" "$TARGET"

    if ! grep -q 'zeromount_spoof_xattr' "$TARGET"; then
        echo "[ERROR] Failed to inject vfs_getxattr hook"
        mv "${TARGET}.orig" "$TARGET"
        return 1
    fi
    echo "[OK] vfs_getxattr hook injected"

    rm -f "${TARGET}.orig"

    echo "[SUCCESS] ZeroMount xattr hooks injected"
    echo "  - Include: <linux/zeromount.h>"
    echo "  - Hook: vfs_getxattr() -> zeromount_spoof_xattr(dentry, name, value, size)"
}

# --- Execute all injections in order ---

echo "============================================"
echo "ZeroMount VFS hooks injection"
echo "Kernel source: $KERNEL_DIR"
echo "============================================"
echo ""

inject_stat
echo ""
inject_namei
echo ""
inject_readdir
echo ""
inject_dpath
echo ""
inject_statfs
echo ""
inject_xattr

echo ""
echo "============================================"
echo "All ZeroMount VFS hooks injected successfully"
echo "============================================"
