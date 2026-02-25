#!/bin/bash
# inject-zeromount-vfs.sh — VFS hook injection for ZeroMount
#
# Injects zeromount hooks into: stat.c, namei.c, readdir.c, d_path.c,
# statfs.c, xattr.c. Execution order matters.
#
# Usage: ./inject-zeromount-vfs.sh <kernel-source-dir>

set -e

KERNEL_DIR="${1:?Usage: $0 <kernel-source-dir>}"

if [ ! -d "$KERNEL_DIR/fs" ]; then
    echo "Error: $KERNEL_DIR/fs not found"
    exit 1
fi

already_injected() {
    grep -q "$2" "$1" 2>/dev/null
}

verify_anchor() {
    local file="$1" pattern="$2" label="$3"
    if ! grep -q "$pattern" "$file"; then
        echo "Error: anchor not found in $file: $label"
        return 1
    fi
}

verify_symbol() {
    local file="$1" symbol="$2"
    if ! grep -q "$symbol" "$file"; then
        echo "  FAIL: $symbol not found in $file"
        return 1
    fi
    echo "  ok: $symbol"
}

inject_stat() {
    local f="$KERNEL_DIR/fs/stat.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "CONFIG_ZEROMOUNT" && { echo "stat.c: already injected"; return 0; }

    verify_anchor "$f" '#include <linux/uaccess.h>' 'uaccess.h include' || return 1
    verify_anchor "$f" 'static int vfs_statx' 'vfs_statx function' || return 1

    cp "$f" "${f}.bak"

    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    sed -i '/^static int vfs_statx(/i\
#ifdef CONFIG_ZEROMOUNT\
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
#endif' "$f"

    awk '
BEGIN { state = 0; injected = 0 }
/^static int vfs_statx\(/ { state = 1 }
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
state == 1 && /^}$/ { state = 0 }
{ print }
END { if (!injected) { print "INJECTION_FAILED" > "/dev/stderr"; exit 1 } }
' "$f" > "${f}.tmp" || { mv "${f}.bak" "$f"; rm -f "${f}.tmp"; return 1; }

    mv "${f}.tmp" "$f"

    verify_symbol "$f" 'zeromount.h' || { mv "${f}.bak" "$f"; return 1; }
    verify_symbol "$f" 'zeromount_stat_hook' || { mv "${f}.bak" "$f"; return 1; }
    verify_symbol "$f" 'zeromount_build_absolute_path' || { mv "${f}.bak" "$f"; return 1; }
    verify_symbol "$f" 'zeromount_resolve_path' || { mv "${f}.bak" "$f"; return 1; }

    rm -f "${f}.bak"
    echo "stat.c: injected"
}

inject_namei() {
    local f="$KERNEL_DIR/fs/namei.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "CONFIG_ZEROMOUNT" && { echo "namei.c: already injected"; return 0; }

    cp "$f" "${f}.bak"

    sed -i '/#include "mount.h"/a\
\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    if ! grep -q "zeromount.h" "$f"; then
        echo "Error: failed to inject include into namei.c"
        mv "${f}.bak" "$f"
        return 1
    fi

    # getname_flags() hook
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
}' "$f"

    if ! grep -q "zeromount_getname_hook" "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    # generic_permission() hook
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
}' "$f"

    if ! grep -A20 "^int generic_permission" "$f" | grep -q "zeromount_is_injected_file"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    # inode_permission() hook
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
}' "$f"

    if ! grep -A20 "^int inode_permission" "$f" | grep -q "zeromount_is_injected_file"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "namei.c: injected"
}

inject_readdir_syscall() {
    local file="$1" start_pattern="$2" end_pattern="$3" inject_fn="$4"

    awk -v start="$start_pattern" -v endpat="$end_pattern" -v fn="$inject_fn" '
BEGIN { state = 0 }
$0 ~ start { state = 1 }
state == 1 && $0 ~ endpat { state = 0 }

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
    printf "\t\t%s(f.file, (void __user **)&dirent, &count, &f.file->f_pos);\n", fn
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
' "$file"
}

inject_readdir() {
    local f="$KERNEL_DIR/fs/readdir.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "CONFIG_ZEROMOUNT" && { echo "readdir.c: already injected"; return 0; }

    verify_anchor "$f" '#include <linux/uaccess.h>' 'uaccess.h include' || return 1
    verify_anchor "$f" 'SYSCALL_DEFINE3(getdents64,' 'getdents64 syscall' || return 1

    cp "$f" "${f}.bak"

    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    # getdents (32-bit)
    inject_readdir_syscall "$f" \
        '^SYSCALL_DEFINE3[(]getdents,' \
        '^SYSCALL_DEFINE3[(]getdents64,' \
        'zeromount_inject_dents' > "${f}.tmp" && mv "${f}.tmp" "$f"

    # getdents64
    inject_readdir_syscall "$f" \
        '^SYSCALL_DEFINE3[(]getdents64,' \
        '^COMPAT_SYSCALL_DEFINE3[(]getdents,' \
        'zeromount_inject_dents64' > "${f}.tmp" && mv "${f}.tmp" "$f"

    # compat_getdents
    inject_readdir_syscall "$f" \
        '^COMPAT_SYSCALL_DEFINE3[(]getdents,' \
        'NEVERMATCH' \
        'zeromount_inject_dents' > "${f}.tmp" && mv "${f}.tmp" "$f"

    local errors=0

    verify_symbol "$f" 'zeromount.h' || errors=$((errors + 1))

    local count
    count=$(grep -c 'int initial_count = count;' "$f" || true)
    [ "$count" -ne 3 ] && { echo "  FAIL: expected 3 initial_count, got $count"; errors=$((errors + 1)); }

    count=$(grep -c '^skip_real_iterate:' "$f" || true)
    [ "$count" -ne 3 ] && { echo "  FAIL: expected 3 skip_real_iterate, got $count"; errors=$((errors + 1)); }

    count=$(grep -c 'zeromount_inject_dents64' "$f" || true)
    [ "$count" -ne 1 ] && { echo "  FAIL: expected 1 inject_dents64, got $count"; errors=$((errors + 1)); }

    count=$(grep -c 'zeromount_inject_dents(' "$f" || true)
    [ "$count" -ne 2 ] && { echo "  FAIL: expected 2 inject_dents, got $count"; errors=$((errors + 1)); }

    count=$(grep -c 'ZEROMOUNT_MAGIC_POS' "$f" || true)
    [ "$count" -ne 3 ] && { echo "  FAIL: expected 3 MAGIC_POS, got $count"; errors=$((errors + 1)); }

    count=$(grep -c '^zm_out:' "$f" || true)
    [ "$count" -ne 3 ] && { echo "  FAIL: expected 3 zm_out, got $count"; errors=$((errors + 1)); }

    if [ "$errors" -gt 0 ]; then
        echo "readdir.c: injection failed ($errors errors), restoring"
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "readdir.c: injected"
}

inject_dpath() {
    local f="$KERNEL_DIR/fs/d_path.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "CONFIG_ZEROMOUNT" && { echo "d_path.c: already injected"; return 0; }

    cp "$f" "${f}.bak"

    sed -i '/#include "mount.h"/a\
\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    if ! grep -q "zeromount.h" "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    awk '
    /^char \*d_path\(const struct path \*path, char \*buf, int buflen\)$/ {
        in_dpath = 1
    }
    in_dpath && /^	int error;$/ {
        print $0
        print ""
        print "#ifdef CONFIG_ZEROMOUNT"
        print "\tif (path->dentry && d_backing_inode(path->dentry)) {"
        print "\t\tchar *v_path = zeromount_get_static_vpath(d_backing_inode(path->dentry));"
        print ""
        print "\t\tif (v_path) {"
        print "\t\t\tint len = strlen(v_path);"
        print "\t\t\tif (buflen < len + 1) {"
        print "\t\t\t\tkfree(v_path);"
        print "\t\t\t\treturn ERR_PTR(-ENAMETOOLONG);"
        print "\t\t\t}"
        print "\t\t\t*--res = '"'"'\\0'"'"';"
        print "\t\t\tres -= len;"
        print "\t\t\tmemcpy(res, v_path, len);"
        print "\t\t\tkfree(v_path);"
        print "\t\t\treturn res;"
        print "\t\t}"
        print "\t}"
        print "#endif"
        print ""
        in_dpath = 0
        next
    }
    { print }
    ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"

    if ! grep -q "zeromount_get_static_vpath" "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "d_path.c: injected"
}

inject_statfs() {
    local f="$KERNEL_DIR/fs/statfs.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "zeromount_spoof_statfs" && { echo "statfs.c: already injected"; return 0; }

    cp "$f" "${f}.bak"

    sed -i '/#include "internal\.h"/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    if ! grep -q '#include <linux/zeromount.h>' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    awk '
BEGIN { in_fn = 0; var_injected = 0; call_injected = 0 }
/^int user_statfs\(/ { in_fn = 1 }
in_fn && /^[a-z].*\(/ && !/^int user_statfs/ { in_fn = 0 }
in_fn && /^}$/ { in_fn = 0 }

in_fn && /if \(!error\) \{/ && !var_injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tint spoofed;"
    print "#endif"
    var_injected = 1
    next
}

in_fn && /error = vfs_statfs\(&path, st\);/ && !call_injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tspoofed = zeromount_spoof_statfs(pathname, st);"
    print "\t\t(void)spoofed;"
    print "#endif"
    call_injected = 1
    next
}

{ print }
' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"

    if ! grep -q 'zeromount_spoof_statfs' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "statfs.c: injected"
}

inject_xattr() {
    local f="$KERNEL_DIR/fs/xattr.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "zeromount_spoof_xattr" && { echo "xattr.c: already injected"; return 0; }

    cp "$f" "${f}.bak"

    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$f"

    if ! grep -q '#include <linux/zeromount.h>' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    awk '
BEGIN { in_fn = 0; injected = 0; held_line = "" }

/^ssize_t$/ && held_line == "" {
    held_line = $0
    next
}

held_line != "" {
    if (/^vfs_getxattr\(/) {
        in_fn = 1
    }
    print held_line
    held_line = ""
}

/^ssize_t vfs_getxattr\(/ { in_fn = 1 }

in_fn && /^\{$/ && !injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\tssize_t zm_ret;"
    print "\tzm_ret = zeromount_spoof_xattr(dentry, name, value, size);"
    print "\tif (zm_ret != -EOPNOTSUPP)"
    print "\t\treturn zm_ret;"
    print "#endif"
    injected = 1
    in_fn = 0
    next
}

{ print }

END { if (held_line != "") print held_line }
' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"

    if ! grep -q 'zeromount_spoof_xattr' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "xattr.c: injected"
}

echo "ZeroMount VFS injection — $KERNEL_DIR"
echo ""

inject_stat
inject_namei
inject_readdir
inject_dpath
inject_statfs
inject_xattr

echo ""
echo "All VFS hooks injected"
