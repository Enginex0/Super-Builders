#!/bin/bash
# inject-zeromount-xattr.sh - Inject ZeroMount xattr spoofing hooks into fs/xattr.c

set -e

TARGET="${1:-fs/xattr.c}"

echo "[INFO] ZeroMount xattr hook injection"
echo "[INFO] Target: $TARGET"

if [ ! -f "$TARGET" ]; then
    echo "[ERROR] Target file not found: $TARGET"
    exit 1
fi

if grep -q "zeromount_spoof_xattr" "$TARGET"; then
    echo "[INFO] Hooks already present - skipping"
    exit 0
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
    exit 1
fi
echo "[OK] Include injected"

echo "[INFO] Injecting vfs_getxattr hook..."

# 5.15: vfs_getxattr has declarations (struct inode, int error) — inject after
# last declaration with compound statement to avoid C89 mixed-declaration error
awk '
BEGIN { in_vfs_getxattr = 0; in_body = 0; injected = 0; held_line = "" }

/^ssize_t$/ && held_line == "" {
    held_line = $0
    next
}

held_line != "" {
    if (/^vfs_getxattr\(/) {
        in_vfs_getxattr = 1
    }
    print held_line
    held_line = ""
}

/^ssize_t vfs_getxattr\(/ { in_vfs_getxattr = 1 }

in_vfs_getxattr && /^\{$/ { in_body = 1 }

in_body && /^\tint error;$/ && !injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t{"
    print "\t\tssize_t zm_ret = zeromount_spoof_xattr(dentry, name, value, size);"
    print "\t\tif (zm_ret != -EOPNOTSUPP)"
    print "\t\t\treturn zm_ret;"
    print "\t}"
    print "#endif"
    injected = 1
    in_vfs_getxattr = 0
    in_body = 0
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
    exit 1
fi
echo "[OK] vfs_getxattr hook injected"

rm -f "${TARGET}.orig"

echo "[SUCCESS] ZeroMount xattr hooks injected"
echo "  - Include: <linux/zeromount.h>"
echo "  - Hook: vfs_getxattr() -> zeromount_spoof_xattr(dentry, name, value, size)"
exit 0
