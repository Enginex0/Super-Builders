#!/bin/bash
# inject-zeromount-procfd.sh - Hook do_proc_readlink() for fd path spoofing (F2)
#
# Detection vector: readlink("/proc/self/fd/N") on an fd pointing to a
# redirected file returns the real backing path via d_path(). A detector
# can compare this against the expected virtual path — mismatch = detection.
#
# Hook: In do_proc_readlink(), before calling d_path(), check if the
# dentry's inode has a virtual path via zeromount_get_static_vpath().
# If so, copy_to_user the virtual path directly and return.
#
# Target: fs/proc/base.c
# Kernel: 5.10 (android12-5.10)
#
# Usage: ./inject-zeromount-procfd.sh <kernel-source-dir>

set -e

KERNEL_DIR="${1:?Usage: $0 <kernel-source-dir>}"
TARGET="$KERNEL_DIR/fs/proc/base.c"

if [ ! -f "$TARGET" ]; then
    echo "[ERROR] File not found: $TARGET"
    exit 1
fi

echo "[INFO] ZeroMount /proc/PID/fd readlink spoofing injection (F2)"
echo "[INFO] Target: $TARGET"

if grep -q "zeromount_get_static_vpath" "$TARGET"; then
    echo "[INFO] Hook already present — skipping"
    exit 0
fi

# Verify do_proc_readlink exists
if ! grep -q 'static int do_proc_readlink' "$TARGET"; then
    echo "[ERROR] Cannot find do_proc_readlink function"
    exit 1
fi

cp "$TARGET" "${TARGET}.bak"

# [1/2] Inject #include <linux/zeromount.h>
echo "[INFO] [1/2] Injecting zeromount.h include..."

if grep -q '#include "internal.h"' "$TARGET"; then
    sed -i '/#include "internal.h"/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"
elif grep -q '#include <linux/sched.h>' "$TARGET"; then
    sed -i '/#include <linux\/sched.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"
else
    # Fallback: add after first #include block
    sed -i '0,/#include/{/#include/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif
}' "$TARGET"
fi

if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
    echo "[ERROR] Failed to inject include"
    mv "${TARGET}.bak" "$TARGET"
    exit 1
fi
echo "[OK] Include injected"

# [2/2] Inject hook into do_proc_readlink
echo "[INFO] [2/2] Injecting do_proc_readlink hook..."

# do_proc_readlink structure in 5.10:
#   static int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
#   {
#       char *tmp = (char *)__get_free_page(GFP_KERNEL);
#       char *pathname;
#       int len;
#
#       if (!tmp)
#           return -ENOMEM;
#
#       pathname = d_path(path, tmp, PAGE_SIZE);
#       ...
#
# Inject after "if (!tmp)" / "return -ENOMEM;" block, before d_path call.

awk '
BEGIN { in_func = 0; injected = 0; found_enomem = 0 }

/^static int do_proc_readlink/ { in_func = 1 }

# After the ENOMEM return, inject the hook
in_func && /return -ENOMEM;/ {
    found_enomem = 1
    print
    next
}

in_func && found_enomem && !injected {
    # This line should be the closing brace or blank after ENOMEM
    # We inject before the d_path call
    if (/d_path/ || /pathname/) {
        print ""
        print "#ifdef CONFIG_ZEROMOUNT"
        print "\tif (!zeromount_should_skip() && path->dentry) {"
        print "\t\tstruct inode *inode = d_backing_inode(path->dentry);"
        print "\t\tif (inode) {"
        print "\t\t\tconst char *vpath = zeromount_get_static_vpath(inode);"
        print "\t\t\tif (vpath) {"
        print "\t\t\t\tint vlen = strlen(vpath);"
        print "\t\t\t\tif (vlen > buflen)"
        print "\t\t\t\t\tvlen = buflen;"
        print "\t\t\t\tif (copy_to_user(buffer, vpath, vlen) == 0) {"
        print "\t\t\t\t\tfree_page((unsigned long)tmp);"
        print "\t\t\t\t\treturn vlen;"
        print "\t\t\t\t}"
        print "\t\t\t}"
        print "\t\t}"
        print "\t}"
        print "#endif"
        print ""
        injected = 1
    }
    print
    next
}

in_func && /^}$/ { in_func = 0 }

{ print }

END {
    if (!injected) {
        print "INJECTION_FAILED" > "/dev/stderr"
        exit 1
    }
}
' "$TARGET" > "${TARGET}.tmp" || {
    echo "[ERROR] awk injection failed"
    mv "${TARGET}.bak" "$TARGET"
    rm -f "${TARGET}.tmp"
    exit 1
}

mv "${TARGET}.tmp" "$TARGET"

# Verify
echo "[INFO] Verifying injection..."
ERRORS=0

if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
    echo "  [FAIL] zeromount.h include not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  [OK] zeromount.h include"
fi

if ! grep -q 'zeromount_get_static_vpath' "$TARGET"; then
    echo "  [FAIL] zeromount_get_static_vpath call not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  [OK] zeromount_get_static_vpath call"
fi

if ! grep -q 'zeromount_should_skip' "$TARGET"; then
    echo "  [FAIL] zeromount_should_skip guard not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  [OK] zeromount_should_skip guard"
fi

if [ "$ERRORS" -eq 0 ]; then
    echo "[SUCCESS] ZeroMount /proc/PID/fd readlink spoofing hook injected"
    echo "  - Include: <linux/zeromount.h>"
    echo "  - Hook: do_proc_readlink() -> zeromount_get_static_vpath(inode)"
    rm -f "${TARGET}.bak"
else
    echo "[ERROR] Injection failed with $ERRORS errors. Restoring backup."
    mv "${TARGET}.bak" "$TARGET"
    exit 1
fi
