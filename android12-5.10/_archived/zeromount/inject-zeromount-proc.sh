#!/bin/bash
# inject-zeromount-proc.sh — /proc spoofing hooks for ZeroMount
#
# Hooks show_map_vma() in task_mmu.c for dev/ino spoofing in /proc/PID/maps,
# and do_proc_readlink() in base.c for fd path spoofing in /proc/PID/fd.
#
# Usage: ./inject-zeromount-proc.sh <kernel-source-dir>

set -e

KERNEL_DIR="${1:?Usage: $0 <kernel-source-dir>}"

already_injected() {
    grep -q "$2" "$1" 2>/dev/null
}

verify_symbol() {
    local file="$1" symbol="$2"
    if ! grep -q "$symbol" "$file"; then
        echo "  FAIL: $symbol not found in $file"
        return 1
    fi
    echo "  ok: $symbol"
}

inject_include() {
    local file="$1"
    shift
    local anchors=("$@")

    for anchor in "${anchors[@]}"; do
        if grep -q "$anchor" "$file"; then
            sed -i "/${anchor//\//\\/}/a\\
#ifdef CONFIG_ZEROMOUNT\\
#include <linux/zeromount.h>\\
#endif" "$file"
            return 0
        fi
    done

    return 1
}

# --- /proc/PID/maps: spoof dev/ino for mmap'd redirected files ---

inject_procmaps() {
    local f="$KERNEL_DIR/fs/proc/task_mmu.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "zeromount_spoof_mmap_metadata" && { echo "task_mmu.c: already injected"; return 0; }

    if ! grep -q 'ino = inode->i_ino;' "$f"; then
        echo "Error: anchor 'ino = inode->i_ino;' not found in task_mmu.c"
        return 1
    fi

    cp "$f" "${f}.bak"

    inject_include "$f" \
        '#include <linux/pkeys.h>' \
        '#include <linux/uaccess.h>' \
        '#include <linux/pagemap.h>' || {
        echo "Error: no suitable include anchor in task_mmu.c"
        mv "${f}.bak" "$f"
        return 1
    }

    if ! grep -q '#include <linux/zeromount.h>' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    awk '
BEGIN { in_func = 0; injected = 0 }

/^static void$/ { maybe_func = 1; print; next }
maybe_func && /^show_map_vma\(/ { in_func = 1; maybe_func = 0 }
maybe_func { maybe_func = 0 }

/^static void show_map_vma\(/ { in_func = 1 }

in_func && /ino = inode->i_ino;/ && !injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tzeromount_spoof_mmap_metadata(inode, &dev, &ino);"
    print "#endif"
    injected = 1
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
' "$f" > "${f}.tmp" || { mv "${f}.bak" "$f"; rm -f "${f}.tmp"; return 1; }

    mv "${f}.tmp" "$f"

    local errors=0
    verify_symbol "$f" 'zeromount.h' || errors=$((errors + 1))
    verify_symbol "$f" 'zeromount_spoof_mmap_metadata' || errors=$((errors + 1))

    if [ "$errors" -gt 0 ]; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "task_mmu.c: injected"
}

# --- /proc/PID/fd: spoof readlink for redirected file descriptors ---

inject_procfd() {
    local f="$KERNEL_DIR/fs/proc/base.c"
    [ ! -f "$f" ] && { echo "Error: $f not found"; return 1; }
    already_injected "$f" "zeromount_get_static_vpath" && { echo "base.c: already injected"; return 0; }

    if ! grep -q 'static int do_proc_readlink' "$f"; then
        echo "Error: do_proc_readlink not found in base.c"
        return 1
    fi

    cp "$f" "${f}.bak"

    inject_include "$f" \
        '#include "internal.h"' \
        '#include <linux/sched.h>' || {
        # Fallback: after first #include
        sed -i '0,/#include/{/#include/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif
}' "$f"
    }

    if ! grep -q '#include <linux/zeromount.h>' "$f"; then
        mv "${f}.bak" "$f"
        return 1
    fi

    awk '
BEGIN { in_func = 0; injected = 0; found_enomem = 0 }

/^static int do_proc_readlink/ { in_func = 1 }

in_func && /return -ENOMEM;/ {
    found_enomem = 1
    print
    next
}

in_func && found_enomem && !injected {
    if (/d_path/ || /pathname/) {
        print ""
        print "#ifdef CONFIG_ZEROMOUNT"
        print "\tif (!zeromount_should_skip() && path->dentry) {"
        print "\t\tstruct inode *inode = d_backing_inode(path->dentry);"
        print "\t\tif (inode) {"
        print "\t\t\tchar *vpath = zeromount_get_static_vpath(inode);"
        print "\t\t\tif (vpath) {"
        print "\t\t\t\tint vlen = strlen(vpath);"
        print "\t\t\t\tif (vlen > buflen)"
        print "\t\t\t\t\tvlen = buflen;"
        print "\t\t\t\tif (copy_to_user(buffer, vpath, vlen) == 0) {"
        print "\t\t\t\t\tkfree(vpath);"
        print "\t\t\t\t\tfree_page((unsigned long)tmp);"
        print "\t\t\t\t\treturn vlen;"
        print "\t\t\t\t}"
        print "\t\t\t\tkfree(vpath);"
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
' "$f" > "${f}.tmp" || { mv "${f}.bak" "$f"; rm -f "${f}.tmp"; return 1; }

    mv "${f}.tmp" "$f"

    local errors=0
    verify_symbol "$f" 'zeromount.h' || errors=$((errors + 1))
    verify_symbol "$f" 'zeromount_get_static_vpath' || errors=$((errors + 1))
    verify_symbol "$f" 'zeromount_should_skip' || errors=$((errors + 1))

    if [ "$errors" -gt 0 ]; then
        mv "${f}.bak" "$f"
        return 1
    fi

    rm -f "${f}.bak"
    echo "base.c: injected"
}

echo "ZeroMount /proc spoofing injection — $KERNEL_DIR"
echo ""

inject_procmaps
inject_procfd

echo ""
echo "All /proc hooks injected"
