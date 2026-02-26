#!/bin/bash
# fix-zeromount-susfs.sh — SUSFS umount bypass for ZeroMount
#
# Adds susfs_is_current_proc_umounted() early-return checks to all
# ZeroMount public functions so umounted processes see stock behavior.
#
# Usage: ./fix-zeromount-susfs.sh [path/to/fs/zeromount.c]

set -e

ZEROMOUNT_C="${1:-fs/zeromount.c}"

if [ ! -f "$ZEROMOUNT_C" ]; then
    echo "Error: $ZEROMOUNT_C not found"
    exit 1
fi

existing=$(grep -c "susfs_is_current_proc_umounted" "$ZEROMOUNT_C" 2>/dev/null || echo 0)
if [ "$existing" -eq 10 ]; then
    echo "SUSFS bypass checks already present (10/10)"
    exit 0
fi
if [ "$existing" -gt 10 ]; then
    echo "Error: $existing susfs_is_current_proc_umounted occurrences found (expected 1 or 10) — file may be double-injected"
    exit 1
fi

# susfs.h include
if ! grep -q '#include <linux/susfs.h>' "$ZEROMOUNT_C"; then
    sed -i '/#include <linux\/zeromount.h>/a\
#ifdef CONFIG_KSU_SUSFS\
#include <linux/susfs.h>\
#endif' "$ZEROMOUNT_C"
fi

# Single awk pass: inject susfs_is_current_proc_umounted() after the first
# early-return guard in each target function. Uses function-entry detection
# + a per-function "done" flag to inject exactly once.
awk '
BEGIN {
    fn = ""
    saw_guard = 0
    injected["uid_blocked"] = 0
    injected["traversal"] = 0
    injected["injected_file"] = 0
    injected["resolve_path"] = 0
    injected["getname_hook"] = 0
    injected["dents_common"] = 0
    injected["spoof_statfs"] = 0
    injected["spoof_xattr"] = 0
    injected["vpath_inode"] = 0
}

/^bool zeromount_is_uid_blocked\(/          { fn = "uid_blocked"; saw_guard = 0 }
/^bool zeromount_is_traversal_allowed\(/    { fn = "traversal"; saw_guard = 0 }
/^bool zeromount_is_injected_file\(/        { fn = "injected_file"; saw_guard = 0 }
/^char \*zeromount_resolve_path\(/          { fn = "resolve_path"; saw_guard = 0 }
/^struct filename \*zeromount_getname_hook\(/ { fn = "getname_hook"; saw_guard = 0 }
/^void zeromount_inject_dents_common\(/     { fn = "dents_common"; saw_guard = 0 }
/^int zeromount_spoof_statfs\(/             { fn = "spoof_statfs"; saw_guard = 0 }
/^ssize_t zeromount_spoof_xattr\(/          { fn = "spoof_xattr"; saw_guard = 0 }
/^char \*zeromount_get_virtual_path_for_inode\(/ { fn = "vpath_inode"; saw_guard = 0 }

# Detect end of function — reset state
/^}$/ { fn = ""; saw_guard = 0 }

# uid_blocked: inject after ZEROMOUNT_DISABLED() guard return
fn == "uid_blocked" && !injected["uid_blocked"] && /ZEROMOUNT_DISABLED/ { saw_guard = 1 }
fn == "uid_blocked" && !injected["uid_blocked"] && saw_guard && /return false;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted()) return true;"
    print "#endif"
    injected["uid_blocked"] = 1
    next
}

# traversal: inject after first guard block return false
fn == "traversal" && !injected["traversal"] && /zeromount_is_uid_blocked/ { saw_guard = 1 }
fn == "traversal" && !injected["traversal"] && saw_guard && /return false;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted()) return false;"
    print "#endif"
    injected["traversal"] = 1
    next
}

# injected_file: inject after should_skip guard return false
fn == "injected_file" && !injected["injected_file"] && /zeromount_should_skip/ { saw_guard = 1 }
fn == "injected_file" && !injected["injected_file"] && saw_guard && /return false;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn false;"
    print "#endif"
    injected["injected_file"] = 1
    next
}

# resolve_path: inject after zeromount_is_critical_process guard
fn == "resolve_path" && !injected["resolve_path"] && /zeromount_is_critical_process/ { saw_guard = 1 }
fn == "resolve_path" && !injected["resolve_path"] && saw_guard && /return NULL;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn NULL;"
    print "#endif"
    injected["resolve_path"] = 1
    next
}

# getname_hook: inject after the multi-condition guard return name
fn == "getname_hook" && !injected["getname_hook"] && /zeromount_should_skip/ { saw_guard = 1 }
fn == "getname_hook" && !injected["getname_hook"] && saw_guard && /return name;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn name;"
    print "#endif"
    injected["getname_hook"] = 1
    next
}

# dents_common: inject after should_skip || uid_blocked guard return
fn == "dents_common" && !injected["dents_common"] && /zeromount_is_uid_blocked/ { saw_guard = 1 }
fn == "dents_common" && !injected["dents_common"] && saw_guard && /^\t\treturn;$/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted()) return;"
    print "#endif"
    injected["dents_common"] = 1
    next
}

# spoof_statfs: inject after uid_blocked guard return 0
fn == "spoof_statfs" && !injected["spoof_statfs"] && /zeromount_is_uid_blocked/ { saw_guard = 1 }
fn == "spoof_statfs" && !injected["spoof_statfs"] && saw_guard && /return 0;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn 0;"
    print "#endif"
    injected["spoof_statfs"] = 1
    next
}

# spoof_xattr: inject after uid_blocked guard return -EOPNOTSUPP
fn == "spoof_xattr" && !injected["spoof_xattr"] && /zeromount_is_uid_blocked/ { saw_guard = 1 }
fn == "spoof_xattr" && !injected["spoof_xattr"] && saw_guard && /return -EOPNOTSUPP;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn -EOPNOTSUPP;"
    print "#endif"
    injected["spoof_xattr"] = 1
    next
}

# get_virtual_path_for_inode: inject after uid_blocked guard return NULL
fn == "vpath_inode" && !injected["vpath_inode"] && /zeromount_is_uid_blocked/ { saw_guard = 1 }
fn == "vpath_inode" && !injected["vpath_inode"] && saw_guard && /return NULL;/ {
    print
    print "#ifdef CONFIG_KSU_SUSFS"
    print "\tif (susfs_is_current_proc_umounted())"
    print "\t\treturn NULL;"
    print "#endif"
    injected["vpath_inode"] = 1
    next
}

{ print }
' "$ZEROMOUNT_C" > "$ZEROMOUNT_C.tmp" && mv "$ZEROMOUNT_C.tmp" "$ZEROMOUNT_C"

count=$(grep -c "susfs_is_current_proc_umounted" "$ZEROMOUNT_C" || echo "0")
if [ "$count" -eq 10 ]; then
    echo "SUSFS bypass: all 10 checks present (1 pre-baked + 9 injected)"
else
    echo "Error: expected 10 checks, found $count"
    exit 1
fi
