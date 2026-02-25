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
if [ "$existing" -eq 9 ]; then
    echo "SUSFS bypass checks already present (9/9)"
    exit 0
fi
if [ "$existing" -gt 9 ]; then
    echo "Error: $existing susfs_is_current_proc_umounted occurrences found (expected 0 or 9) — file may be double-injected"
    exit 1
fi

# susfs.h include
if ! grep -q '#include <linux/susfs.h>' "$ZEROMOUNT_C"; then
    sed -i '/#include <linux\/zeromount.h>/a\
#ifdef CONFIG_KSU_SUSFS\
#include <linux/susfs.h>\
#endif' "$ZEROMOUNT_C"
fi

# zeromount_is_uid_blocked: umounted procs treated as blocked
if ! grep -q 'susfs_is_current_proc_umounted.*return true' "$ZEROMOUNT_C"; then
    sed -i '/^bool zeromount_is_uid_blocked(uid_t uid) {$/,/^}$/{
        /if (ZEROMOUNT_DISABLED()) return false;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted()) return true;\
#endif
}' "$ZEROMOUNT_C"
fi

# zeromount_is_traversal_allowed: deny traversal for umounted
if ! grep -A3 'zeromount_is_uid_blocked(current_uid().val)) return false;' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted.*return false'; then
    sed -i '/^bool zeromount_is_traversal_allowed(struct inode \*inode, int mask) {$/,/^}$/{
        /if (!inode || zeromount_should_skip() || zeromount_is_uid_blocked(current_uid().val)) return false;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted()) return false;\
#endif
}' "$ZEROMOUNT_C"
fi

# zeromount_is_injected_file: invisible to umounted
if ! grep -A5 'zeromount_is_injected_file' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^bool zeromount_is_injected_file(struct inode \*inode) {$/,/^}$/{
        /if (!inode || !inode->i_sb || zeromount_should_skip())$/,/return false;/{
            /return false;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return false;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

# zeromount_resolve_path: no redirection for umounted
if ! grep -A5 'zeromount_resolve_path' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^char \*zeromount_resolve_path(const char \*pathname)$/,/^}$/{
        /if (zeromount_is_critical_process())/,/return NULL;/{
            /return NULL;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return NULL;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

# zeromount_getname_hook: passthrough for umounted
if ! grep -A5 'zeromount_getname_hook' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^struct filename \*zeromount_getname_hook(struct filename \*name)$/,/^}$/{
        /if (zeromount_should_skip() || zeromount_is_uid_blocked(current_uid().val) || !name || name->name\[0\] != '"'"'\/'"'"')/,/return name;/{
            /return name;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return name;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

# zeromount_inject_dents_common: no dir injection for umounted
if ! grep -A3 'zeromount_inject_dents_common' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^void zeromount_inject_dents_common(struct file \*file/,/^}$/{
        /if (zeromount_should_skip() || zeromount_is_uid_blocked(current_uid().val)) return;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted()) return;\
#endif
}' "$ZEROMOUNT_C"
fi

# zeromount_spoof_statfs: no spoofing for umounted
if ! grep -A5 'zeromount_spoof_statfs' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^int zeromount_spoof_statfs(const char __user \*pathname/,/^}$/{
        /if (zeromount_should_skip() || zeromount_is_uid_blocked(current_uid().val))$/,/return 0;/{
            /return 0;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return 0;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

# zeromount_spoof_xattr: no spoofing for umounted
if ! grep -A5 'zeromount_spoof_xattr' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^ssize_t zeromount_spoof_xattr(struct dentry \*dentry/,/^}$/{
        /if (zeromount_should_skip() || zeromount_is_uid_blocked(current_uid().val))$/,/return -EOPNOTSUPP;/{
            /return -EOPNOTSUPP;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return -EOPNOTSUPP;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

# zeromount_get_virtual_path_for_inode: hidden from umounted
if ! grep -A5 'zeromount_get_virtual_path_for_inode' "$ZEROMOUNT_C" | grep -q 'susfs_is_current_proc_umounted'; then
    sed -i '/^char \*zeromount_get_virtual_path_for_inode(struct inode \*inode) {$/,/^}$/{
        /if (zeromount_is_uid_blocked(current_uid().val))$/,/return NULL;/{
            /return NULL;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (susfs_is_current_proc_umounted())\
        return NULL;\
#endif
        }
}' "$ZEROMOUNT_C"
fi

count=$(grep -c "susfs_is_current_proc_umounted" "$ZEROMOUNT_C" || echo "0")
if [ "$count" -eq 9 ]; then
    echo "SUSFS bypass: all 9 checks injected"
else
    echo "Error: expected 9 checks, found $count"
    exit 1
fi
