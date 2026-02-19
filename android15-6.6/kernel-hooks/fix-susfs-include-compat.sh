#!/bin/bash
# Resolve SUSFS GKI patch rejects on older 6.6 sublevels (<=58)
# The patch is written for the newest sublevel; older ones have
# slightly different include layout and function context

set -e
cd "${1:-.}" || exit 1

fix_namespace() {
    local rej="fs/namespace.c.rej"
    local f="fs/namespace.c"
    [ -f "$rej" ] || return 0

    echo "[+] Resolving $rej"

    if ! grep -q '#include <linux/susfs_def.h>' "$f"; then
        sed -i '/#include "pnode.h"/i\
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\
#include <linux/susfs_def.h>\
#endif' "$f"
    fi

    if ! grep -q 'extern bool susfs_is_current_ksu_domain' "$f"; then
        sed -i '/#include "internal.h"/a\
\
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\
extern bool susfs_is_current_ksu_domain(void);\
extern bool susfs_is_sdcard_android_data_decrypted __read_mostly;\
\
static atomic64_t susfs_ksu_mounts = ATOMIC64_INIT(0);\
\
#define CL_COPY_MNT_NS BIT(25)\
#endif' "$f"
    fi

    rm -f "$rej"
    echo "[+] $f fixed"
}

fix_task_mmu() {
    local rej="fs/proc/task_mmu.c.rej"
    local f="fs/proc/task_mmu.c"
    [ -f "$rej" ] || return 0

    echo "[+] Resolving $rej"

    # Inject vma declaration inside pagemap_read after the last existing local var
    # Can't use global grep — vma exists in other functions. Use awk for scope.
    awk '
    /^static ssize_t pagemap_read/ { in_func=1 }
    in_func && /int ret = 0, copied = 0;/ {
        print
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
        print "\tstruct vm_area_struct *vma;"
        print "#endif"
        in_func=0
        next
    }
    { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"

    rm -f "$rej"
    echo "[+] $f fixed"
}

fix_namespace
fix_task_mmu
