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

    # SUSFS needs a vma declaration inside pagemap_read
    if ! grep -q 'CONFIG_KSU_SUSFS_SUS_MAP' "$f"; then
        sed -i '/pagemap_entry_t \*res = NULL;/a\
#ifdef CONFIG_KSU_SUSFS_SUS_MAP\
\tstruct vm_area_struct *vma;\
#endif' "$f"
    fi

    rm -f "$rej"
    echo "[+] $f fixed"
}

fix_namespace
fix_task_mmu
