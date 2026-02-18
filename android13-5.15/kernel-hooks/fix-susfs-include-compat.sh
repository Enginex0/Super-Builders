#!/bin/bash
# Resolve SUSFS patch include rejects on older 5.15 sublevels
# The patch expects #include <linux/mnt_idmapping.h> as context,
# which doesn't exist before ~5.15.44. Inject the includes directly.

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

    if ! grep -q 'susfs_is_current_ksu_domain' "$f"; then
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

fix_open() {
    local rej="fs/open.c.rej"
    local f="fs/open.c"
    [ -f "$rej" ] || return 0

    echo "[+] Resolving $rej"

    if ! grep -q '#include <linux/susfs_def.h>' "$f"; then
        sed -i '/#include <linux\/compat.h>/a\
#ifdef CONFIG_KSU_SUSFS\
#include <linux/susfs_def.h>\
#endif' "$f"
    fi

    rm -f "$rej"
    echo "[+] $f fixed"
}

fix_namespace
fix_open
