/* SPDX-License-Identifier: GPL-2.0-only */
/* E3Q reclaim contract v1: existing reserved storage, no public ABI resize. */
#ifndef E3Q_MEM_RECLAIM_H
#define E3Q_MEM_RECLAIM_H

#define E3Q_RECLAIM_COOKIE 0x4533515245434c31ULL
#define E3Q_HOST_OWNED 0
#define E3Q_PLATFORM_OWNED 1
#define E3Q_RM_OWNED 2
#define E3Q_QUARANTINED 3

/* Private contract between this kernel and the matching gunyah_qcom module.
 * Platform ops reserved1 advertises the contract BEFORE any ownership changes.
 * Parcel reserved1..5 have these meanings; reserved6..8 remain untouched.
 * No field is renamed/added in the exported struct, preserving genksyms CRCs.
 */
#define E3Q_STATE(p) ((p)->android_backport_reserved1)
#define E3Q_OWNER(p) ((p)->android_backport_reserved2)
#define E3Q_ASSIGNED(p) ((p)->android_backport_reserved3)
#define E3Q_MODULE(p) ((p)->android_backport_reserved4)
#define E3Q_POISON(p) ((p)->android_backport_reserved5)

/* Core-private symbol; the QCOM module never calls or imports it. */
void gh_vm_mem_block_new(void);

#endif
