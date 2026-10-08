/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SUSFS_UID_GATE_H
#define _LINUX_SUSFS_UID_GATE_H

#include <linux/cred.h>

/* An additional consumer-side restriction, never an authorization decision.
 * Use the kernel real UID, not a user-namespace-mapped or effective UID.
 * Android reserves 100000 UIDs per user; app, SDK-sandbox and isolated
 * identities have app-id >= 10000. System identities in EVERY user bypass.
 */
static inline bool susfs_uid_gate_for_uid(unsigned int uid)
{
#ifdef CONFIG_KSU_SUSFS_UID_GATED_HIDING
	return uid != (unsigned int)-1 && uid % 100000U >= 10000U;
#else
	(void)uid;
	return true;
#endif
}

static inline bool susfs_uid_gate_current(void)
{
	return susfs_uid_gate_for_uid(current_uid().val);
}

#endif /* _LINUX_SUSFS_UID_GATE_H */
