#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
#define GFP_KERNEL 0
#define U8_MAX 255
#define GH_MEM_HANDLE_INVAL UINT32_MAX
#define GH_RM_MAX_MEM_ENTRIES 512
#define GH_MEM_SHARE_REQ_FLAGS_APPEND 2
#define GH_RM_RPC_MEM_RECLAIM 0x51000015
#define GH_RM_RPC_MEM_LEND 0x51000012
#define GH_RM_ACL_X 1
#define GH_RM_ACL_W 2
#define GH_RM_ACL_R 4
#define QCOM_SCM_PERM_EXEC 1
#define QCOM_SCM_PERM_WRITE 2
#define QCOM_SCM_PERM_READ 4
#define BIT_ULL(n) (1ULL << (n))
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define struct_size(p, m, n) (sizeof(*(p)) + sizeof((p)->m[0]) * (n))
#define flex_array_size(p, m, n) (sizeof((p)->m[0]) * (n))
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define down_read(p) ((void)(p))
#define up_read(p) ((void)(p))
#define preempt_disable() ((void)0)
#define preempt_enable() ((void)0)
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;
typedef uint16_t __le16;
typedef uint32_t __le32;
struct gh_rm { int unused; };
struct gh_rm_mem_acl_entry { u16 vmid; u8 perms; u8 reserved; };
struct gh_rm_mem_entry { u64 phys_addr, size; };
struct gh_rm_mem_parcel {
	int mem_type; u32 label; size_t n_acl_entries;
	struct gh_rm_mem_acl_entry *acl_entries; size_t n_mem_entries;
	struct gh_rm_mem_entry *mem_entries; u32 mem_handle;
	u64 android_backport_reserved1, android_backport_reserved2;
	u64 android_backport_reserved3, android_backport_reserved4;
	u64 android_backport_reserved5, android_backport_reserved6;
	u64 android_backport_reserved7, android_backport_reserved8;
};
struct qcom_scm_vmperm { u32 vmid, perm; };
struct module { int refs, going; };
struct gh_rm_platform_ops {
	int (*pre_mem_share)(void *, struct gh_rm_mem_parcel *);
	int (*post_mem_reclaim)(void *, struct gh_rm_mem_parcel *);
	u64 android_backport_reserved1;
};
struct gh_rm_mem_share_req_header { u8 mem_type, pad0, flags, pad1; u32 label; };
struct gh_rm_mem_share_req_acl_section { u32 n_entries; struct gh_rm_mem_acl_entry entries[]; };
struct gh_rm_mem_share_req_mem_section { u16 n_entries, pad; struct gh_rm_mem_entry entries[]; };
struct gh_rm_mem_release_req { u32 mem_handle; u8 flags, pad0; u16 pad1; };
struct gh_vm_mem { struct gh_rm_mem_parcel parcel; void **pages; size_t npages; int list; };
struct gh_vm { struct gh_rm *rm; void *mm; };
static struct module test_module;
static const struct gh_rm_platform_ops *rm_platform_ops;
static int rm_platform_ops_lock;
static u16 self_vmid;
static int scm_calls, scm_fail_at, scm_failure_has_effect, rm_calls, rm_owned;
static int rm_initial_error, rm_reclaim_error, append_error, malformed_response;
static int vmid_error, allocation_fail_at, allocations, unpins, deleted, blocked;
static u64 ownership[600];
static unsigned tests;
static u16 qcom_scm_map_vmid(u16 vmid) { return vmid <= 63 ? vmid : 58; }
static void *allocate(size_t n, size_t size) {
	allocations++;
	return allocations == allocation_fail_at ? NULL : calloc(n, size);
}
#define kcalloc(n,s,f) allocate((n),(s))
#define kzalloc(n,f) allocate(1,(n))
#define kfree(p) free(p)
#define kvfree(p) free(p)
static struct module *__module_address(unsigned long addr) { (void)addr; return &test_module; }
static int try_module_get(struct module *m) { if (m->going) return 0; m->refs++; return 1; }
static void module_put(struct module *m) { if (m) { assert(m->refs > 0); m->refs--; } }
void gh_vm_mem_block_new(void) { blocked = 1; }
static int gh_rm_get_vmid(void *rm, u16 *id) { (void)rm; *id = self_vmid; return vmid_error; }
static int qcom_scm_assign_mem(u64 addr, u64 size, u64 *src,
			       struct qcom_scm_vmperm *perms, unsigned n) {
	size_t index = addr / 4096 - 1;
	u64 dest = 0;
	assert(size == 4096 && index < 600 && n > 0);
	assert(*src == ownership[index]);
	for (unsigned j = 0; j < n; j++) {
		assert(perms[j].perm == 7);
		dest |= BIT_ULL(perms[j].vmid);
	}
	scm_calls++;
	if (scm_calls == scm_fail_at) {
		if (scm_failure_has_effect) ownership[index] = dest;
		return -EIO;
	}
	ownership[index] = dest;
	*src = dest; /* Real API mutates the source mask on success. */
	return 0;
}
static int gh_rm_call(struct gh_rm *rm, u32 id, const void *req, size_t len,
		     void **response, size_t *response_size) {
	(void)rm; (void)req; (void)len;
	rm_calls++;
	if (id == GH_RM_RPC_MEM_RECLAIM) {
		assert(rm_owned);
		if (rm_reclaim_error) return rm_reclaim_error;
		rm_owned = 0;
		return 0;
	}
	assert(id == GH_RM_RPC_MEM_LEND && response && response_size);
	rm_owned = 1; /* A failed/timeout initial call MAY already have taken effect. */
	if (rm_initial_error) return rm_initial_error;
	*response = malloc(sizeof(u32));
	assert(*response);
	*(u32 *)*response = 42;
	*response_size = malformed_response ? 0 : sizeof(u32);
	return 0;
}
static int gh_rm_mem_append(struct gh_rm *rm, u32 h, struct gh_rm_mem_entry *e, size_t n) {
	(void)rm; (void)e; assert(h == 42 && n > 0); return append_error;
}
static void unpin_user_pages(void **p, size_t n) {
	(void)p;
	assert(!rm_owned);
	for (size_t i = 0; i < n; i++) assert(ownership[i] == BIT_ULL(qcom_scm_map_vmid(self_vmid)));
	unpins++;
}
static void account_locked_vm(void *mm, size_t n, bool add) { (void)mm; (void)n; assert(!add); }
static void list_del(int *list) { (void)list; deleted++; }
