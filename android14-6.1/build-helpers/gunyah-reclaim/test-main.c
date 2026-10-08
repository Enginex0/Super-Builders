static struct gh_rm_platform_ops patched_ops = {
	.pre_mem_share = qcom_scm_gh_rm_pre_mem_share,
	.post_mem_reclaim = qcom_scm_gh_rm_post_mem_reclaim,
	.android_backport_reserved1 = E3Q_RECLAIM_COOKIE,
};
static struct gh_rm_platform_ops old_ops = {
	.pre_mem_share = qcom_scm_gh_rm_pre_mem_share,
	.post_mem_reclaim = qcom_scm_gh_rm_post_mem_reclaim,
};
static struct gh_rm rm;
static struct gh_vm vm = { .rm = &rm };

static struct gh_vm_mem fixture(size_t n, u16 host) {
	struct gh_vm_mem m = {0};
	self_vmid = host;
	scm_calls = scm_fail_at = scm_failure_has_effect = rm_calls = rm_owned = 0;
	rm_initial_error = rm_reclaim_error = append_error = malformed_response = 0;
	vmid_error = allocation_fail_at = allocations = unpins = deleted = blocked = 0;
	test_module = (struct module){0};
	rm_platform_ops = &patched_ops;
	m.npages = n;
	m.pages = calloc(n, sizeof(*m.pages));
	m.parcel.n_mem_entries = n;
	m.parcel.mem_entries = calloc(n, sizeof(*m.parcel.mem_entries));
	m.parcel.n_acl_entries = 1;
	m.parcel.acl_entries = calloc(1, sizeof(*m.parcel.acl_entries));
	m.parcel.acl_entries[0] = (struct gh_rm_mem_acl_entry){128, 7, 0};
	m.parcel.mem_handle = GH_MEM_HANDLE_INVAL;
	for (size_t i = 0; i < n; i++) {
		m.parcel.mem_entries[i] = (struct gh_rm_mem_entry){4096 * (i + 1), 4096};
		ownership[i] = BIT_ULL(qcom_scm_map_vmid(host));
	}
	tests++;
	return m;
}
static void discard_model(struct gh_vm_mem *m) {
	/* Test process only: free host-side MOCK metadata after checking quarantine.
	 * This is not a kernel recovery path and never touches real guest memory. */
	if (!deleted) { free(m->pages); free(m->parcel.acl_entries); free(m->parcel.mem_entries); }
}
static int lend(struct gh_vm_mem *m) { return gh_rm_mem_lend_common(&rm, GH_RM_RPC_MEM_LEND, &m->parcel); }
static void assert_quarantined(struct gh_vm_mem *m) {
	assert(!gh_vm_mem_reclaim_mapping(&vm, m));
	assert(unpins == 0 && deleted == 0 && blocked);
	assert(test_module.refs == 1);
	int calls = scm_calls + rm_calls;
	assert(gh_rm_mem_reclaim(&rm, &m->parcel) != 0);
	assert(scm_calls + rm_calls == calls); /* No uncertain automatic retry. */
}
int main(void) {
	for (u16 host = 2; host <= 4; host++) {
		struct gh_vm_mem m = fixture(5, host);
		assert(lend(&m) == 0 && test_module.refs == 1);
		assert(E3Q_OWNER(&m.parcel) == host && E3Q_ASSIGNED(&m.parcel) == 5);
		assert(gh_vm_mem_reclaim_mapping(&vm, &m));
		assert(unpins == 1 && deleted == 1 && test_module.refs == 0 && !blocked);
	}
	for (int effect = 0; effect <= 1; effect++) {
		for (int fail = 1; fail <= 5; fail++) {
			struct gh_vm_mem m = fixture(5, 2);
			scm_fail_at = fail; scm_failure_has_effect = effect;
			assert(lend(&m) == -EIO && rm_calls == 0);
			assert(E3Q_ASSIGNED(&m.parcel) == 0); /* Known prefix rolled back. */
			assert_quarantined(&m); discard_model(&m);
			m = fixture(5, 2);
			assert(lend(&m) == 0);
			scm_fail_at = 5 + fail; scm_failure_has_effect = effect;
			assert_quarantined(&m);
			assert(E3Q_ASSIGNED(&m.parcel) == (u64)(6 - fail));
			discard_model(&m);
		}
	}
	for (int mode = 0; mode < 2; mode++) {
		struct gh_vm_mem m = fixture(5, 2);
		if (mode) malformed_response = 1; else rm_initial_error = -ETIMEDOUT;
		assert(lend(&m) != 0 && scm_calls == 5);
		assert_quarantined(&m); discard_model(&m);
	}
	for (int fail = 0; fail < 2; fail++) {
		struct gh_vm_mem m = fixture(513, 2);
		append_error = -EIO;
		assert(lend(&m) == -EIO && m.parcel.mem_handle == 42);
		assert(E3Q_STATE(&m.parcel) == E3Q_RM_OWNED && scm_calls == 513);
		if (fail) {
			rm_reclaim_error = -EIO;
			assert_quarantined(&m); discard_model(&m);
		} else {
			assert(gh_vm_mem_reclaim_mapping(&vm, &m));
			assert(test_module.refs == 0 && unpins == 1);
		}
	}
	for (int mode = 0; mode < 5; mode++) {
		struct gh_vm_mem m = fixture(5, 2);
		if (mode == 0) rm_platform_ops = &old_ops;
		if (mode == 1) rm_platform_ops = NULL;
		if (mode == 2) test_module.going = 1;
		if (mode == 3) vmid_error = -EIO;
		if (mode == 4) allocation_fail_at = 2; /* QCOM perms allocation. */
		assert(lend(&m) != 0 && scm_calls == 0 && rm_calls == 0);
		assert(gh_vm_mem_reclaim_mapping(&vm, &m) && test_module.refs == 0);
	}
	struct gh_vm_mem m = fixture(5, 2);
	assert(qcom_scm_gh_rm_pre_mem_share(&rm, &m.parcel) == -EOPNOTSUPP);
	assert(scm_calls == 0); /* New module on old kernel: refuse before ownership. */
	discard_model(&m);
	printf("PASS: %u exact-C fault scenarios; unsafe unpins=0\n", tests);
	return 0;
}
