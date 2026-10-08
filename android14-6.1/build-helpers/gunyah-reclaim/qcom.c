/* E3Q reclaim v1: retain prefix progress; never mask a failed assignment. */
static int qcom_scm_gh_rm_restore(struct gh_rm_mem_parcel *p)
{
	struct qcom_scm_vmperm host = {
		.vmid = E3Q_OWNER(p),
		.perm = QCOM_SCM_PERM_EXEC | QCOM_SCM_PERM_WRITE | QCOM_SCM_PERM_READ,
	};
	u64 src = 0, src_cpy;
	size_t i, n;
	int ret;

	for (n = 0; n < p->n_acl_entries; n++)
		src |= BIT_ULL(qcom_scm_map_vmid(le16_to_cpu(p->acl_entries[n].vmid)));

	/* Assignments were made in ascending order. Undo only the known prefix,
	 * in reverse order, and record each success before attempting the next.
	 */
	while (E3Q_ASSIGNED(p)) {
		i = E3Q_ASSIGNED(p) - 1;
		src_cpy = src;
		ret = qcom_scm_assign_mem(le64_to_cpu(p->mem_entries[i].phys_addr),
					le64_to_cpu(p->mem_entries[i].size),
					&src_cpy, &host, 1);
		if (ret) {
			E3Q_POISON(p) = 1;
			return ret;
		}
		E3Q_ASSIGNED(p)--;
	}
	return 0;
}

static int qcom_scm_gh_rm_pre_mem_share(void *rm, struct gh_rm_mem_parcel *mem_parcel)
{
	struct qcom_scm_vmperm *new_perms;
	u64 src, src_cpy;
	size_t i, n;
	int ret, rollback;
	u16 self_vmid, vmid;

	/* Old kernels do not initialize the v1 contract. Refuse before SCM. */
	if (E3Q_STATE(mem_parcel) != E3Q_PLATFORM_OWNED ||
	    E3Q_ASSIGNED(mem_parcel) || E3Q_POISON(mem_parcel))
		return -EOPNOTSUPP;
	ret = gh_rm_get_vmid(rm, &self_vmid);
	if (ret)
		return ret;
	/* Restore exactly the SCM owner used by the successful outgoing path.
	 * No fixed Samsung guest/PAS identifiers are changed.
	 */
	E3Q_OWNER(mem_parcel) = qcom_scm_map_vmid(self_vmid);
	new_perms = kcalloc(mem_parcel->n_acl_entries, sizeof(*new_perms), GFP_KERNEL);
	if (!new_perms)
		return -ENOMEM;
	for (n = 0; n < mem_parcel->n_acl_entries; n++) {
		vmid = le16_to_cpu(mem_parcel->acl_entries[n].vmid);
		new_perms[n].vmid = qcom_scm_map_vmid(vmid);
		if (mem_parcel->acl_entries[n].perms & GH_RM_ACL_X)
			new_perms[n].perm |= QCOM_SCM_PERM_EXEC;
		if (mem_parcel->acl_entries[n].perms & GH_RM_ACL_W)
			new_perms[n].perm |= QCOM_SCM_PERM_WRITE;
		if (mem_parcel->acl_entries[n].perms & GH_RM_ACL_R)
			new_perms[n].perm |= QCOM_SCM_PERM_READ;
	}
	src = BIT_ULL(E3Q_OWNER(mem_parcel));
	for (i = 0; i < mem_parcel->n_mem_entries; i++) {
		src_cpy = src;
		ret = qcom_scm_assign_mem(le64_to_cpu(mem_parcel->mem_entries[i].phys_addr),
					le64_to_cpu(mem_parcel->mem_entries[i].size),
					&src_cpy, new_perms, mem_parcel->n_acl_entries);
		if (ret) {
			/* A failed SCM call does not prove zero side effects. Never
			 * release these pages, even if the known prefix rolls back.
			 */
			E3Q_POISON(mem_parcel) = 1;
			rollback = qcom_scm_gh_rm_restore(mem_parcel);
			if (rollback)
				ret = rollback;
			goto out;
		}
		E3Q_ASSIGNED(mem_parcel)++;
	}
	ret = 0;
out:
	kfree(new_perms);
	return ret;
}

static int qcom_scm_gh_rm_post_mem_reclaim(void *rm, struct gh_rm_mem_parcel *mem_parcel)
{
	/* Uncertain calls are quarantined, not blindly retried. */
	if (E3Q_POISON(mem_parcel))
		return -EUCLEAN;
	return qcom_scm_gh_rm_restore(mem_parcel);
}
