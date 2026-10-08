int gh_rm_platform_pre_mem_share(struct gh_rm *rm, struct gh_rm_mem_parcel *mem_parcel)
{
	struct module *owner;
	int ret = -EOPNOTSUPP;

	down_read(&rm_platform_ops_lock);
	/* Stock/old modules have no contract cookie. Refuse BEFORE any SCM call;
	 * a CRC-compatible module is not necessarily behavior-compatible.
	 */
	if (!rm_platform_ops ||
	    rm_platform_ops->android_backport_reserved1 != E3Q_RECLAIM_COOKIE ||
	    !rm_platform_ops->pre_mem_share || !rm_platform_ops->post_mem_reclaim)
		goto out;
	if (E3Q_STATE(mem_parcel) != E3Q_HOST_OWNED || E3Q_MODULE(mem_parcel) ||
	    E3Q_ASSIGNED(mem_parcel) || E3Q_POISON(mem_parcel)) {
		ret = -EUCLEAN;
		goto out;
	}
	/* The ops lock serializes unregister. __module_address requires RCU or
	 * preemption protection; keep a module reference for the entire parcel.
	 */
	preempt_disable();
	owner = __module_address((unsigned long)rm_platform_ops);
	ret = owner && !try_module_get(owner) ? -ENODEV : 0;
	preempt_enable();
	if (ret)
		goto out;
	E3Q_MODULE(mem_parcel) = (unsigned long)owner;
	E3Q_STATE(mem_parcel) = E3Q_PLATFORM_OWNED;
	ret = rm_platform_ops->pre_mem_share(rm, mem_parcel);
	if (E3Q_POISON(mem_parcel)) {
		gh_vm_mem_block_new();
		E3Q_STATE(mem_parcel) = E3Q_QUARANTINED;
		if (!ret)
			ret = -EUCLEAN;
	} else if (ret && !E3Q_ASSIGNED(mem_parcel)) {
		E3Q_STATE(mem_parcel) = E3Q_HOST_OWNED;
		E3Q_MODULE(mem_parcel) = 0;
		module_put(owner);
	}
out:
	up_read(&rm_platform_ops_lock);
	return ret;
}

int gh_rm_platform_post_mem_reclaim(struct gh_rm *rm, struct gh_rm_mem_parcel *mem_parcel)
{
	struct module *owner;
	int ret = -EUCLEAN;

	down_read(&rm_platform_ops_lock);
	if (E3Q_POISON(mem_parcel) || E3Q_STATE(mem_parcel) != E3Q_PLATFORM_OWNED)
		goto out;
	if (!rm_platform_ops ||
	    rm_platform_ops->android_backport_reserved1 != E3Q_RECLAIM_COOKIE ||
	    !rm_platform_ops->post_mem_reclaim)
		goto out;
	ret = rm_platform_ops->post_mem_reclaim(rm, mem_parcel);
	if (!ret && !E3Q_ASSIGNED(mem_parcel) && !E3Q_POISON(mem_parcel)) {
		owner = (struct module *)(unsigned long)E3Q_MODULE(mem_parcel);
		E3Q_MODULE(mem_parcel) = 0;
		E3Q_STATE(mem_parcel) = E3Q_HOST_OWNED;
		module_put(owner);
	} else if (!ret) {
		ret = -EUCLEAN;
	}
out:
	if (ret) {
		gh_vm_mem_block_new();
		E3Q_POISON(mem_parcel) = 1;
		E3Q_STATE(mem_parcel) = E3Q_QUARANTINED;
	}
	up_read(&rm_platform_ops_lock);
	return ret;
}
