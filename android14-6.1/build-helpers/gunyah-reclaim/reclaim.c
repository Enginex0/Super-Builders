int gh_rm_mem_reclaim(struct gh_rm *rm, struct gh_rm_mem_parcel *parcel)
{
	struct gh_rm_mem_release_req req = {
		.mem_handle = cpu_to_le32(parcel->mem_handle),
	};
	int ret;

	if (E3Q_POISON(parcel) || E3Q_STATE(parcel) == E3Q_QUARANTINED)
		return -EUCLEAN;
	if (E3Q_STATE(parcel) == E3Q_HOST_OWNED)
		return E3Q_ASSIGNED(parcel) || E3Q_MODULE(parcel) ||
			parcel->mem_handle != GH_MEM_HANDLE_INVAL ? -EUCLEAN : 0;
	if (E3Q_STATE(parcel) == E3Q_RM_OWNED) {
		if (parcel->mem_handle == GH_MEM_HANDLE_INVAL)
			return -EUCLEAN;
		ret = gh_rm_call(rm, GH_RM_RPC_MEM_RECLAIM, &req, sizeof(req), NULL, NULL);
		if (ret) {
			gh_vm_mem_block_new();
			E3Q_POISON(parcel) = 1;
			E3Q_STATE(parcel) = E3Q_QUARANTINED;
			return ret;
		}
		parcel->mem_handle = GH_MEM_HANDLE_INVAL;
		E3Q_STATE(parcel) = E3Q_PLATFORM_OWNED;
	}
	return gh_rm_platform_post_mem_reclaim(rm, parcel);
}

static bool gh_vm_mem_reclaim_mapping(struct gh_vm *ghvm, struct gh_vm_mem *mapping)
{
	int ret = gh_rm_mem_reclaim(ghvm->rm, &mapping->parcel);

	if (ret) {
		pr_err("GH_RECLAIM quarantine label=%u handle=%u state=%llu remaining=%llu ret=%d\n",
			mapping->parcel.label, mapping->parcel.mem_handle,
			E3Q_STATE(&mapping->parcel), E3Q_ASSIGNED(&mapping->parcel), ret);
		gh_vm_mem_block_new();
		return false;
	}
	unpin_user_pages(mapping->pages, mapping->npages);
	account_locked_vm(ghvm->mm, mapping->npages, false);
	kvfree(mapping->pages);
	kfree(mapping->parcel.acl_entries);
	kvfree(mapping->parcel.mem_entries);
	list_del(&mapping->list);
	return true;
}
