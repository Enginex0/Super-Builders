/* Enhanced KSTAT redirect registration for the SUSFS 24743360 layout.
 * Keep the existing userspace command layout; initialize every new lookup and
 * statfs field before publishing either inode to SUS_KSTAT_HLIST. */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT
static int susfs_prepare_redirect_entry(const struct path *path,
		struct st_susfs_sus_kstat_hlist *entry, struct inode **marked_inode)
{
	struct inode *inode = d_backing_inode(path->dentry);
	struct vfsmount *visible_mnt;
	int err;

	if (!inode || !inode->i_mapping)
		return -EINVAL;
	if (inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (!fi || !fi->inode.i_mapping)
			return -EINVAL;
		inode = &fi->inode;
		entry->is_fuse = true;
	}
	entry->target_ino = inode->i_ino;
	entry->info.target_ino = inode->i_ino;
	entry->target_dev = inode->i_sb->s_dev;
	entry->spoofed_mnt_id = susfs_get_non_sus_mnt_id_from_mnt(real_mount(path->mnt));
	visible_mnt = susfs_get_non_sus_vfsmnt_from_vfsmnt(path->mnt);
	err = statfs_by_dentry_wrapper(visible_mnt->mnt_root, &entry->spoofed_kstatfs);
	if (!err)
		entry->spoofed_kstatfs.f_flags = calculate_f_flags_wrapper(visible_mnt);
	dput(visible_mnt->mnt_root);
	mntput(visible_mnt);
	if (!err)
		*marked_inode = inode;
	return err;
}

void susfs_add_sus_kstat_redirect(void __user **user_info)
{
	struct st_susfs_sus_kstat_redirect info = {0};
	struct st_susfs_sus_kstat_hlist *entry = NULL, *virtual_entry = NULL;
	struct path real_path, virtual_path;
	struct inode *real_inode = NULL, *virtual_inode = NULL;
	bool real_resolved = false, virtual_resolved = false;

	if (copy_from_user(&info, *user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	if (!memchr(info.real_pathname, '\0', sizeof(info.real_pathname)) ||
	    !memchr(info.virtual_pathname, '\0', sizeof(info.virtual_pathname)) ||
	    !info.real_pathname[0] || !info.virtual_pathname[0]) {
		info.err = -EINVAL;
		goto out;
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		info.err = -ENOMEM;
		goto out;
	}
	info.err = kern_path(info.real_pathname, 0, &real_path);
	if (info.err)
		goto out;
	real_resolved = true;
	info.err = susfs_prepare_redirect_entry(&real_path, entry, &real_inode);
	if (info.err)
		goto out;

	strscpy(entry->info.target_pathname, info.virtual_pathname,
		sizeof(entry->info.target_pathname));
	entry->info.flags = KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV | KSTAT_SPOOF_NLINK |
		KSTAT_SPOOF_SIZE | KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC |
		KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC |
		KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC |
		KSTAT_SPOOF_BLOCKS | KSTAT_SPOOF_BLKSIZE;
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	entry->info.spoofed_dev = huge_decode_dev(info.spoofed_dev);
#else
	entry->info.spoofed_dev = old_decode_dev(info.spoofed_dev);
#endif
	entry->info.spoofed_ino = info.spoofed_ino;
	entry->info.spoofed_nlink = info.spoofed_nlink;
	entry->info.spoofed_size = info.spoofed_size;
	entry->info.spoofed_atime_tv_sec = info.spoofed_atime_tv_sec;
	entry->info.spoofed_atime_tv_nsec = info.spoofed_atime_tv_nsec;
	entry->info.spoofed_mtime_tv_sec = info.spoofed_mtime_tv_sec;
	entry->info.spoofed_mtime_tv_nsec = info.spoofed_mtime_tv_nsec;
	entry->info.spoofed_ctime_tv_sec = info.spoofed_ctime_tv_sec;
	entry->info.spoofed_ctime_tv_nsec = info.spoofed_ctime_tv_nsec;
	entry->info.spoofed_blocks = info.spoofed_blocks;
	entry->info.spoofed_blksize = info.spoofed_blksize;

	info.err = kern_path(info.virtual_pathname, 0, &virtual_path);
	if (!info.err) {
		virtual_resolved = true;
		virtual_entry = kzalloc(sizeof(*virtual_entry), GFP_KERNEL);
		if (!virtual_entry) {
			info.err = -ENOMEM;
			goto out;
		}
		virtual_entry->info = entry->info;
		info.err = susfs_prepare_redirect_entry(&virtual_path, virtual_entry, &virtual_inode);
		if (info.err)
			goto out;
		/* Redirected descriptors must retain the visible virtual filesystem. */
		entry->spoofed_mnt_id = virtual_entry->spoofed_mnt_id;
		entry->spoofed_kstatfs = virtual_entry->spoofed_kstatfs;
		if (entry->target_ino == virtual_entry->target_ino &&
		    entry->target_dev == virtual_entry->target_dev &&
		    entry->is_fuse == virtual_entry->is_fuse) {
			kfree(virtual_entry);
			virtual_entry = NULL;
		}
	} else if (info.err != -ENOENT) {
		goto out;
	}

	mutex_lock(&susfs_mutex_lock_sus_kstat);
	set_bit(AS_FLAGS_SUS_KSTAT, &real_inode->i_mapping->flags);
	if (virtual_inode)
		set_bit(AS_FLAGS_SUS_KSTAT, &virtual_inode->i_mapping->flags);
	hash_add_rcu(SUS_KSTAT_HLIST, &entry->node, entry->target_ino);
	if (virtual_entry)
		hash_add_rcu(SUS_KSTAT_HLIST, &virtual_entry->node, virtual_entry->target_ino);
	mutex_unlock(&susfs_mutex_lock_sus_kstat);
	entry = NULL;
	virtual_entry = NULL;
	info.err = 0;
out:
	if (virtual_resolved)
		path_put(&virtual_path);
	if (real_resolved)
		path_put(&real_path);
	kfree(virtual_entry);
	kfree(entry);
	if (copy_to_user(&((struct st_susfs_sus_kstat_redirect __user *)*user_info)->err,
			&info.err, sizeof(info.err)))
		info.err = -EFAULT;
	SUSFS_LOGI("kstat redirect registration: ret=%d\n", info.err);
}
#endif /* CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT */
