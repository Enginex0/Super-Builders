// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_main.c - Module init/exit
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sysfs.h>
#include "sprof_core.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelSU Next / Kotoamatsukami Team");
MODULE_DESCRIPTION("Snapdragon Profile (SProf) - VFS Environment Shaping for Snapdragon 6450");
MODULE_VERSION("1.0.0");

static struct sprof_system_state *sprof_state_ptr = NULL;
static struct proc_dir_entry *sprof_proc_root = NULL;
static struct kobject *sprof_kobj = NULL;

static int sprof_show_profile(struct seq_file *m, void *v)
{
    struct sprof_profile *p = sprof_profile_get_active();
    if (!p) {
        seq_puts(m, "no active profile\n");
        return 0;
    }
    seq_printf(m, "active: %s (id=%d)\n", p->name, p->id);
    seq_printf(m, "cpu: %s @ %d MHz, %d cores\n", p->hw.cpu_model, p->hw.cpu_mhz, p->hw.cpu_cores);
    seq_printf(m, "ram: %d MB\n", p->hw.ram_mb);
    return 0;
}

static int sprof_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sprof_show_profile, NULL);
}

static const struct proc_ops sprof_proc_ops = {
    .proc_open = sprof_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int sprof_proc_init(void)
{
    sprof_proc_root = proc_mkdir("sprof", NULL);
    if (!sprof_proc_root) return -ENOMEM;
    proc_create("sprof/active", 0444, NULL, &sprof_proc_ops);
    return 0;
}

void sprof_proc_cleanup(void)
{
    remove_proc_entry("sprof/active", NULL);
    remove_proc_entry("sprof", NULL);
}

static ssize_t sprof_active_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct sprof_profile *p = sprof_profile_get_active();
    if (!p) return snprintf(buf, PAGE_SIZE, "none\n");
    return snprintf(buf, PAGE_SIZE, "%d %s\n", p->id, p->name);
}

static struct kobj_attribute sprof_active_attr = __ATTR(active_profile, 0444, sprof_active_show, NULL);

int sprof_sysfs_init(struct kobject *kobj)
{
    int err;
    sprof_kobj = kobject_create_and_add("sprof", kobj);
    if (!sprof_kobj) return -ENOMEM;
    err = sysfs_create_file(sprof_kobj, &sprof_active_attr.attr);
    if (err) {
        kobject_put(sprof_kobj);
        sprof_kobj = NULL;
    }
    return err;
}

void sprof_sysfs_cleanup(void)
{
    if (sprof_kobj) {
        sysfs_remove_file(sprof_kobj, &sprof_active_attr.attr);
        kobject_put(sprof_kobj);
        sprof_kobj = NULL;
    }
}

int sprof_init(void)
{
    int ret;
    pr_info("sprof: initializing Snapdragon Profile module\n");
    ret = sprof_qcom_eud_init();
    if (ret) {
        pr_err("sprof: EUD init failed: %d\n", ret);
        return ret;
    }
    ret = sprof_proc_init();
    if (ret) {
        sprof_qcom_eud_cleanup();
        return ret;
    }
    pr_info("sprof: initialized\n");
    return 0;
}

void sprof_exit(void)
{
    pr_info("sprof: unloading\n");
    sprof_proc_cleanup();
    sprof_sysfs_cleanup();
    sprof_qcom_eud_cleanup();
}

module_init(sprof_init);
module_exit(sprof_exit);
