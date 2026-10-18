/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPROF_CORE_H
#define _SPROF_CORE_H

#include "sprof_types.h"

int sprof_qcom_eud_read_cpu(struct sprof_hw_profile *hw);
int sprof_qcom_eud_read_ram(struct sprof_hw_profile *hw);
int sprof_qcom_eud_read_storage(struct sprof_hw_profile *hw);
int sprof_qcom_eud_read_network(struct sprof_hw_profile *hw);
int sprof_qcom_eud_read_all(struct sprof_hw_profile *hw);
int sprof_qcom_eud_init(void);
void sprof_qcom_eud_cleanup(void);

void sprof_build_cpuinfo(struct sprof_profile *p);
void sprof_build_meminfo(struct sprof_profile *p);
void sprof_build_stat(struct sprof_profile *p);
void sprof_build_loadavg(struct sprof_profile *p);
void sprof_build_uptime(struct sprof_profile *p);
void sprof_build_hostname(struct sprof_profile *p);
void sprof_build_filesystems(struct sprof_profile *p);
void sprof_build_cmdline(struct sprof_profile *p);
void sprof_build_mounts(struct sprof_profile *p);
void sprof_build_version(struct sprof_profile *p);
void sprof_build_bus_pci(struct sprof_profile *p);
void sprof_build_interrupt(struct sprof_profile *p);
void sprof_build_diskstats(struct sprof_profile *p);
void sprof_build_vmstat(struct sprof_profile *p);
void sprof_build_buddyinfo(struct sprof_profile *p);
void sprof_build_slabinfo(struct sprof_profile *p);
void sprof_build_softirqs(struct sprof_profile *p);
void sprof_build_all_content(struct sprof_profile *p);

int sprof_env_add_var(struct sprof_env_block *env, const char *name, const char *value);
void sprof_env_build_block(struct sprof_profile *p);
void sprof_env_free(struct sprof_env_block *env);

int sprof_profile_create(enum sprof_profile_type type, const char *name, struct sprof_hw_profile *hw);
int sprof_profile_activate(int id);
int sprof_profile_deactivate(void);
int sprof_profile_delete(int id);
struct sprof_profile *sprof_profile_get_active(void);
struct sprof_profile *sprof_profile_get_by_id(int id);

int sprof_process_rule_add(struct sprof_profile *p, pid_t pid, const char *name, const char *cmdline);
int sprof_process_rule_remove(struct sprof_profile *p, pid_t pid);
struct sprof_process_rule *sprof_process_rule_find(struct sprof_profile *p, pid_t pid);

const char *sprof_vfs_check_spoof(const char *path, int *out_len);
int sprof_vfs_add_spoof(const char *real_path, const char *content, int content_len);
int sprof_vfs_remove_spoof(const char *real_path);
int sprof_overlay_add_bridge(const char *overlay_path, const char *real_path);
int sprof_overlay_remove_bridge(const char *overlay_path);
const char *sprof_overlay_check_bridge(const char *overlay_path);

int sprof_proc_init(void);
void sprof_proc_cleanup(void);
int sprof_sysfs_init(struct kobject *kobj);
void sprof_sysfs_cleanup(void);

int sprof_init(void);
void sprof_exit(void);

#endif
