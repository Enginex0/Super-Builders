// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_profile.c - Profile management
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include "sprof_core.h"

static struct sprof_system_state sprof_state;

int sprof_profile_create(enum sprof_profile_type type, const char *name,
                          struct sprof_hw_profile *hw)
{
    struct sprof_profile *p;
    if (!name) return -EINVAL;
    if (sprof_state.profile_count >= SPROF_MAX_PROFILES) return -ENOSPC;
    p = &sprof_state.profiles[sprof_state.profile_count];
    memset(p, 0, sizeof(*p));
    p->id = sprof_state.profile_count;
    p->type = type;
    p->active = 0;
    p->loaded = 1;
    strncpy(p->name, name, SPROF_MAX_NAME_LEN - 1);
    if (hw) memcpy(&p->hw, hw, sizeof(p->hw));
    INIT_LIST_HEAD(&p->process_rules);
    p->rule_count = 0;
    INIT_LIST_HEAD(&p->env.variables);
    sprof_state.profile_count++;
    pr_info("sprof: created profile '%s' id=%d\n", name, p->id);
    return p->id;
}

int sprof_profile_activate(int id)
{
    struct sprof_profile *p = sprof_profile_get_by_id(id);
    if (!p) return -ENOENT;
    if (p->active) return 0;
    p->active = 1;
    sprof_state.active = p;
    sprof_state.active_profile_id = id;
    sprof_build_all_content(p);
    sprof_env_build_block(p);
    pr_info("sprof: activated profile %d (%s)\n", id, p->name);
    return 0;
}

int sprof_profile_deactivate(void)
{
    if (!sprof_state.active) return -ENOENT;
    sprof_state.active->active = 0;
    sprof_state.active = NULL;
    sprof_state.active_profile_id = -1;
    pr_info("sprof: deactivated\n");
    return 0;
}

int sprof_profile_delete(int id)
{
    struct sprof_profile *p = sprof_profile_get_by_id(id);
    if (!p) return -ENOENT;
    if (p->active) sprof_profile_deactivate();
    sprof_env_free(&p->env);
    memset(p, 0, sizeof(*p));
    pr_info("sprof: deleted profile %d\n", id);
    return 0;
}

struct sprof_profile *sprof_profile_get_active(void)
{
    return sprof_state.active;
}

struct sprof_profile *sprof_profile_get_by_id(int id)
{
    if (id < 0 || id >= sprof_state.profile_count) return NULL;
    return &sprof_state.profiles[id];
}

int sprof_process_rule_add(struct sprof_profile *p, pid_t pid,
                            const char *name, const char *cmdline)
{
    struct sprof_process_rule *r;
    if (!p) return -EINVAL;
    if (p->rule_count >= SPROF_MAX_PROFILES) return -ENOSPC;
    r = kzalloc(sizeof(*r), GFP_KERNEL);
    if (!r) return -ENOMEM;
    r->target_pid = pid;
    if (name) strncpy(r->spoofed_name, name, sizeof(r->spoofed_name) - 1);
    if (cmdline) strncpy(r->spoofed_cmdline, cmdline, sizeof(r->spoofed_cmdline) - 1);
    r->active = 1;
    list_add_tail(&r->list, &p->process_rules);
    p->rule_count++;
    return 0;
}

int sprof_process_rule_remove(struct sprof_profile *p, pid_t pid)
{
    struct sprof_process_rule *r, *tmp;
    if (!p) return -EINVAL;
    list_for_each_entry_safe(r, tmp, &p->process_rules, list) {
        if (r->target_pid == pid) {
            list_del(&r->list);
            kfree(r);
            p->rule_count--;
            return 0;
        }
    }
    return -ENOENT;
}

struct sprof_process_rule *sprof_process_rule_find(struct sprof_profile *p, pid_t pid)
{
    struct sprof_process_rule *r;
    if (!p) return NULL;
    list_for_each_entry(r, &p->process_rules, list) {
        if (r->target_pid == pid) return r;
    }
    return NULL;
}
