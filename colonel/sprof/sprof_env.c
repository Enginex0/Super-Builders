// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_env.c - Environment variable spoofing
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include "sprof_core.h"

int sprof_env_add_var(struct sprof_env_block *env, const char *name, const char *value)
{
    struct sprof_env_var *ev;
    if (!env || !name || !value) return -EINVAL;
    if (env->var_count >= SPROF_MAX_ENV_VARS) return -ENOMEM;
    ev = kzalloc(sizeof(*ev), GFP_KERNEL);
    if (!ev) return -ENOMEM;
    ev->name = kstrdup(name, GFP_KERNEL);
    ev->value = kstrdup(value, GFP_KERNEL);
    if (!ev->name || !ev->value) {
        kfree(ev->name); kfree(ev->value); kfree(ev); return -ENOMEM;
    }
    ev->name_len = strlen(name);
    ev->value_len = strlen(value);
    list_add_tail(&ev->list, &env->variables);
    env->var_count++;
    return 0;
}

void sprof_env_build_block(struct sprof_profile *p)
{
    struct sprof_env_var *ev;
    int pos = 0;
    if (!p->env.data) {
        p->env.data = kzalloc(SPROF_MAX_ENV_SIZE, GFP_KERNEL);
        p->env.capacity = SPROF_MAX_ENV_SIZE;
    }
    list_for_each_entry(ev, &p->env.variables, list) {
        int len = scnprintf(p->env.data + pos, p->env.capacity - pos,
            "%s=%s\n", ev->name, ev->value);
        pos += len;
        if (pos >= p->env.capacity - 1) break;
    }
    p->env.size = pos;
}

void sprof_env_free(struct sprof_env_block *env)
{
    struct sprof_env_var *ev, *tmp;
    if (!env) return;
    list_for_each_entry_safe(ev, tmp, &env->variables, list) {
        list_del(&ev->list);
        kfree(ev->name); kfree(ev->value); kfree(ev);
    }
    kfree(env->data);
    env->data = NULL;
    env->size = 0;
    env->capacity = 0;
    env->var_count = 0;
    INIT_LIST_HEAD(&env->variables);
}
