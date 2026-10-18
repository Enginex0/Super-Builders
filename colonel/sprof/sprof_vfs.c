// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_vfs.c - VFS interception layer
 * Intercepts /proc/* reads and returns spoofed content
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "sprof_core.h"

static LIST_HEAD(sprof_fs_spoofs);
static LIST_HEAD(sprof_overlay_bridges);
static DEFINE_SPINLOCK(sprof_vfs_lock);

const char *sprof_vfs_check_spoof(const char *path, int *out_len)
{
    struct sprof_fs_spoof *s;
    const char *result = NULL;
    if (!path || !out_len) return NULL;
    spin_lock(&sprof_vfs_lock);
    list_for_each_entry(s, &sprof_fs_spoofs, list) {
        if (s->active && strcmp(s->real_path, path) == 0) {
            *out_len = s->content_len;
            result = s->spoofed_content;
            break;
        }
    }
    spin_unlock(&sprof_vfs_lock);
    return result;
}

int sprof_vfs_add_spoof(const char *real_path, const char *content, int content_len)
{
    struct sprof_fs_spoof *s;
    if (!real_path || !content) return -EINVAL;
    s = kzalloc(sizeof(*s), GFP_KERNEL);
    if (!s) return -ENOMEM;
    strncpy(s->real_path, real_path, sizeof(s->real_path) - 1);
    s->spoofed_content = kzalloc(content_len + 1, GFP_KERNEL);
    if (!s->spoofed_content) { kfree(s); return -ENOMEM; }
    memcpy(s->spoofed_content, content, content_len);
    s->content_len = content_len;
    s->active = 1;
    spin_lock(&sprof_vfs_lock);
    list_add_tail(&s, &sprof_fs_spoofs);
    spin_unlock(&sprof_vfs_lock);
    return 0;
}

int sprof_vfs_remove_spoof(const char *real_path)
{
    struct sprof_fs_spoof *s, *tmp;
    if (!real_path) return -EINVAL;
    list_for_each_entry_safe(s, tmp, &sprof_fs_spoofs, list) {
        if (strcmp(s->real_path, real_path) == 0) {
            list_del(&s->list);
            kfree(s->spoofed_content);
            kfree(s);
            return 0;
        }
    }
    return -ENOENT;
}

int sprof_overlay_add_bridge(const char *overlay_path, const char *real_path)
{
    struct sprof_overlay_bridge *b;
    if (!overlay_path || !real_path) return -EINVAL;
    b = kzalloc(sizeof(*b), GFP_KERNEL);
    if (!b) return -ENOMEM;
    strncpy(b->overlay_path, overlay_path, sizeof(b->overlay_path) - 1);
    strncpy(b->real_path, real_path, sizeof(b->real_path) - 1);
    b->active = 1;
    spin_lock(&sprof_vfs_lock);
    list_add_tail(&b, &sprof_overlay_bridges);
    spin_unlock(&sprof_vfs_lock);
    return 0;
}

int sprof_overlay_remove_bridge(const char *overlay_path)
{
    struct sprof_overlay_bridge *b, *tmp;
    if (!overlay_path) return -EINVAL;
    list_for_each_entry_safe(b, tmp, &sprof_overlay_bridges, list) {
        if (strcmp(b->overlay_path, overlay_path) == 0) {
            list_del(&b->list);
            kfree(b);
            return 0;
        }
    }
    return -ENOENT;
}

const char *sprof_overlay_check_bridge(const char *overlay_path)
{
    struct sprof_overlay_bridge *b;
    const char *result = NULL;
    if (!overlay_path) return NULL;
    spin_lock(&sprof_vfs_lock);
    list_for_each_entry(b, &sprof_overlay_bridges, list) {
        if (b->active && strcmp(b->overlay_path, overlay_path) == 0) {
            result = b->real_path;
            break;
        }
    }
    spin_unlock(&sprof_vfs_lock);
    return result;
}
