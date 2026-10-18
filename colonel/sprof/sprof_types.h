/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPROF_TYPES_H
#define _SPROF_TYPES_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>

#define SPROF_MAX_CPU_THREADS    8
#define SPROF_MAX_CPU_CORES      8
#define SPROF_MAX_RAM_MB         65536
#define SPROF_MAX_ENV_VARS       64
#define SPROF_MAX_ENV_SIZE       16384
#define SPROF_MAX_NAME_LEN       128
#define SPROF_MAX_PROC_SIZE      32768
#define SPROF_MAX_PROFILES       16

#define SPROF_CPU_VENDOR_INTEL   "GenuineIntel"
#define SPROF_CPU_VENDOR_AMD     "AuthenticAMD"

enum sprof_profile_type {
    SPROF_TYPE_NONE = 0,
    SPROF_TYPE_WINDOWS_10,
    SPROF_TYPE_WINDOWS_11,
    SPROF_TYPE_UBUNTU_2204,
    SPROF_TYPE_DEBIAN_12,
    SPROF_TYPE_FEDORA_39,
    SPROF_TYPE_MAX
};

struct sprof_hw_profile {
    char        cpu_vendor[32];
    char        cpu_model[128];
    int         cpu_family;
    int         cpu_model_num;
    int         cpu_stepping;
    int         cpu_mhz;
    int         cpu_cores;
    int         cpu_threads;
    int         cpu_sockets;
    char        cpu_flags[512];
    int         ram_mb;
    int         swap_mb;
    char        root_device[64];
    char        root_fs[16];
    unsigned long root_size_gb;
    char        hostname[64];
    char        mac_prefix[8];
    char        bios_vendor[64];
    char        bios_version[64];
    char        board_vendor[64];
    char        board_name[64];
};

struct sprof_proc_content {
    char    cpuinfo[SPROF_MAX_PROC_SIZE];
    int     cpuinfo_len;
    char    meminfo[SPROF_MAX_PROC_SIZE];
    int     meminfo_len;
    char    stat[SPROF_MAX_PROC_SIZE];
    int     stat_len;
    char    loadavg[256];
    int     loadavg_len;
    char    uptime[256];
    int     uptime_len;
    char    hostname[256];
    int     hostname_len;
    char    filesystems[SPROF_MAX_PROC_SIZE];
    int     filesystems_len;
    char    cmdline[1024];
    int     cmdline_len;
    char    mounts[SPROF_MAX_PROC_SIZE];
    int     mounts_len;
    char    version[1024];
    int     version_len;
    char    bus_pci_devices[SPROF_MAX_PROC_SIZE];
    int     bus_pci_devices_len;
    char    interrupt[SPROF_MAX_PROC_SIZE];
    int     interrupt_len;
    char    dma_info[SPROF_MAX_PROC_SIZE];
    int     dma_info_len;
    char    ioports[SPROF_MAX_PROC_SIZE];
    int     ioports_len;
    char    iomem[SPROF_MAX_PROC_SIZE];
    int     iomem_len;
    char    zonesinfo[SPROF_MAX_PROC_SIZE];
    int     zonesinfo_len;
    char    diskstats[SPROF_MAX_PROC_SIZE];
    int     diskstats_len;
    char    vmstat[SPROF_MAX_PROC_SIZE];
    int     vmstat_len;
    char    buddyinfo[512];
    int     buddyinfo_len;
    char    slabinfo[SPROF_MAX_PROC_SIZE];
    int     slabinfo_len;
    char    softirqs[SPROF_MAX_PROC_SIZE];
    int     softirqs_len;
    char    schedstat[SPROF_MAX_PROC_SIZE];
    int     schedstat_len;
};

struct sprof_env_var {
    struct list_head    list;
    char                *name;
    char                *value;
    int                 name_len;
    int                 value_len;
};

struct sprof_env_block {
    struct list_head    variables;
    int                 var_count;
    char                *data;
    int                 size;
    int                 capacity;
};

struct sprof_process_rule {
    struct list_head    list;
    pid_t               target_pid;
    char                spoofed_name[256];
    char                spoofed_cmdline[1024];
    int                 active;
};

struct sprof_profile {
    int                         id;
    int                         active;
    int                         loaded;
    char                        name[SPROF_MAX_NAME_LEN];
    enum sprof_profile_type     type;
    struct sprof_hw_profile     hw;
    struct sprof_proc_content   proc;
    struct sprof_env_block      env;
    struct list_head            process_rules;
    int                         rule_count;
};

struct sprof_system_state {
    struct sprof_profile    profiles[SPROF_MAX_PROFILES];
    int                     profile_count;
    int                     active_profile_id;
    struct sprof_profile   *active;
    spinlock_t              lock;
    struct proc_dir_entry   *proc_dir;
    struct kobject          *kobj;
    int                     initialized;
    int                     version;
};

struct sprof_fs_spoof {
    struct list_head    list;
    char                real_path[512];
    char                *spoofed_content;
    int                 content_len;
    int                 active;
};

struct sprof_overlay_bridge {
    struct list_head    list;
    char                overlay_path[512];
    char                real_path[512];
    int                 active;
};

#endif
