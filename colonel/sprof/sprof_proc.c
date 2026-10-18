// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_proc.c - Generate /proc/* spoofed content from hw profile
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include "sprof_core.h"

void sprof_build_cpuinfo(struct sprof_profile *p)
{
    struct sprof_hw_profile *hw = &p->hw;
    int len = scnprintf(p->proc.cpuinfo, SPROF_MAX_PROC_SIZE,
        "processor\t: %d\n"
        "BogoMIPS\t: %lu.%02lu\n"
        "Features\t: %s\n"
        "CPU implementer\t: 0x%02x\n"
        "CPU architecture: %d\n"
        "CPU variant\t: 0x%x\n"
        "CPU part\t: 0x%03x\n"
        "CPU revision\t: %d\n\n",
        0, (loops_per_jiffy / 500000UL), ((loops_per_jiffy / 5000UL) % 100UL),
        hw->cpu_flags, hw->cpu_model_num >> 8, hw->cpu_family,
        hw->cpu_model_num & 0xFF, hw->cpu_model_num, hw->cpu_stepping);
    p->proc.cpuinfo_len = len;
}

void sprof_build_meminfo(struct sprof_profile *p)
{
    struct sysinfo si;
    si_meminfo(&si);
    p->proc.meminfo_len = scnprintf(p->proc.meminfo, SPROF_MAX_PROC_SIZE,
        "MemTotal:       %lu kB\n"
        "MemFree:        %lu kB\n"
        "MemAvailable:   %lu kB\n"
        "Buffers:        %lu kB\n"
        "Cached:         %lu kB\n"
        "SwapTotal:      %lu kB\n"
        "SwapFree:       %lu kB\n",
        si.totalram * si.mem_unit / 1024,
        si.freeram * si.mem_unit / 1024,
        si.freeram * si.mem_unit / 1024,
        si.bufferram * si.mem_unit / 1024,
        (si.totalram - si.freeram) * si.mem_unit / 4096,
        si.totalswap * si.mem_unit / 1024,
        si.freeswap * si.mem_unit / 1024);
}

void sprof_build_stat(struct sprof_profile *p)
{
    p->proc.stat_len = scnprintf(p->proc.stat, SPROF_MAX_PROC_SIZE,
        "cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
        0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL);
}

void sprof_build_loadavg(struct sprof_profile *p)
{
    p->proc.loadavg_len = scnprintf(p->proc.loadavg, 256,
        "0.01 0.02 0.00 1/%d 1\n", p->hw.cpu_threads);
}

void sprof_build_uptime(struct sprof_profile *p)
{
    p->proc.uptime_len = scnprintf(p->proc.uptime, 256, "%lu.%02lu\n", 0UL, 0UL);
}

void sprof_build_hostname(struct sprof_profile *p)
{
    struct new_utsname *u = &init_uts_ns.name;
    p->proc.hostname_len = scnprintf(p->proc.hostname, 256, "%s\n", u->nodename);
}

void sprof_build_filesystems(struct sprof_profile *p)
{
    p->proc.filesystems_len = scnprintf(p->proc.filesystems, SPROF_MAX_PROC_SIZE,
        "nodev\ttmpfs\nnodev\tproc\nnodev\tsysfs\nnodev\tdevpts\n"
        "nodev\tdevtmpfs\n\text4\n\tvfat\n\tnfs\n\tcifs\n"
        "nodev\toverlay\nnodef\tsquashfs\nnodev\tpstore\n");
}

void sprof_build_cmdline(struct sprof_profile *p)
{
    p->proc.cmdline_len = scnprintf(p->proc.cmdline, 1024,
        "BOOT_IMAGE=/vmlinuz root=/dev/mmcblk0p2 ro console=ttyS0,115200\n");
}

void sprof_build_mounts(struct sprof_profile *p)
{
    p->proc.mounts_len = scnprintf(p->proc.mounts, SPROF_MAX_PROC_SIZE,
        "/dev/mmcblk0p2 / ext4 ro,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\n");
}

void sprof_build_version(struct sprof_profile *p)
{
    struct new_utsname *u = &init_uts_ns.name;
    p->proc.version_len = scnprintf(p->proc.version, 1024,
        "#1 SMP PREEMPT %s %s\n", u->release, u->version);
}

void sprof_build_bus_pci(struct sprof_profile *p)
{
    p->proc.bus_pci_devices_len = scnprintf(p->proc.bus_pci_devices, SPROF_MAX_PROC_SIZE,
        "0000:00:00.0 Host bridge: Qualcomm SoC\n");
}

void sprof_build_interrupt(struct sprof_profile *p)
{
    p->proc.interrupt_len = scnprintf(p->proc.interrupt, SPROF_MAX_PROC_SIZE,
        "           CPU0\n"
        "  0:         0  GIC  32 Level  arch_timer\n"
        "  1:         0  GIC  33 Level  arch_timer\n");
}

void sprof_build_diskstats(struct sprof_profile *p)
{
    p->proc.diskstats_len = scnprintf(p->proc.diskstats, SPROF_MAX_PROC_SIZE,
        " 179       0 mmcblk0 1024 100 2048 100 0 0 0 0 100 100\n");
}

void sprof_build_vmstat(struct sprof_profile *p)
{
    p->proc.vmstat_len = scnprintf(p->proc.vmstat, SPROF_MAX_PROC_SIZE,
        "nr_free_pages %lu\n", 1024UL);
}

void sprof_build_buddyinfo(struct sprof_profile *p)
{
    p->proc.buddyinfo_len = scnprintf(p->proc.buddyinfo, 512,
        "Node 0, zone DMA 100 100 100 100 100 100 100 100 100 100 100\n");
}

void sprof_build_slabinfo(struct sprof_profile *p)
{
    p->proc.slabinfo_len = scnprintf(p->proc.slabinfo, SPROF_MAX_PROC_SIZE,
        "slabinfo - version: 2.1\n");
}

void sprof_build_softirqs(struct sprof_profile *p)
{
    p->proc.softirqs_len = scnprintf(p->proc.softirqs, SPROF_MAX_PROC_SIZE,
        "                    CPU0\n"
        "          HI:        0\n"
        "       TIMER:        0\n");
}

void sprof_build_all_content(struct sprof_profile *p)
{
    sprof_build_cpuinfo(p);
    sprof_build_meminfo(p);
    sprof_build_stat(p);
    sprof_build_loadavg(p);
    sprof_build_uptime(p);
    sprof_build_hostname(p);
    sprof_build_filesystems(p);
    sprof_build_cmdline(p);
    sprof_build_mounts(p);
    sprof_build_version(p);
    sprof_build_bus_pci(p);
    sprof_build_interrupt(p);
    sprof_build_diskstats(p);
    sprof_build_vmstat(p);
    sprof_build_buddyinfo(p);
    sprof_build_slabinfo(p);
    sprof_build_softirqs(p);
}
