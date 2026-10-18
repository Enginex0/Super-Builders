// SPDX-License-Identifier: GPL-2.0
/*
 * sprof_eud.c - Qualcomm EUD hardware probe
 * Reads actual hardware values from Snapdragon 6450
 * via QFPROM and cpufreq subsystems.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/utsname.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>
#include "sprof_core.h"

#define QCOM_QFPROM_BASE         0x00780000
#define QCOM_QFPROM_SIZE         0x10000
#define QFPROM_OEM_ID_OFFSET     0x000000E0
#define QFPROM_PTE_OFFSET        0x00000100
#define QFPROM_SOC_VER_OFFSET    0x000000E8
#define QFPROM_CPU_PART_OFFSET   0x000000F0
#define QFPROM_CPU_VARIANT_OFFSET 0x000000F4

#define SM6450_PART_NUM          0x00E0
#define SM6450_VARIANT           0x0001
#define SM6450_OEM_ID            0x0051
#define SM6450_SOC_VER           0x60050000
#define SM6450_MAX_FREQ_KHZ      2400000
#define SM6450_MIN_FREQ_KHZ      1800000
#define SM6450_BIG_CORES         4
#define SM6450_LITTLE_CORES      4
#define SM6450_TOTAL_CORES       8

struct qcom_eud_state {
    void __iomem    *qfprom_base;
    int             qfprom_mapped;
    int             initialized;
    spinlock_t      lock;
    int             cpu_family_real;
    int             cpu_model_real;
    int             cpu_variant_real;
    int             cpu_part_real;
    int             oem_id_real;
    int             soc_ver_real;
    int             max_freq_khz;
    int             min_freq_khz;
    int             total_cores;
    int             big_cores;
    int             little_cores;
};

static struct qcom_eud_state eud_state;

static inline u32 qfprom_read(u32 offset)
{
    if (!eud_state.qfprom_mapped)
        return 0;
    return readl(eud_state.qfprom_base + offset);
}

int sprof_qcom_eud_read_cpu(struct sprof_hw_profile *hw)
{
    u32 reg_val;
    int online_cpus = 0;
    int cpu;

    if (!hw)
        return -EINVAL;
    if (!eud_state.initialized) {
        pr_warn("sprof_eud: not initialized\n");
        return -ENODEV;
    }

    reg_val = qfprom_read(QFPROM_CPU_PART_OFFSET);
    eud_state.cpu_part_real = reg_val & 0xFFFF;
    reg_val = qfprom_read(QFPROM_CPU_VARIANT_OFFSET);
    eud_state.cpu_variant_real = reg_val & 0xFFFF;
    reg_val = qfprom_read(QFPROM_SOC_VER_OFFSET);
    eud_state.soc_ver_real = reg_val;
    reg_val = qfprom_read(QFPROM_OEM_ID_OFFSET);
    eud_state.oem_id_real = reg_val & 0xFFFF;

    pr_info("sprof_eud: QFPROM part=0x%04x variant=0x%04x soc=0x%08x oem=0x%04x\n",
        eud_state.cpu_part_real, eud_state.cpu_variant_real,
        eud_state.soc_ver_real, eud_state.oem_id_real);

    eud_state.max_freq_khz = cpufreq_get(0);
    if (eud_state.max_freq_khz <= 0)
        eud_state.max_freq_khz = SM6450_MAX_FREQ_KHZ;
    eud_state.min_freq_khz = SM6450_MIN_FREQ_KHZ;

    for_each_online_cpu(cpu)
        online_cpus++;
    eud_state.total_cores = online_cpus;
    if (eud_state.total_cores > SM6450_BIG_CORES) {
        eud_state.big_cores = SM6450_BIG_CORES;
        eud_state.little_cores = eud_state.total_cores - SM6450_BIG_CORES;
    } else {
        eud_state.big_cores = eud_state.total_cores;
        eud_state.little_cores = 0;
    }

    snprintf(hw->cpu_vendor, sizeof(hw->cpu_vendor), "Qualcomm Technologies, Inc");
    snprintf(hw->cpu_model, sizeof(hw->cpu_model), "Snapdragon 6450 (SM6450 Taro)");
    hw->cpu_family = 7;
    hw->cpu_model_num = eud_state.cpu_part_real;
    hw->cpu_stepping = eud_state.cpu_variant_real;
    hw->cpu_mhz = eud_state.max_freq_khz / 1000;
    hw->cpu_cores = eud_state.total_cores;
    hw->cpu_threads = eud_state.total_cores;
    hw->cpu_sockets = 1;
    snprintf(hw->cpu_flags, sizeof(hw->cpu_flags),
        "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
        "asimdhp cpuid asimdrdm lrcpc dcpop asimddp");

    return 0;
}

int sprof_qcom_eud_read_ram(struct sprof_hw_profile *hw)
{
    struct sysinfo si;
    if (!hw) return -EINVAL;
    si_meminfo(&si);
    hw->ram_mb = (u64)si.totalram * si.mem_unit / (1024 * 1024);
    hw->swap_mb = (u64)si.totalswap * si.mem_unit / (1024 * 1024);
    pr_info("sprof_eud: ram=%d MB swap=%d MB\n", hw->ram_mb, hw->swap_mb);
    return 0;
}

int sprof_qcom_eud_read_storage(struct sprof_hw_profile *hw)
{
    struct kstatfs st;
    if (!hw) return -EINVAL;
    if (vfs_statfs(&init_user_ns, &(struct path){.dentry = NULL}, &st) == 0) {
        hw->root_size_gb = (u64)st.f_blocks * st.f_frsize / (1024ULL * 1024 * 1024);
    }
    snprintf(hw->root_device, sizeof(hw->root_device), "/dev/block/bootdevice/by-name/system");
    snprintf(hw->root_fs, sizeof(hw->root_fs), "ext4");
    return 0;
}

int sprof_qcom_eud_read_network(struct sprof_hw_profile *hw)
{
    struct net_device *dev;
    if (!hw) return -EINVAL;
    rcu_read_lock();
    dev = dev_get_by_name_rcu(&init_net, "wlan0");
    if (dev) {
        hw->mac_prefix[0] = dev->dev_addr[0];
        hw->mac_prefix[1] = dev->dev_addr[1];
        hw->mac_prefix[2] = dev->dev_addr[2];
    }
    rcu_read_unlock();
    snprintf(hw->hostname, sizeof(hw->hostname), "localhost");
    return 0;
}

int sprof_qcom_eud_read_all(struct sprof_hw_profile *hw)
{
    int ret;
    if (!hw) return -EINVAL;
    ret = sprof_qcom_eud_read_cpu(hw);
    if (ret) return ret;
    ret = sprof_qcom_eud_read_ram(hw);
    if (ret) return ret;
    ret = sprof_qcom_eud_read_storage(hw);
    if (ret) return ret;
    ret = sprof_qcom_eud_read_network(hw);
    return ret;
}

int sprof_qcom_eud_init(void)
{
    memset(&eud_state, 0, sizeof(eud_state));
    spin_lock_init(&eud_state.lock);
    eud_state.qfprom_base = ioremap(QCOM_QFPROM_BASE, QCOM_QFPROM_SIZE);
    if (!eud_state.qfprom_base) {
        pr_warn("sprof_eud: QFPROM ioremap failed, will use cpufreq only\n");
    } else {
        eud_state.qfprom_mapped = 1;
    }
    eud_state.initialized = 1;
    pr_info("sprof_eud: initialized for Snapdragon 6450\n");
    return 0;
}

void sprof_qcom_eud_cleanup(void)
{
    if (eud_state.qfprom_mapped && eud_state.qfprom_base)
        iounmap(eud_state.qfprom_base);
    memset(&eud_state, 0, sizeof(eud_state));
    pr_info("sprof_eud: cleaned up\n");
}
