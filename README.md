<p align="center">
  <h1 align="center">⚡ Super-Builders</h1>
  <p align="center"><b>Pre-Patched GKI Kernel Builds for ZeroMount + SUSFS</b></p>
  <p align="center">Every kernel version. Every KSU variant. One CI pipeline.</p>
  <p align="center">
    <img src="https://img.shields.io/badge/status-beta-orange?style=for-the-badge" alt="Beta">
    <img src="https://img.shields.io/badge/GKI-android_12--16-green?style=for-the-badge&logo=android" alt="GKI">
    <img src="https://img.shields.io/badge/Telegram-community-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </p>
</p>

---

> [!WARNING]
> **Super-Builders is in active development. Kernel builds are provided as-is.**
>
> Flashing a custom kernel carries inherent risk. **You are solely responsible for any outcome** — including bootloops, data loss, or bricked devices. Review the patches, understand your device's kernel version, and make sure you know what you're doing before flashing. If in doubt, fork this repo and build the kernel yourself.
>
> No warranty. No liability. Your device, your risk.

---

## 🧬 What is Super-Builders?

Super-Builders is the **kernel build pipeline** for [ZeroMount](https://github.com/Enginex0/zeromount). It takes Google's stock GKI kernel sources, applies the SUSFS + ZeroMount VFS patches, and compiles them across every supported Android version, kernel version, and KSU variant via GitHub Actions CI.

The kernels built here provide the **infrastructure layer** — the hiding primitives, VFS hooks, and control interfaces that the [ZeroMount userspace module](https://github.com/Enginex0/zeromount) relies on for mountless module loading, root detection evasion, and SUSFS automation.

**Super-Builders builds the engine. [ZeroMount](https://github.com/Enginex0/zeromount) drives it.**

---

## ✨ What's In The Kernel Patches

### SUSFS Hiding Infrastructure

- [x] **Path hiding** — files and directories vanish from `readdir` and path lookups for unprivileged apps
- [x] **Kstat spoofing** — file metadata (inode, device, timestamps, size) returns stock values to `stat`/`fstat`/`lstat`
- [x] **Maps hiding** — `/proc/PID/maps`, `/proc/PID/mem`, pagemap, and `map_files` entries blanked for flagged inodes
- [x] **Mount ID spoofing** — non-SU processes see fake mount IDs across `mountinfo`, `fdinfo`, `statfs`
- [x] **Mount hiding** — KSU mount entries filtered from `/proc/PID/mountinfo` for non-root processes
- [x] **Uname spoofing** — `uname -r` / `uname -v` return stock-looking kernel version strings
- [x] **Cmdline & bootconfig spoofing** — `/proc/cmdline` and `/proc/bootconfig` show clean boot state
- [x] **AVC log suppression** — SELinux audit denial messages suppressed from dmesg/logcat
- [x] **Kallsyms hiding** — SUSFS and ZeroMount kernel symbols hidden from `/proc/kallsyms`

### ZeroMount VFS Engine

- [x] **VFS path redirection** — intercepts `getname()` to redirect file lookups at the VFS layer, zero mount table entries
- [x] **Directory entry injection** — module files appear in `ls` / `readdir` like stock system files
- [x] **d_path spoofing** — `/proc/PID/fd` symlinks and `d_path()` return virtual paths
- [x] **Mmap metadata spoofing** — `/proc/PID/maps` dev/ino replaced with stock values for redirected files
- [x] **SELinux xattr injection** — redirected files carry correct SELinux contexts (`system_file`, `vendor_file`, etc.)
- [x] **statfs spoofing** — system partitions report `EROFS_SUPER_MAGIC` as expected
- [x] **Write protection** — injected files are read-only through virtual paths, preventing source corruption
- [x] **Bloom filter** — 4096-bit 3-hash pre-check rejects non-matching paths in a few CPU cycles
- [x] **ioctl control** — `/dev/zeromount` miscdevice with 11 commands for userspace rule management

### Custom Extensions (Not in Upstream SUSFS)

- [x] **Kstat redirect** — single supercall maps virtual-path stat to real-path metadata
- [x] **Unicode filter** — blocks filesystem path attacks using invisible/confusable unicode characters
- [x] **AS_FLAGS collision guards** — `BUILD_BUG_ON` prevents inode flag bit conflicts between SUSFS and ZeroMount

### Performance & Safety

- [x] **Inline fast-path** — root/system processes skip hiding logic entirely (zero overhead)
- [x] **Two-level readdir guard** — parent directory flags enable early skip when no hidden children exist
- [x] **RCU-protected data structures** — all hash tables use Read-Copy-Update for lock-free concurrent reads
- [x] **Zygote SID null guard** — prevents false-positive process classification during early boot
- [x] **UID range fix** — all Android app UIDs (10000–19999) correctly recognized
- [x] **Memory barriers** — `WRITE_ONCE`/`READ_ONCE` on hot-path hook flags for cross-CPU safety
- [x] **strncpy null-termination** — buffer overread prevention across 5+ SUSFS entry points
- [x] **EACCES removal** — hidden paths return `ENOENT` (indistinguishable from nonexistent) instead of leaking SUSFS presence

---

## 📋 Build Progress

### GKI Kernels

| Android | Kernel | Sublevels | Variants | Patches | Build |
|---------|--------|-----------|----------|---------|-------|
| Android 12 | 5.10 | 107 → 246 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | ✅ All green |
| Android 13 | 5.10 | 107 → 246 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |
| Android 13 | 5.15 | 41 → 194 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |
| Android 14 | 5.15 | 131 → 194 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |
| Android 14 | 6.1 | 25 → 157 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |
| Android 15 | 6.6 | 30 → 127 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |
| Android 16 | 6.12 | 23 → 58 | SukiSU, ReSukiSU, KSU-Next, WKSU | ✅ | 🔄 In progress |

### Pre-GKI

| Android | Kernel | Sublevels | Variants | Patches | Build |
|---------|--------|-----------|----------|---------|-------|
| Android 12 | 5.4 (LTS) | 302 | SukiSU, ReSukiSU | ✅ | ✅ All green |

> KernelSU-Next and WKSU are not supported on 5.4 — they lack pre-5.7 compatibility (`TWA_RESUME` enum).

### Not Yet Done

| Target | Status | Notes |
|--------|--------|-------|
| non-GKI 4.19 | 🔲 Planned | — |
| non-GKI 4.14 | 🔲 Planned | — |
| MKSU workflow | 🔲 Planned | No SUSFS branch exists upstream yet |
| RKSU workflow | 🔲 Planned | No SUSFS integration upstream yet |

### Deferred

| Target | Status | Notes |
|--------|--------|-------|
| USB ADB filter (65_ patches) | ⏸️ Deferred | Patches archived — may revisit later |

---

## 🔧 Patch Architecture

Each kernel version directory contains the same three-layer patch system:

```
android12-5.10/
├── SukiSU-Ultra/patches/
│   ├── 50_enhanced_susfs-android12-5.10.patch    # SUSFS hiding infrastructure (~3900 lines)
│   ├── 60_zeromount-android12-5.10.patch          # ZeroMount VFS driver (~2200 lines)
│   └── 70_ksu_safety-sukisu-5.10.patch            # KSU variant-specific safety fixes
├── KernelSU-Next/patches/
│   ├── 50_enhanced_susfs-android12-5.10.patch     # same 50_ — variant-independent
│   ├── 60_zeromount-android12-5.10.patch           # same 60_ — variant-independent
│   └── 70_ksu_safety-kernelsu-next-5.10.patch     # different 70_ — variant-specific
├── build-helpers/                                  # sublevel compat scripts
└── defconfig.fragment                              # kernel config flags
```

**`50_` (Enhanced SUSFS)** — The core hiding infrastructure. Hooks `readdir`, `namei`, `stat`, `proc`, `namespace`, and more. Shared across all KSU variants — same patch, different forks.

**`60_` (ZeroMount VFS)** — The mountless file injection driver. Intercepts `getname()`, injects directory entries, spoofs `d_path`, xattrs, and statfs. Also variant-independent.

**`70_` (KSU Safety)** — Small variant-specific patches for each KSU fork. Fixes null-termination, UID ranges, zygote guards, and supercall wiring in the fork's own `kernel/` directory.

**`build-helpers/`** — Scripts that handle sublevel-specific compatibility issues across kernel versions. Different sublevels have different API surfaces — these scripts detect and adapt at build time.

**`defconfig.fragment`** — Kernel config flags enabling SUSFS, ZeroMount, ZRAM, BBR, and other features.

**Application order:** `50_` → `70_` → `60_` → build-helpers

---

## 🏗️ KSU Variants

| Variant | Fork | 5.4 Support |
|---------|------|-------------|
| **SukiSU Ultra** | [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) | ✅ |
| **ReSukiSU** | [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) | ✅ |
| **KernelSU-Next** | [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next) | 🔲 Planned |
| **WKSU** | [WildKSU](https://github.com/WildKernels/Wild_KSU) | 🔲 Planned |

All four variants share the same `50_` and `60_` kernel patches. The `70_` patch is generated per-variant to address safety issues specific to each fork's codebase.

---

## 🚀 Quick Start

1. **Find your kernel version** — check `Settings → About Phone → Kernel version` or run `uname -r`
2. **Download the matching build** from [Releases](https://github.com/Enginex0/Super-Builders/releases) for your Android version, kernel sublevel, and preferred KSU variant
3. **Flash the kernel** using your preferred method (fastboot, custom recovery, etc.)
4. **Install [ZeroMount](https://github.com/Enginex0/zeromount)** — the userspace module that activates the kernel features
5. **Reboot** and open the ZeroMount WebUI from your KSU manager

> [!CAUTION]
> **Flashing the wrong kernel version will bootloop your device.** Match your exact Android version and kernel sublevel. If you're unsure, don't flash — ask in the [Telegram group](https://t.me/superpowers9) first.

---

## 🔨 Build It Yourself

Every build runs through GitHub Actions CI. Fork this repo and trigger the workflow for your target:

```bash
# Dispatch a specific kernel build
gh workflow run kernel-a12-5.10.yml --ref main \
  -f ksu_variant=SukiSU \
  -f add_susfs=true \
  -f add_zeromount=true

# Or use kernel-custom.yml for single-sublevel builds
gh workflow run kernel-custom.yml --ref main \
  -f kernel_target="android12-5.10.107 (2022-11)" \
  -f ksu_variant=All
```

The CI pipeline handles kernel source checkout, patch application, build-helper execution, compilation, and artifact packaging automatically.

---

## 💬 Community

```bash
$ super-builders --connect

 ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗████████╗
██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝
██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        ██║
██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        ██║
╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗   ██║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝

 [✓] SIGNAL    ──→  t.me/superpowers9
 [✓] UPLINK    ──→  kernel builds · bug triage · feature drops
 [✓] STATUS    ──→  OPEN — all operators welcome
```

<p align="center">
  <a href="https://t.me/superpowers9">
    <img src="https://img.shields.io/badge/⚡_JOIN_THE_GRID-SuperPowers_Telegram-black?style=for-the-badge&logo=telegram&logoColor=cyan&labelColor=0d1117&color=00d4ff" alt="Telegram">
  </a>
</p>

---

## 🙏 Credits

- **[ZeroMount](https://github.com/Enginex0/zeromount)** — the userspace module that drives these kernels
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** by simonpunk — the hiding framework these patches are built on
- **[SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)** — SukiSU fork with builtin SUSFS
- **[ReSukiSU](https://github.com/ReSukiSU/ReSukiSU)** — ReSukiSU fork
- **[KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)** — next-gen KernelSU fork
- **[WildKSU](https://github.com/WildKernels/Wild_KSU)** — WildKSU fork
- **[KernelSU](https://github.com/tiann/KernelSU)** by tiann — the original kernel root framework
- **[NoMount](https://github.com/maxsteeel/nomount)** — the project that inspired the VFS approach

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

<p align="center">
  <b>⚡ The kernel infrastructure behind 👻 GHOST mode.</b>
</p>
