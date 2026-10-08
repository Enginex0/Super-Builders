# Kernel Build Directory

Patches, configuration, and build scripts for one GKI kernel version. CI applies these to Google's stock kernel source, compiles across all supported sublevels, and outputs flashable boot images with SUSFS hiding + ZeroMount VFS injection.

See the [root README](../README.md) for project overview and feature details.

---

## Directory Layout

```
├── SukiSU-Ultra/patches/
│   ├── 50_add_susfs_in_gki-*.patch      # upstream SUSFS
│   ├── 51_enhanced_susfs-*.patch         # our enhancements
│   ├── 60_zeromount-*.patch              # ZeroMount VFS driver
│   └── 70_ksu_safety-sukisu-*.patch      # variant-specific fixes
├── ReSukiSU/patches/                     # same 50_/51_/60_, different 70_
├── KernelSU-Next/patches/                # same 50_/51_/60_, different 70_
├── WildKSU/patches/                      # same 50_/51_/60_, different 70_
├── build-helpers/                        # sublevel compat scripts
├── defconfig.fragment                    # kernel config toggles
├── samsung-s928bxxu6zzhl-source.env      # immutable ZZHL source-port provenance
├── samsung-s928bxxu6zzhl-target.env      # exact EUX/ZZHL firmware and image identity
├── samsung-sm-s928b-17-zzhl-common-port.tar.xz # DZG1 delta ported to AOSP 6.1.162
├── sukisu-pin.txt                        # git commit pin for SukiSU fork
├── resukisu-pin.txt                      # git commit pin for ReSukiSU fork
├── kernelsu-next-pin.txt                 # git commit pin for KSU-Next fork
└── wksu-pin.txt                          # git commit pin for WildKSU fork
```

> **android12-5.4 only has SukiSU and ReSukiSU.** KSU-Next and WildKSU lack pre-5.7 kernel compatibility.

---

## Patches

Four patches per variant. Within the same kernel version, **50_, 51_, and 60_ are identical across all variants.** Only 70_ differs — it targets each KSU fork's specific codebase.

| Patch | Contents | Scope |
|-------|----------|-------|
| **50_** | Upstream SUSFS from [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu). Hooks readdir, namei, stat, proc, namespace, mount. Creates `fs/susfs.c` and supporting headers. | Shared |
| **51_** | Our enhancements on top of upstream: Kconfig-toggled features, bug fixes, hardening, strncpy null-termination, EACCES→ENOENT fix, AS_FLAGS collision guards. | Shared |
| **60_** | ZeroMount VFS driver. Path redirection via `getname()`, directory entry injection, d_path spoofing, xattr injection, statfs spoofing, bloom filter, ioctl interface. | Shared |
| **70_** | KSU fork safety fixes. Null-termination, UID range corrections, zygote SID guards, supercall wiring. Small (~18 lines for SukiSU builtin, larger for others). | Per-variant |

### Application Order

```
50_ → 51_ → 70_ → 60_ → fix-susfs-compat.sh (runtime)
```

50_ lays the SUSFS foundation. 51_ enhances it. 70_ fixes the KSU fork. 60_ adds ZeroMount on top. `fix-susfs-compat.sh` handles sublevel-specific issues that static patches can't cover.

---

## defconfig.fragment

This file gets merged on top of the stock GKI defconfig at build time. Each section controls a feature group. Edit it to enable or disable features for your build.

### [base]

| Toggle | Default | Purpose |
|--------|---------|---------|
| `CONFIG_KSU` | y | KernelSU root framework. Everything depends on this. |
| `CONFIG_SECCOMP` + `CONFIG_SECCOMP_FILTER` | y | Keeps seccomp support compiled into the kernel. |
| `CONFIG_UAPI_HEADER_TEST` | n | **5.4 only.** Disables header test that fails with prebuilt clang. Absent on 5.10+. |
| `CONFIG_TCP_CONG_BBR` | y | BBR congestion control. Better throughput on lossy networks. |
| `CONFIG_TCP_CONG_CUBIC` | y | CUBIC congestion control. Linux default. |
| `CONFIG_TCP_CONG_WESTWOOD` | y | Westwood+ congestion control. Good for wireless. |
| `CONFIG_IP_SET` + related | y | ipset support for firewall apps (AFWall+, NetGuard). |
| `CONFIG_KALLSYMS_ALL` | y | Full kernel symbol table. Required by KSU for hook resolution. |

### [susfs]

Every toggle here depends on `CONFIG_KSU_SUSFS=y`. Disable the master toggle and none of these compile.

| Toggle | Default | What it hides |
|--------|---------|---------------|
| `CONFIG_KSU_SUSFS` | y | **Master toggle.** Enables the entire SUSFS hiding framework. |
| `CONFIG_KSU_SUSFS_SUS_PATH` | y | Files and directories vanish from `readdir` and path lookups. Set to `n` on 6.12 (AS_FLAGS bit collision). Absent on 6.6. |
| `CONFIG_KSU_SUSFS_SUS_MOUNT` | y | Mount entries filtered from `/proc/PID/mountinfo`. |
| `CONFIG_KSU_SUSFS_SUS_KSTAT` | y | `stat()`/`fstat()`/`lstat()` return spoofed metadata (inode, device, timestamps). |
| `CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT` | y | Maps virtual-path stat to real-file metadata. Used by ZeroMount. |
| `CONFIG_KSU_SUSFS_SUS_MAP` | y | `/proc/PID/maps` and `/proc/PID/mem` entries hidden for flagged inodes. |
| `CONFIG_KSU_SUSFS_SPOOF_UNAME` | y | `uname -r` returns a stock-looking kernel version string. |
| `CONFIG_KSU_SUSFS_ENABLE_LOG` | y | SUSFS debug logging to dmesg. Disable for production if log noise matters. |
| `CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG` | y | `/proc/cmdline` and `/proc/bootconfig` show clean boot state. |
| `CONFIG_KSU_SUSFS_OPEN_REDIRECT` | y | File open operations redirected to alternate paths. |
| `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS` | y | SUSFS and ZeroMount symbols hidden from `/proc/kallsyms`. |
| `CONFIG_KSU_SUSFS_UNICODE_FILTER` | y | Blocks invisible/confusable unicode characters in filesystem paths. |
| `CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT` | y | Auto-adds KSU default mounts to the hidden mount list. |
| `CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT` | y | Auto-adds bind mounts to the hidden mount list. |
| `CONFIG_KSU_SUSFS_HIDDEN_NAME` | y | Hidden name/inode hash tables + VFS hooks. **5.10 only.** |
| `CONFIG_KSU_SUSFS_HARDENED` | y | Additional hardening checks. **5.10 only.** |

### [zram]

Compressed RAM swap. All compression algorithms enabled so the kernel picks the best one at runtime. Default compressor is LZ4KD. Safe to leave as-is.

### [overlayfs]

```
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_POSIX_ACL=y
```

Required for KSU module overlays to work. Don't disable unless you know what you're doing.

### [performance]

Debug options that may be enabled by your device's vendor config. **All commented out by default.** Check `/proc/config.gz` on your device first — only uncomment if these are actually set in your base config.

Disabling them reduces lock contention and improves throughput, but removes kernel debug safety nets.

### [kpm]

```
CONFIG_KPM=y
```

Kernel Patch Manager. Enables runtime kernel patching support.

---

## KSU Variants

Each variant is a different fork of KernelSU. The CI checks out the exact commit specified in the pin file, applies patches, and builds.

| Variant | Fork | Pin File |
|---------|------|----------|
| SukiSU Ultra | [SukiSU-Ultra/SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) | `sukisu-pin.txt` |
| ReSukiSU | [ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) | `resukisu-pin.txt` |
| KernelSU-Next | [KernelSU-Next/KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next) | `kernelsu-next-pin.txt` |
| WildKSU | [WildKernels/Wild_KSU](https://github.com/WildKernels/Wild_KSU) | `wksu-pin.txt` |

**SukiSU pin must point to the `builtin` branch.** The `main` branch lacks `CONFIG_KSU_SUSFS` in its Kconfig, which means `fs/susfs.o` never compiles and the build fails with undefined symbol errors at link time.

To update a pin: change the commit hash in the pin file. Test with dry-test first.

---

## Build Helpers

Scripts in `build-helpers/` are called by CI at specific stages. They handle differences between kernel sublevels so the same patches work across the full sublevel range.

| Script | Stage | Purpose |
|--------|-------|---------|
| `assemble-defconfig.sh` | Pre-build | Merges GKI base defconfig + `defconfig.fragment` into final `.config` |
| `fix-old-kernel-compat.sh` | Pre-patch | Fixes vanilla kernel issues on older sublevels (missing includes, etc.) |
| `fix-susfs-compat.sh` | Post-patch | Fixes sublevel-dependent SUSFS issues. Idempotent — safe to run multiple times. |
| `bypass-abi-check.sh` | Pre-build | Skips GKI ABI compliance checks. Custom kernels break the stable driver ABI by design. |
| `clean-build-flags.sh` | Pre-build | Strips debug/test config options for production builds. |
| `clean-module-list.sh` | Pre-build | Removes modules not needed for the target device. |
| `apply-s928b-zzhl-source-port.sh` | Post-sync | Verifies and applies the audited DZG1 Samsung delta port onto the pinned AOSP 6.1.162 common tree used for ZZHL. |
| `report-config.sh` | Post-config | Prints enabled features to CI logs for verification. |
| `setup-bbg.sh` | Pre-build | Configures BBG support. |

---

## Building

### From GitHub Actions UI

1. Go to **Actions** → pick the workflow for your variant (`build-sukisu.yml`, `build-resukisu.yml`, etc.)
2. Click **Run workflow**
3. Fill in: `android_version`, `kernel_version`, `sub_level`, `os_patch_level`
4. Toggle feature flags as needed (all default to on except `add_bbg` and `add_kpm`)

### From CLI

```bash
# Single target build (all variants)
gh workflow run kernel-custom.yml --ref main \
  -f kernel_target="android12-5.10.209 (2024-05)"

# Specific variant
gh workflow run build-sukisu.yml --ref main \
  -f android_version=android12 \
  -f kernel_version=5.10 \
  -f sub_level=209 \
  -f os_patch_level=2024-05
```

### Feature Flags

| Flag | Default | Controls |
|------|---------|----------|
| `add_susfs` | true | Applies 50_ + 51_ patches |
| `add_zeromount` | true | Applies 60_ patch |
| `add_zram` | true | Enables ZRAM config section |
| `add_overlayfs_support` | true | Enables overlayfs config section |
| `add_bbg` | false | Runs `setup-bbg.sh` |
| `add_kpm` | false | Enables KPM config section |

### Dry-Testing (Patch Validation)

Validates that patches apply cleanly to the kernel source without compiling. Run this before full builds to catch patch conflicts early.

```bash
# Single sublevel
gh workflow run dry-test-patches.yml --ref main \
  -f android_version=android12 \
  -f kernel_version=5.10 \
  -f sub_level=209 \
  -f os_patch_level=2024-05 \
  -f mode=single

# All sublevels for this kernel version
gh workflow run dry-test-patches.yml --ref main \
  -f android_version=android12 \
  -f kernel_version=5.10 \
  -f mode=matrix
```

---

## Version-Specific Notes

Not all kernel versions are identical. Key differences:

| Kernel | Variants | Notable Differences |
|--------|----------|---------------------|
| 5.4 | 2 (SukiSU, ReSukiSU) | Pre-GKI. Requires `UAPI_HEADER_TEST=n`. No KSU-Next/WKSU (lack `TWA_RESUME`). Single sublevel (302 LTS). |
| 5.10 | 4 | Baseline GKI. Has `HIDDEN_NAME` and `HARDENED` toggles (unique to 5.10). |
| 5.15 | 4 | `struct nameidata` natively has `state` field (upstream patch adds it redundantly). |
| 6.1 | 4 | `vfs_statx` takes `struct filename *`. `inode_permission` gained `mnt_userns` parameter. |
| 6.6 | 4 | `SUS_PATH` absent from defconfig (not supported). `do_faccessat`/`do_sys_openat2` moved to `fs/open.c`. |
| 6.12 | 4 | `SUS_PATH=n` (AS_FLAGS bit collision). LTO disabled (`none`). `fd_file()` accessor replaces `f.file`. |

---

## Updating Patches

**50_ (upstream SUSFS):** Replace with the latest from [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu). After replacing, always re-test 51_ — context lines may have shifted.

**51_ (enhancements):** Must be regenerated if 50_ changes. Apply 50_ to a clean kernel source, make your changes, diff against the post-50_ tree.

**60_ (ZeroMount):** Independent of 50_/51_. Update separately.

**70_ (KSU safety):** Regenerate when pinning to a new KSU fork commit. Diff the fork's `kernel/` directory to find what needs fixing.

After any patch update: dry-test → smoke build (lowest + highest sublevel) → full matrix.
