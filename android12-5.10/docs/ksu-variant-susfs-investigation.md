# KSU Variant SUSFS Integration Investigation

**Date:** 2026-02-25
**Branch:** experiment/boot-debug
**CI Workflow:** kernel-custom.yml → gki-build.yml
**Kernel Target:** android12-5.10.209

---

## 1. CI Failure Summary

| Run ID | Variant | Result | Error |
|--------|---------|--------|-------|
| 22406734629 | RKSU 5.10.209 | **LINK FAIL** | `undefined symbol: ksu_init_rc_hook`, `undefined symbol: ksu_handle_vfs_fstat` |
| 22406715661 | SukiSU 5.10.209 | **COMPILE FAIL** | `implicit declaration of function 'susfs_is_current_proc_umounted'`, `implicit declaration of function 'susfs_is_hidden_name'` in fs/open.c |
| 22406726337 | (successful run) | **PASS** | — |
| — | ReSukiSU 5.10.209 | **BUILD PASS, RUNTIME FAIL** | Detections triggered, device instability after flash |

---

## 2. Build Pipeline Flow

From `gki-build.yml` (984 lines), the kernel build follows this sequence:

```
1. Checkout repo
2. Set build params (ANDROID_VERSION, KERNEL_VERSION, SUB_LEVEL, etc.)
3. Free disk space
4. Restore cached toolchain + kernel source
5. Clone kernel source (Google GKI android12-5.10)
6. ── Add KSU Variant ──
   │  Runs variant-specific setup.sh with branch selection
   │  Installs KSU driver to drivers/kernelsu/
   │
7. ── Fix KernelSU API Compatibility ──
   │  Adds stubs for missing symbols (currently only ksu_handle_sys_newfstatat)
   │  Renames RKSU SUSFS API names to match upstream
   │
8. ── Clone SUSFS and Apply Patches ──
   │  a. Clone external SUSFS repo (fork or upstream)
   │  b. If add_enhanced_susfs: run fix-susfs.sh, inject-susfs-features.sh, etc.
   │  c. Copy susfs.c, susfs.h, susfs_def.h to kernel tree
   │  d. Apply GKI patch (50_add_susfs_in_gki-android12-5.10.patch)
   │  e. Post-patch compat fixes (patch-fdinfo-compat.sh)
   │  f. If add_enhanced_susfs: run patch-kernel-sources.sh, patch-config.sh
   │
9. Apply device-specific patches (ZeroMount, ZRAM, etc.)
10. Build kernel
```

### KSU Variant Branch Selection (gki-build.yml:185-212)

| Variant | Setup URL | SUSFS Branch | Non-SUSFS Branch |
|---------|-----------|-------------|------------------|
| SukiSU | ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh | `susfs-dev` | `main` |
| MKSU | 5ec1cff/KernelSU/main/kernel/setup.sh | `susfs-dev` | `main` |
| ReSukiSU | ReSukiSU/ReSukiSU/main/kernel/setup.sh | `susfs-ksud` | `main` |
| WKSU | WildKernels/Wild_KSU/stable/kernel/setup.sh | (none) | (none) |
| RKSU | rsuntk/KernelSU/main/kernel/setup.sh | `susfs-rksu-master` | `main` |
| KernelSU-Next | rifsxd/KernelSU-Next/{BRANCH}/kernel/setup.sh | `dev_susfs` | `next` |

---

## 3. KSU Variant Architecture Matrix

### Hook Architecture

There are two fundamentally different hook models:

**Model A — Direct VFS Patching ("builtin"):**
Kernel source files (fs/read_write.c, fs/stat.c, fs/open.c, etc.) are patched at build time with `extern` declarations and direct function calls. The KSU driver exports matching symbols.

**Model B — Kprobe ("dynamic"):**
Kernel source files are NOT patched. The KSU driver attaches kprobes/kretprobes at runtime to intercept syscalls dynamically. No exported VFS hook symbols needed.

### SUSFS Integration Model

**Model X — External SUSFS:**
SUSFS lives in a separate repo. The GKI patch, susfs.c, susfs.h, susfs_def.h, and KSU integration patch are applied at build time. The KSU driver's supercalls.c is modified by the external patch.

**Model Y — Built-in SUSFS:**
SUSFS is already integrated into the KSU variant's source code. supercalls.c has CMD_SUSFS_* handlers. Kconfig has CONFIG_KSU_SUSFS options. No external KSU integration patch needed.

### Per-Variant Classification

| Variant | Hook Model | SUSFS Model | ksu_init_rc_hook | ksu_handle_vfs_fstat | kprobe count in ksud.c |
|---------|-----------|-------------|------------------|---------------------|----------------------|
| KernelSU-Next | A (VFS patch) | X (external) | Yes | Yes | — (not checked) |
| SukiSU `main` | B (kprobe) | Y (built-in) | **No** | **No** | 25 |
| SukiSU `builtin` | A (VFS patch) | Y (built-in) | **Yes** | **Yes** | 1 |
| ReSukiSU `main` | A+B (hybrid) | Y (built-in) | **Yes** | **Yes** | 22 |
| ReSukiSU `susfs-ksud` | A+B (hybrid) | Y (built-in) | **Yes** | **Yes** | 22 |
| RKSU `susfs-rksu-master` | A (VFS patch) | X (external) | **No** | **No** | 1 |
| MKSU (all branches) | B (kprobe) | **None** | **No** | **No** | depends on KPROBES |

---

## 4. Per-Variant Branch Analysis

### SukiSU-Ultra (ShirkNeko/SukiSU-Ultra)

| Branch | SHA (short) | Purpose | Hook Model | SUSFS |
|--------|-------------|---------|-----------|-------|
| `main` | ad06449c63a1 | Active development | Kprobe (25 refs) | Built-in |
| `builtin` | 7ce0762898f8 | Traditional VFS hook model | VFS patch (1 kprobe ref) | Built-in |
| `crowdin` | 2a5df8c92a61 | Translations only (string XMLs) | N/A | N/A |
| `old` | 97af8532e17b | Stale since 2026-01-30 | — | — |

**Key files unique to `builtin` branch:** ksuinit.c, lsm_hook.c, shim.c, kp_hook.c, kp_hook.h, kp_util.c, kp_util.h, embed_ksud.c, export_symbol.txt

**Key files unique to `main` branch:** ksu.c, syscall_hook_manager.c, syscall_hook_manager.h, tiny_sulog.c, util.c, util.h, manual_su.c, manual_su.h

**`builtin` branch Kconfig confirms SUSFS:** CONFIG_KSU_SUSFS with sub-options for SUS_PATH, SUS_MOUNT, SUS_KSTAT, SPOOF_UNAME, ENABLE_LOG, HIDE_KSU_SUSFS_SYMBOLS, SPOOF_CMDLINE_OR_BOOTCONFIG, OPEN_REDIRECT, SUS_MAP (all default y except SUS_PATH)

**`builtin` branch supercalls.c confirms SUSFS handlers:** CMD_SUSFS_ADD_SUS_PATH, CMD_SUSFS_ADD_SUS_PATH_LOOP, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH, CMD_SUSFS_SET_SDCARD_ROOT_PATH, CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, CMD_SUSFS_ADD_SUS_KSTAT, CMD_SUSFS_UPDATE_SUS_KSTAT, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY

**Workflow currently uses:** `susfs-dev` — **DOES NOT EXIST** in this repo

**CI log evidence:** `SukiSU-Ultra version (Github): v4.1.1-ad06449c@main` — confirming `main` branch was used after `susfs-dev` failed

### ReSukiSU (ReSukiSU/ReSukiSU)

| Branch | SHA (short) | Purpose |
|--------|-------------|---------|
| `main` | 27c41151cfcf | Active development (same SHA as kernel/ifdef-hell) |
| `susfs-ksud` | 690275f60e99 | SUSFS integration branch |
| `Crowdin` | — | Translations |
| `kernel/ifdef-hell` | 27c41151cfcf | Same as main |
| `ksud-post-fs-data` | — | — |

**Both `main` and `susfs-ksud` have:**
- ksu_init_rc_hook (bool, __read_mostly, line 78 of ksud.c)
- ksu_handle_vfs_fstat (line 544 of ksud.c)
- Full SUSFS supercall dispatch in supercalls.c
- CONFIG_KSU_SUSFS Kconfig menu

**Difference between `main` and `susfs-ksud`:**
- supercalls.c: `main` = 1269 lines, `susfs-ksud` = 1199 lines
- `main` has newer allowlist API (do_new_get_allow_list_common with ksu_new_get_allow_list_cmd)
- `susfs-ksud` has older allowlist API (do_get_allow_list with ksu_get_allow_list_cmd)

**Workflow currently uses:** `susfs-ksud`

### RKSU (rsuntk/KernelSU)

| Branch | Purpose |
|--------|---------|
| `main` | Base KernelSU (no SUSFS) |
| `susfs-rksu-master` | SUSFS-enabled build branch |
| `susfs-rksu-test` | Test branch |
| `deprecated/susfs-legacy` | Deprecated |
| `deprecated/susfs-main` | Deprecated |

**`susfs-rksu-master` ksud.c exports:**
- `bool ksu_vfs_read_hook __read_mostly = true` (line 71)
- `bool ksu_execveat_hook __read_mostly = true` (line 72)
- `bool ksu_input_hook __read_mostly = true` (line 73)
- `int ksu_handle_vfs_read(file, buf, count, NULL)` (line 372)
- `int ksu_handle_sys_read(fd, buf_ptr, count_ptr)` (line 465)
- `int ksu_handle_input_handle_event(type, code, value)` (line 484)
- `int ksu_handle_execveat_ksud(fd, filename_ptr, ...)` (line 206)

**NOT present anywhere in RKSU:**
- `ksu_init_rc_hook` — GKI patch uses this as boot-phase guard
- `ksu_handle_vfs_fstat` — GKI patch calls this for fstat spoofing
- `ksu_handle_sys_newfstatat` — already stubbed by workflow

**CI log evidence:** `KernelSU branch: "susfs-rksu-master"`, `KSU-SusFS version: v2.0.0`

---

## 5. GKI Patch Symbol Requirements

The GKI patch (`50_add_susfs_in_gki-android12-5.10.patch`) adds extern declarations and function calls in kernel VFS files. These symbols must be provided by the KSU driver.

### KSU-provided symbols referenced by GKI patch

| Symbol | Type | Referenced in | Patch line |
|--------|------|--------------|------------|
| `ksu_init_rc_hook` | `bool __read_mostly` | fs/read_write.c, fs/stat.c | 1296, 1623 |
| `ksu_handle_vfs_fstat` | `void (int fd, loff_t *kstat_size_ptr)` | fs/stat.c | 1624, 1636 |
| `ksu_su_compat_enabled` | bool | fs/open.c, fs/stat.c | multiple |
| `ksu_handle_devpts` | `int (struct inode*)` | fs/devpts/inode.c | — |
| `ksu_input_hook` | `bool __read_mostly` | drivers/input/input.c | 11 |
| `ksu_handle_input_handle_event` | `int (uint*, uint*, int*)` | drivers/input/input.c | 13 |

### SUSFS-provided symbols referenced by GKI patch

| Symbol | Referenced in |
|--------|--------------|
| `susfs_is_current_proc_umounted()` | fs/open.c, fs/exec.c, fs/devpts/inode.c, fs/stat.c, fs/readdir.c |
| `susfs_is_inode_sus_path()` | fs/namei.c, fs/readdir.c |
| `susfs_is_current_ksu_domain()` | fs/proc_namespace.c |

### Symbols added by enhancement scripts (not in base GKI patch)

| Symbol | Added by | Referenced in |
|--------|----------|--------------|
| `susfs_is_hidden_ino()` | fix-susfs-perf.sh | fs/readdir.c |
| `susfs_is_hidden_name()` | fix-susfs-perf.sh | fs/readdir.c |
| `susfs_should_hide_dirent()` | fix-susfs-perf.sh | fs/readdir.c (inline) |
| `susfs_check_unicode_bypass()` | patch-kernel-sources.sh | fs/namei.c, fs/open.c, fs/stat.c |
| `susfs_get_redirected_path_all()` | patch-kernel-sources.sh | fs/namei.c |
| `susfs_is_uid_zeromount_excluded()` | patch-kernel-sources.sh | fs/proc_namespace.c |

---

## 6. Failure Root Cause Analysis

### 6a. RKSU Build Failure

**CI Run:** 22406734629
**Error location:** Linker stage (ld.lld)

```
ld.lld: error: undefined symbol: ksu_init_rc_hook
>>> referenced by read_write.c:650 (fs/read_write.c:650)
>>>               vmlinux.o:(__arm64_sys_read)
>>> referenced by stat.c:189 (fs/stat.c:189)
>>>               vmlinux.o:(vfs_fstat)

ld.lld: error: undefined symbol: ksu_handle_vfs_fstat
>>> referenced by stat.c:190 (fs/stat.c:190)
>>>               vmlinux.o:(vfs_fstat)
```

**Root cause:** The GKI patch inserts `extern bool ksu_init_rc_hook` and `extern void ksu_handle_vfs_fstat()` into kernel VFS files. RKSU's `susfs-rksu-master` branch does not define these symbols. It uses different names (`ksu_vfs_read_hook`) and lacks fstat hooking entirely. The workflow's compat step (gki-build.yml:224) only stubs `ksu_handle_sys_newfstatat`, not these two.

**Existing compat mechanism:** Line 229 of gki-build.yml adds a `ksu_handle_sys_newfstatat` stub via awk into ksud.c. The same approach could add the missing symbols.

### 6b. SukiSU Build Failure

**CI Run:** 22406715661
**Error location:** Compile stage (clang)

```
fs/open.c:455:6: error: implicit declaration of function 'susfs_is_current_proc_umounted'
fs/open.c:465:9: error: implicit declaration of function 'susfs_is_hidden_name'
```

Additional error in log:
```
error: pathspec 'susfs-dev' did not match any file(s) known to git
clang-12: error: unable to execute command: Executable "ld" doesn't exist!
```

**Root cause chain:**
1. Workflow sets `BRANCH="susfs-dev"` for SukiSU (gki-build.yml:188)
2. SukiSU-Ultra has no `susfs-dev` branch (only: main, builtin, crowdin, old)
3. setup.sh fails to checkout `susfs-dev`, falls back to `main`
4. `main` branch uses kprobe architecture — does not export VFS hook symbols
5. External SUSFS patches are applied on top, adding calls to `susfs_is_current_proc_umounted()` in fs/open.c
6. The function declaration is not found because the header inclusion or function prototype is missing/mismatched for the kprobe-based `main` branch context
7. Compile fails on implicit declaration

**CI log confirmation:** `SukiSU-Ultra version (Github): v4.1.1-ad06449c@main` — proving `main` was used, not `builtin`

### 6c. ReSukiSU Runtime Failure

**Build result:** Successful compilation and linking
**Runtime result:** Detections triggered, device instability

**Root cause (inferred):** Double-patching of SUSFS. ReSukiSU's `susfs-ksud` branch already has:
- Full SUSFS supercall dispatch in supercalls.c (CMD_SUSFS_* handlers)
- SUSFS Kconfig menu (CONFIG_KSU_SUSFS with all sub-options)
- Built-in SUSFS function implementations

The workflow then:
1. Clones external SUSFS repo
2. Runs fix-susfs.sh (modifies external SUSFS sources with rewrites of functions like susfs_update_sus_kstat, susfs_get_redirected_path, etc.)
3. Runs inject-susfs-features.sh (adds kstat_redirect, open_redirect_all, unicode_filter, etc.)
4. Copies modified external susfs.c/susfs.h/susfs_def.h over the kernel tree (potentially conflicting with what the built-in version expects)
5. Applies GKI patch (adds VFS hooks that call SUSFS functions)
6. Runs patch-kernel-sources.sh which patches supercalls.c (already has built-in handlers)
7. Runs patch-config.sh which patches Kconfig (already has SUSFS options)

This results in potentially mismatched SUSFS source code, duplicate supercall handlers, and conflicting Kconfig entries.

---

## 7. Enhancement Scripts Inventory

### Scripts in `android12-5.10/susfs/`

| Script | Purpose | Modifies |
|--------|---------|----------|
| `fix-susfs.sh` | Safety/correctness fixes to upstream SUSFS source + KSU integration fixes | susfs.c, susfs.h, KSU ksud.c/setuid_hook.c/sucompat.c |
| `inject-susfs-features.sh` | Adds custom features not in upstream SUSFS | susfs.c, susfs.h, susfs_def.h, KSU integration patch |
| `fix-susfs-perf.sh` | Performance patches (readdir rewrite, hidden-ino/name hash tables, parent flag) | GKI patch file (before apply), susfs.c, susfs_def.h |

### Scripts in `android12-5.10/kernel-hooks/`

| Script | Purpose | Modifies |
|--------|---------|----------|
| `patch-kernel-sources.sh` | Patches kernel C sources post-GKI-patch (supercall handlers, zeromount display, VFS redirect, unicode filter) | supercalls.c, proc_namespace.c, namei.c, open.c, stat.c |
| `patch-config.sh` | Patches Kconfig and defconfig for SUSFS features | Kconfig, gki_defconfig |
| `patch-fdinfo-compat.sh` | Cross-sublevel compat for fdinfo.c | fs/proc/fdinfo.c |

### Compatibility with built-in SUSFS variants

| Script | KernelSU-Next (external SUSFS) | SukiSU/ReSukiSU (built-in SUSFS) |
|--------|-------------------------------|----------------------------------|
| fix-susfs.sh | Compatible (designed for this) | **HARMFUL** — rewrites functions that may differ in built-in version |
| inject-susfs-features.sh | Compatible | **PARTIALLY USEFUL** — features may be new, but injection targets may differ |
| fix-susfs-perf.sh | Compatible | **NEEDS ANALYSIS** — Phase A modifies GKI patch, Phase B modifies susfs.c |
| patch-kernel-sources.sh | Compatible | **PARTIALLY HARMFUL** — supercalls.c already has handlers |
| patch-config.sh | Compatible | **PARTIALLY HARMFUL** — Kconfig already has options |
| patch-fdinfo-compat.sh | Compatible | Likely compatible (kernel-side, not KSU-side) |

---

## 8. Built-in SUSFS Feature Inventory

### Verified SUSFS Kconfig options in built-in variants

Checked in both SukiSU-Ultra `builtin` and ReSukiSU `susfs-ksud`:

| Config Option | SukiSU `builtin` | ReSukiSU `susfs-ksud` |
|--------------|-------------------|----------------------|
| CONFIG_KSU_SUSFS | Yes | Yes |
| CONFIG_KSU_SUSFS_SUS_PATH | Yes (default y) | Yes (default n) |
| CONFIG_KSU_SUSFS_SUS_MOUNT | Yes | Yes |
| CONFIG_KSU_SUSFS_SUS_KSTAT | Yes | Yes |
| CONFIG_KSU_SUSFS_SPOOF_UNAME | Yes | Yes |
| CONFIG_KSU_SUSFS_ENABLE_LOG | Yes | Yes |
| CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS | Yes | Yes |
| CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG | Yes | Yes |
| CONFIG_KSU_SUSFS_OPEN_REDIRECT | Yes | Yes |
| CONFIG_KSU_SUSFS_SUS_MAP | Yes | Yes |

### Features added by enhancement scripts (NOT in built-in SUSFS)

| Feature | Config/CMD | Added by |
|---------|-----------|----------|
| kstat redirect | CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT, struct st_susfs_sus_kstat_redirect | inject-susfs-features.sh |
| open redirect all UIDs | CMD_SUSFS_ADD_OPEN_REDIRECT_ALL, AS_FLAGS_OPEN_REDIRECT_ALL | inject-susfs-features.sh |
| Unicode filter | CONFIG_KSU_SUSFS_UNICODE_FILTER, susfs_check_unicode_bypass() | inject-susfs-features.sh + patch-kernel-sources.sh |
| ZeroMount coupling | susfs_is_uid_zeromount_excluded(), zeromount_is_uid_blocked() extern | inject-susfs-features.sh + patch-kernel-sources.sh |
| BUILD_BUG_ON guards | Compile-time bit collision checks | inject-susfs-features.sh |
| Hidden-ino hash table | susfs_is_hidden_ino(), replaces ilookup in readdir | fix-susfs-perf.sh |
| Hidden-name hash table | susfs_is_hidden_name(), FUSE inode recycling fallback | fix-susfs-perf.sh |
| Parent directory flag | AS_FLAGS_SUS_PATH_PARENT | fix-susfs-perf.sh |
| Inline readdir fast-path | susfs_should_hide_dirent() | fix-susfs-perf.sh |
| Zeromount kallsyms hiding | Extends kallsyms filter | fix-susfs-perf.sh |

### Verified: Enhancement features NOT present in built-in SUSFS

Neither SukiSU-Ultra `builtin` nor ReSukiSU `susfs-ksud` ship susfs.c, susfs.h, or susfs_def.h. These come from the external susfs4ksu repo for ALL variants. The "built-in" part is only the KSU-side wiring (supercalls.c dispatch, ksud.c hooks, setuid_hook.c, selinux SIDs). Enhancement features listed above are injected into the external SUSFS sources before copying, so they apply identically across variants.

### Verified: fix-susfs.sh Phase 2 Compatibility Matrix

| Fix | Target | SukiSU `builtin` | ReSukiSU `susfs-ksud` |
|-----|--------|-------------------|----------------------|
| 1: off-by-one `uid < 19999` | setuid_hook.c | MATCH (L45) | NO MATCH — uses `is_zygote()` |
| 2: early-boot `susfs_zygote_sid` guard | setuid_hook.c | MATCH (L116) | NO MATCH — no `susfs_zygote_sid` |
| 3: remove `ksu_handle_execveat_init` call | ksud.c | No-op (absent) | No-op (absent) |
| 4: remove orphaned extern decl | ksud.c | No-op (absent) | No-op (absent) |
| 5: dead `return 0` in faccessat | sucompat.c | No-op (awk guard correct) | **FALSE POSITIVE** — awk triggers on non-dead returns |
| 6: WRITE_ONCE/READ_ONCE barriers | ksud.c | MATCH | MATCH |

### Verified: supercalls.c Injection Anchors

All four anchors used by `patch-kernel-sources.sh`'s `inject_supercall_handlers` match in both variants:

| Anchor | SukiSU `builtin` | ReSukiSU `susfs-ksud` |
|--------|-------------------|----------------------|
| `CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY` | L1012 | L1003 |
| `#endif.*CONFIG_KSU_SUSFS_SUS_KSTAT` | L1016 | L1007 |
| `CMD_SUSFS_ADD_OPEN_REDIRECT` | L1036 | L1027 |
| `#endif.*CONFIG_KSU_SUSFS_OPEN_REDIRECT` | L1040 | L1031 |

Both variants have identical 17 CMD_SUSFS_* command sets. Divergence is in surrounding KSU core code (tracepoint vs kprobe, sulog, dynamic_manager), not in SUSFS handlers.

---

## 9. Existing Compat Mechanisms in Workflow

### gki-build.yml "Fix KernelSU API Compatibility" step (lines 224-238)

Currently handles:
1. **ksu_handle_sys_newfstatat stub** (line 229): If `ksu_handle_sys_newfstatat` is missing from ksud.c, injects an empty stub after `ksu_handle_vfs_fstat`
2. **RKSU SUSFS API rename** (lines 235-238): Renames `CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS` → `CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS` in supercalls.c

Now handled (this session):
- SukiSU branch mismatch: **FIXED** (`susfs-dev` → `builtin`)
- Variant-aware fix gating: **FIXED** (fix-susfs.sh Phase 2 skips fix 5 for SukiSU/ReSukiSU)

Not handled (deferred):
- `ksu_init_rc_hook` missing in RKSU
- `ksu_handle_vfs_fstat` missing in RKSU

---

## 10. Decision Points — Resolved

### SukiSU-Ultra — RESOLVED
- Branch fixed: `susfs-dev` → `builtin`
- External SUSFS GKI patch IS needed (variant doesn't ship susfs.c/susfs.h/susfs_def.h)
- Enhancement scripts safe: Phase 1 modifies external SUSFS sources (safe), supercall anchors match (safe)
- fix-susfs.sh Phase 2: fixes 1, 2, 6 apply correctly; fix 5 skipped (variant gate)

### ReSukiSU — RESOLVED
- Branch `susfs-ksud` confirmed correct
- Same external SUSFS architecture as SukiSU (needs source files + GKI patch)
- fix-susfs.sh Phase 2: fix 6 applies; fixes 1-4 no-op; fix 5 skipped (variant gate)
- Runtime issues after this fix need device testing to isolate

### RKSU — DEFERRED
- `susfs-rksu-master` uses `ksu_vfs_read_hook` (not `ksu_init_rc_hook`), no `ksu_handle_vfs_fstat`
- Needs proper symbol wiring, not stubs
- Requires cloning RKSU fork and mapping its hook architecture to GKI patch expectations

### MKSU (5ec1cff/KernelSU) — DEFERRED
- Zero SUSFS integration on any branch (main, dev, inlinehook, syscallhook, lkm, etc.)
- No `ksu_init_rc_hook`, no `CMD_SUSFS`, no `CONFIG_KSU_SUSFS` across all branches
- All branches are pure kprobe-based (depend on `CONFIG_KPROBES`)
- No `susfs-dev` branch exists — the workflow reference was always broken
- Same category as RKSU: needs the `10_enable_susfs_for_ksu.patch` applied, which the workflow doesn't do
- Branches: main, dev, inlinehook (inline_hook.c + trampoline.S), syscallhook (pte.c), lkm, bootimg, debug, allowshell, avd, old_mksu, rebase

---

## Appendix: Raw Evidence

### CI URLs
- Workflow dashboard: https://github.com/Enginex0/Super-Builders/actions/workflows/kernel-custom.yml
- RKSU failure: `gh run view 22406734629 --repo Enginex0/Super-Builders`
- SukiSU failure: `gh run view 22406715661 --repo Enginex0/Super-Builders`
- Successful run (between the two failures): `gh run view 22406726337 --repo Enginex0/Super-Builders`

### GitHub Actions Workflow Files

All in `.github/workflows/`:

| File | Role |
|------|------|
| kernel-custom.yml | Entry point — workflow_dispatch with device/variant selection |
| gki-build.yml | Reusable build workflow (984 lines) — all patch/build logic |
| cache-dependencies.yml | Toolchain + kernel source caching |
| kernel-a12-5.10.yml | Scheduled/matrix build for android12-5.10 |
| kernel-a13-5.10.yml | Scheduled/matrix build for android13-5.10 |
| kernel-a13-5.15.yml | Scheduled/matrix build for android13-5.15 |
| kernel-a14-5.15.yml | Scheduled/matrix build for android14-5.15 |
| kernel-a14-6.1.yml | Scheduled/matrix build for android14-6.1 |
| kernel-a15-6.6.yml | Scheduled/matrix build for android15-6.6 |
| kernel-a16-6.12.yml | Scheduled/matrix build for android16-6.12 |
| main.yml | Top-level orchestrator |

### Repository URLs

**KSU Variants:**
- KernelSU-Next: https://github.com/rifsxd/KernelSU-Next
- SukiSU-Ultra: https://github.com/ShirkNeko/SukiSU-Ultra
- ReSukiSU: https://github.com/ReSukiSU/ReSukiSU
- RKSU: https://github.com/rsuntk/KernelSU
- MKSU: https://github.com/5ec1cff/KernelSU
- WKSU: https://github.com/WildKernels/Wild_KSU

**SUSFS:**
- Upstream: https://gitlab.com/simonpunk/susfs4ksu
- Fork: https://github.com/Enginex0/susfs4ksu

**Build repo:**
- Super-Builders: https://github.com/Enginex0/Super-Builders

### Setup.sh URLs per Variant (from gki-build.yml:185-212)

| Variant | setup.sh URL | SUSFS branch arg |
|---------|-------------|-----------------|
| SukiSU | `https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh` | `susfs-dev` (BROKEN — branch doesn't exist) |
| MKSU | `https://raw.githubusercontent.com/5ec1cff/KernelSU/main/kernel/setup.sh` | `susfs-dev` |
| ReSukiSU | `https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh` | `susfs-ksud` |
| WKSU | `https://raw.githubusercontent.com/WildKernels/Wild_KSU/stable/kernel/setup.sh` | (no SUSFS branch) |
| RKSU | `https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh` | `susfs-rksu-master` |
| KernelSU-Next | `https://raw.githubusercontent.com/rifsxd/KernelSU-Next/${BRANCH}/kernel/setup.sh` | `dev_susfs` |

### Local Paths Referenced

**Kernel test environment:**
- Kernel source: `/home/claudetest/gki-build/kernel-test/android12-5.10-2024-05/`
- Kernel common tree: `/home/claudetest/gki-build/kernel-test/android12-5.10-2024-05/common/`
- SUSFS patches repo: `/home/claudetest/gki-build/kernel-test/susfs4ksu-510/`
- SUSFS GKI patch: `/home/claudetest/gki-build/kernel-test/susfs4ksu-510/kernel_patches/50_add_susfs_in_gki-android12-5.10.patch`
- SUSFS kernel patches dir: `/home/claudetest/gki-build/kernel-test/susfs4ksu-510/kernel_patches/`

**Build repo (version-specific dir):**
- Root: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/`
- SUSFS scripts: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/susfs/`
- Kernel hooks: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/kernel-hooks/`
- ZeroMount: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/zeromount/`
- Defconfig fragment: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/defconfig.fragment`
- SUSFS pin file: `/mnt/external/claudetest-gki-build/Super-Builders/android12-5.10/susfs-pin.txt`

**CI runner paths (from build logs):**
- Kernel root on runner: `/home/runner/work/Super-Builders/Super-Builders/android12-5.10-209/`
- Kernel common on runner: `/home/runner/work/Super-Builders/Super-Builders/android12-5.10-209/common/`
- Defconfig on runner: `/home/runner/work/Super-Builders/Super-Builders/android12-5.10-209/common/arch/arm64/configs/gki_defconfig`

### Kernel Source Files Modified by GKI Patch + Scripts

| File | Modified by |
|------|------------|
| `fs/read_write.c` | GKI patch (ksu_init_rc_hook extern + guard) |
| `fs/stat.c` | GKI patch (ksu_init_rc_hook + ksu_handle_vfs_fstat) + patch-kernel-sources.sh (unicode) |
| `fs/open.c` | GKI patch (susfs_is_current_proc_umounted) + patch-kernel-sources.sh (unicode) |
| `fs/exec.c` | GKI patch |
| `fs/namei.c` | GKI patch + patch-kernel-sources.sh (open_redirect_all + unicode) |
| `fs/readdir.c` | GKI patch + fix-susfs-perf.sh (hidden-ino/name rewrite) |
| `fs/proc_namespace.c` | GKI patch + patch-kernel-sources.sh (zeromount display) |
| `fs/devpts/inode.c` | GKI patch |
| `fs/proc/task_mmu.c` | GKI patch |
| `drivers/input/input.c` | GKI patch (ksu_input_hook) |
| `fs/Makefile` | GKI patch (adds susfs.o) |
