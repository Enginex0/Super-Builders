# ReSukiSU 35119 – SUSFS Native v2

Native ports of the functional changes in SUSFS `4fc9c18`, `e5b4d28`, and `153f88d`, retaining UAPI 2 and the existing 35119 manager. The kernel patch covers 13 ReSukiSU files plus the separate Linux 6.1 exec patch. Three optional ksud source files are supplied separately.

## Immutable inputs

| Component | Commit |
| --- | --- |
| ReSukiSU 35119 | `f1dd81dc96d7f3f6691e6ac8b50fba9ae8a2f17c` |
| SUSFS v2.3.0 base | `5727f79e3a7175cfb0e1a754fc2ed78eaf866237` |
| WebView profile synchronization | `4fc9c1898ea66f51847cdbc0d1473ea4ef525a70` |
| Scoped su-FD synchronization | `e5b4d2879836cfb8379010a8ebee76c519f5c834` |
| Post-exec installation fix | `153f88df3be2501d2d33364f8fe05247aecb3cef` |
| Port identity | `ReSukiSU-35119-SUSFS-Native-v2` |

The original SUSFS base remains pinned. These are adapted native patches, not a replacement of ReSukiSU's hook manager with the generic official-KernelSU patch.

## Coverage and deliberate adaptations

| Upstream part | Native implementation |
| --- | --- |
| WebView unmount policy in app profiles | UID 1053 reads the standard non-root profile, including global-default and explicit overrides. |
| WebView profile survives package pruning | UID 1053 is preserved alongside the existing default-profile UID. A WebView profile cannot grant root and uses the key `webview_zygote`. |
| Normal zygote and zygote_next | Both consult the same profile; the special UID branch remains because ReSukiSU's `is_appuid()` excludes 1053. zygote_next sets deferred-unmount flags without unmounting init's namespace. |
| Removal of the old WebView feature | Adapted: feature ID 5 remains available to the existing manager. GET reads the effective profile. SET after boot writes a persistent non-root profile. |
| Existing feature file at boot | SET before boot completion updates only the legacy fallback. It never saves or replaces an allowlist that is still loading asynchronously in init. Loaded profiles take precedence. |
| Scoped driver-FD permissions | Existing permission checks plus a private session capability for `GET_WRAPPER_FD` and `DISABLE_ESCAPE_TO_ROOT` only. |
| FD context allocation/free | Equivalent static-cookie identity, also validating file operations; no extra per-FD allocation or release hook required. |
| Separate upstream driver name | Adapted: kernel retains `[ksu_driver]` so unmodified 35119 ksud/manager can find the FD. Logs distinguish `control` and `su-session` roles. |
| UAPI 3 / manager 32620 requirement | Not adopted: all public UAPI files remain unchanged at ReSukiSU UAPI 2. Official KernelSU version numbers do not map to ReSukiSU's version numbers. |
| Wrapper creation in a restricted root-profile domain | Private inode creation uses KSU credentials and restores the caller credentials before publishing the FD and on every error path. |
| Session FD only after successful exec | Retained and tested. Explicit native boolean recognition replaces upstream's overloaded zero return convention. `O_CLOEXEC` closes the FD on the next exec. FD allocation failure does not rewrite a successful exec result. |
| Removed premature setuid installations | No session FD is installed from either native setuid path. Manager control-FD handling remains native. |
| Profile error propagation | Failed `set_cred_ucounts()` propagates its error. An existing escape-disable flag never produces a session capability. |
| Updated SUSFS Kconfig help | PATH, MOUNT, KSTAT, MAP and OPEN_REDIRECT descriptions adapted to the pinned source behavior. Config values are not changed. |
| ksud early FD claim and name recognition | Optional patch: exact names, upstream scoped-name preference, early caching before su argument processing. |
| ksud TTY access under restricted SELinux profiles | Optional patch: EACCES fallback to the wrapper, recheck whether it is a TTY, and close the temporary FD even if dup2 fails. |
| ksud unload scanning | Optional patch: recognize exactly the normal driver, scoped driver and wrapper names. |
| Upstream LSM macro formatting | Not applicable: this ReSukiSU tree has no corresponding `kernel/hook/lsm_hook.h`. |
| Generic trampoline, boot and seccomp scaffolding / patch offsets | Native ReSukiSU paths are retained. Generic structure replacements and patch metadata are not copied. Existing chroot/argv paths are not redesigned by this port. |

The existing manager UI remains usable through feature ID 5; no new pseudo-app screen or replacement manager APK is required for kernel-side WebView profile control. The global fallback defaults to the previous value until an explicit profile is saved. With `CONFIG_KSU_DISABLE_POLICY`, feature ID 5 retains its original global behavior.

## Apply and verify

Start from a fresh checkout of the exact ReSukiSU pin, with the original pinned SUSFS GKI patch already applied to the common tree. Do not layer the combined v2 kernel patch over the v1 kernel patch. A mixed or partial source state is rejected.

```sh
PORT=android14-6.1/build-helpers/su-session
python3 "$PORT/apply.py" --common /kernel/common --ksu /kernel/KernelSU \
  --susfs-commit 5727f79e3a7175cfb0e1a754fc2ed78eaf866237
python3 "$PORT/test.py" --common /kernel/common --ksu /kernel/KernelSU \
  --work-dir /scratch/susfs-native-tests
```

Both patches are prechecked before writing, applications roll back on a write failure, and repeating a fully applied set is safe. `--verify-only` checks the resulting source state. All UAPI files are compared against the pinned commit. The SUSFS commit argument must come from the verified dependency checkout, as it does in the workflow.

To include the optional ksud source changes, pass `--with-ksud` on the initial fresh-source application and on later verification. Alternatively apply `resukisu-35119-ksud-optional.patch` independently to unchanged 35119 userspace sources with `git apply --check` followed by `git apply`.

```sh
python3 "$PORT/test-ksud.py" --ksu /kernel/KernelSU --work-dir /scratch/ksud-tests
```

The kernel workflow does not build or install ksud. The optional patch becomes effective only after a separate Android ksud build and its deployment. It keeps UAPI 2. No userspace binary or manager is changed on the device by this source package.

## Validation and build identity

- 267 assertions on actual su/exec/dispatch/wrapper C functions, 79 WebView assertions, and 45 assertions with app policy disabled: 391 total.
- Nine deliberately broken C variants must fail, including premature FD installation, unrestricted session permissions, boot-time profile overwrite and WebView profile pruning.
- The C harnesses were executed with Clang/WebAssembly on Windows and also compiled as AArch64 objects. Kernel APIs, storage and namespace effects are mocked.
- Thirteen native Rust scenarios on the actual optional ksud functions pass; four broken variants must fail. libc, procfs and driver IOCTL results are mocked. Root-shell early-claim ordering is also checked.
- The existing Enhanced SUSFS KSTAT/ZeroMount dispatcher transformations and idempotent umount transformation are checked against the ported source.
- The reusable workflow input remains named `susfs_su_session`, defaults to false, and is enabled by this branch's strict ZZHL workflow. It now applies the complete native v2 kernel port.
- Artifact names use `-SUSFS-Native-v2`. Packaging checks final `CONFIG_KSU_SUSFS=y`, both exec and WebView bridge markers in Image, and records all three upstream commits and patch/source/Image hashes in `RESUKISU-SU-SESSION.json`.

No complete kernel or Android ksud/APK build, KMI/DLKM verification, SELinux runtime test or device boot test has been performed for native v2. Existing strict build gates remain necessary. Local source tests do not establish flash readiness.

## Sources

- [SUSFS WebView synchronization](https://gitlab.com/simonpunk/susfs4ksu/-/commit/4fc9c1898ea66f51847cdbc0d1473ea4ef525a70)
- [SUSFS scoped-FD synchronization](https://gitlab.com/simonpunk/susfs4ksu/-/commit/e5b4d2879836cfb8379010a8ebee76c519f5c834)
- [SUSFS exec correction](https://gitlab.com/simonpunk/susfs4ksu/-/commit/153f88df3be2501d2d33364f8fe05247aecb3cef)
- [KernelSU WebView app-profile dependency](https://github.com/tiann/KernelSU/commit/3497a56261564ee7fca494e3bfa0fac80118a34d)
- [KernelSU scoped-FD and ksud dependency](https://github.com/tiann/KernelSU/commit/c72f294e09536222d450237e4c1f0271bfe145ff)
