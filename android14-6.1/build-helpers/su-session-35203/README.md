# ReSukiSU 35203 / UAPI5 / SUSFS 2.3.0 / ZeroMount integration

Base: successful [run 37153808537](https://github.com/kaos2310/Super-Builders/actions/runs/37153808537)
at Super-Builders `3d6a8eb0b76d234b65b191e8f7aa0b6727bd7df3` (ReSukiSU 35202).
Target: S928BXXU6ZZI4 / EUX, Android 14 / Linux 6.1.162, full-strict KMI.

Source verified on 2026-10-04:

- ReSukiSU `8770c7e324a22895703c4916b8a16520e0b81c79`: 4503 + 30700 = **35203**.
- SUSFS remains pinned to `24743360ea08d98f6ad72b856851abed8de5854f`, **v2.3.0**.
- Kernel and ARM64 ksud/ksuinit are rebuilt from the same immutable commit.
- The matching 35203 Manager is supplied by the user.

The upstream commit changes `kernel/supercall/dispatch.c`, `uapi/supercall.h`,
`userspace/ksud/src/android/init_event.rs` and `ksucalls.rs`. UAPI rises to 5,
and EVENT_SERVICES returns 1 for the first service stage and 0 for duplicates.
EVENT_POST_FS_DATA resets the service state for an emulated soft reboot.
The existing scoped su-session ABI and adapter transformation anchors remain
unchanged. This adapter requires UAPI5 and preserves upstream service handling.

The build retains OPEN_REDIRECT, Enhanced SUSFS, ZeroMount, UIDGate-v1,
Gunyah reclaim, the bootconfig static-key fix, LTO and strict Samsung DLKM CRC gates.
The historical 35189 adapter remains available for its source pin.

35203 retains the stale ksuinit libc lock record. `resukisu_35203_lock.py`
requires the exact commit, manifests and same-commit ksud lock, and replaces
only that record with Git libc `1a661633f11a261ff9c00b40875ef72f1cbec818`.
The repaired package record follows ksud at libc 0.2.190. Both Android dependency graphs and builds
use `--locked`; CI archives the original and effective locks and build identity.
The userspace workflow requires fresh target directories and records UAPI source
hashes plus the newly generated Rust bindings with UAPI=5 and EVENT_SERVICES=4.
The bindings path comes from the recorded Cargo `build-script-executed.out_dir`
for the local ksud package; no private Cargo directory layout is assumed.
The Cargo build messages are included in the artifact checksum manifest.
The bindings check accepts whitespace around Rust punctuation, including
bindgen's unformatted token stream (`KERNEL_SU_UAPI_VERSION : __u32 = 5 ;`).
The checked-in fixture preserves actual bindgen 0.73.2 / Libclang 18.1.1 output
from this source pin; altered UAPI4 and service-event values must still fail.
`cargo-ndk 4.1.2` consumes build-script and build-finished messages instead of
forwarding them. `capture-resukisu-cargo.py` records the raw Cargo subprocess
stdout before that filter, while forwarding the same bytes to cargo-ndk and
preserving stderr, arguments, NDK environment and the build exit status.
The installed cargo-ndk binary is invoked by its absolute path, resolved with
`command -v cargo-ndk`, with `ndk` as its first argument. The Cargo subcommand
launcher overwrites `CARGO`; a bare direct invocation also fails because
cargo-ndk 4.1.2 canonicalizes argv[0] to locate its linker binary.
The real subprocess remains the selected Nightly Cargo. Only its build stream
is recorded; metadata invocations are passed through without recording, and
exclusive file creation rejects a stale receipt or a second build invocation.
CI smoke-tests this boundary using its installed cargo-ndk 4.1.2, real Cargo
metadata and a stub build stream before compiling ARM64 ksud or ksuinit. The
bare invocation must reproduce the canonicalization failure, while the
absolute invocation must capture the complete successful build stream.

Run `apply.py` after Enhanced SUSFS/ZeroMount integration, then `test.py` and
`--verify-only` after downstream patches. The inherited exact-C fault tests,
negative controls and packaged Image attestations remain mandatory in CI.
`resukisu_35203_uapi.py` also tests the actual upstream `do_report_event` C with
SUSFS enabled and disabled: start once, skip duplicates, copy errors, unrelated
events and repeated post-fs-data resets. Six deliberate mutations must fail.
The service function is checked again before packaging. Both service log strings
and the service-test receipt are required in the packaged artifact.

Host tests use kernel API mocks. Concurrent requests and Samsung One UI 9 init
ordering remain unverified. Device checks require the exact resulting Image:

1. Keep a recoverable boot.img and first boot without modules.
2. Use the matching 35203 Manager and check `ksud debug info` for `uapi_version: 5`.
3. Confirm one service-stage execution, duplicate skip logging, and a fresh
   single execution after emulated soft reboot.
4. Enable ZeroMount, Zygisk Next, LSPosed and SUSFS individually and verify their
   mounts, daemons and service.sh scripts.
5. Test Manager cold starts, process recreation, module WebUIs, normal and XZ
   module ZIPs, free cache space and temporary-file cleanup.

The requested CI run is started after local checks. No live monitoring or
debugging follows its launch.
