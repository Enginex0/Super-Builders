# BakaSU 35215 / UAPI5 / SUSFS 2.3.0 / ZeroMount integration

Base: successful [run 37290796287](https://github.com/kaos2310/Super-Builders/actions/runs/37290796287)
at Super-Builders `c45911e707dc538ade849eaa4c44068f6948e052` (BakaSU 35205).
Target: S928BXXU6ZZI4 / EUX, Android 14 KMI / Linux 6.1.162, full-strict KMI.

Source verified on 2026-10-06:

- BakaSU `1bfed00f597e65700d70fee0feb1d424fc21a2e5`: 4512 + 30700 = **35215**.
- Upstream renamed ReSukiSU to BakaSU and moved to `Baka-SU/BakaSU`.
- Internal Manager namespace is `org.bakasu.bakasu`; the default applicationId
  remains `com.resukisu.resukisu` with the same signing certificate.
- Use the matching BakaSU 35215 Manager. The upstream rename also removes
  MKSU/RKSU/SukiSU-Ultra from the built-in manager certificate list.
- SUSFS remains `24743360ea08d98f6ad72b856851abed8de5854f`, **v2.3.0**.
- Kernel and ARM64 ksud/ksuinit use the same immutable source commit.
- Upstream module scripts now receive `BAKASU=true` in place of `KSU_SUKISU=true`.

UAPI5, EVENT_SERVICES=4, the service start/skip/reset gate and scoped su-session
ABI are unchanged from 35203. The exact-pin adapter retains the explicit session
decision and successful-exec guard, while preserving upstream service handling.
OPEN_REDIRECT, Enhanced SUSFS, ZeroMount, UIDGate-v1, Gunyah reclaim, the
bootconfig static-key fix, LTO and strict Samsung DLKM CRC gates are retained.
The historical 35203 adapter and userspace verifiers remain available.

35215 retains the stale ksuinit libc lock record. `bakasu_35215_lock.py`
requires the exact commit, manifests and same-commit ksud lock, and changes only
that record to Git libc `1a661633f11a261ff9c00b40875ef72f1cbec818`, version 0.2.190.
Upstream's renamed Git dependency URLs and locked revisions remain unchanged.
Both Android dependency graphs and builds use `--locked`; CI archives the
original/effective lockfiles and build identity.

Fresh target directories and Cargo-reported OUT_DIR capture remain mandatory.
`bakasu_35215_uapi.py` checks immutable UAPI sources, generated bindings
(UAPI=5 and EVENT_SERVICES=4), and the real service-event C with six mutation
controls. The actual bindgen 0.73.2 whitespace fixture from 35203 remains valid
because the UAPI headers and bindgen source contract did not change.

Run `apply.py` after Enhanced SUSFS/ZeroMount, then `test.py` and `--verify-only`
after downstream patches. Exact-C fault tests, negative controls and packaged
Image attestations remain mandatory. CI confirms 35215 from source history and
Kbuild, verifies compiled functions, and includes test receipts in AnyKernel3.

Host tests use kernel API mocks. Concurrent requests and physical-device boot
remain unverified. Device checks need this exact Image and the matching BakaSU
Manager, including UAPI5 debug info and single service-stage execution.

The complete upstream kernel and UAPI trees, userspace dependency manifests,
locks and bindgen build source are byte-identical between 35205 and 35215.
The new ksud commits modify APK-comment scanning and config-only boot patch
handling; both binaries are freshly rebuilt from the 35215 pin.
SUSFS gki-android14-6.1 still points to 24743360. ZeroMount upstream master
still points to c3cb7ffdf749f2441928ec47798615a4c79fab65 (v2.0.216-dev).
The existing kernel-side ZeroMount patch is retained. Its statx/readlink order,
dual SUSFS ioctl ABI, disabled legacy task_mmu hook, native UAPI5 scoped
session path and UID-gated consumers are verified against the 35215 port.

The separate ZeroMount module job applies the exact two-site BakaSU flag patch
at c3cb7ff: installer and Rust detection accept `BAKASU=true` or
`KSU_SUKISU=true`. The kernel remains the authoritative SUSFS probe. Without
an external SUSFS module, Enhanced mode still requires the SUSFS userspace
binary; otherwise Embedded/Absent classification is preserved. The job tests
16 shell flag cases and 128 Rust classification cases, rejects a legacy-only
detector mutation, builds Android ARM64 with the pinned Cargo.lock, then packages
the binary and patched installer with the checksum-pinned official WebUI and
auxiliary files. The compatibility ZIP and build identity are separate artifacts.
This addresses the BakaSU classification conflict; no device installation log
was supplied to diagnose an additional installer abort.
