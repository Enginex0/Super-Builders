# BakaSU 35205 / UAPI5 / SUSFS 2.3.0 / ZeroMount integration

Base: successful [run 37234964454](https://github.com/kaos2310/Super-Builders/actions/runs/37234964454)
at Super-Builders `1ee20a9318eb238fc28f68c7e5a3ddb124ea1879` (ReSukiSU 35203).
Target: S928BXXU6ZZI4 / EUX, Android 14 KMI / Linux 6.1.162, full-strict KMI.

Source verified on 2026-10-05:

- BakaSU `9dbce02e511ea6b6305a238b84e456f6a92e1d0b`: 4505 + 30700 = **35205**.
- Upstream renamed ReSukiSU to BakaSU and moved to `Baka-SU/BakaSU`.
- Manager package changed from `com.resukisu.resukisu` to `org.bakasu.bakasu`.
- Use the matching BakaSU 35205 Manager. The upstream rename also removes
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

35205 retains the stale ksuinit libc lock record. `resukisu_35205_lock.py`
requires the exact commit, manifests and same-commit ksud lock, and changes only
that record to Git libc `1a661633f11a261ff9c00b40875ef72f1cbec818`, version 0.2.190.
Upstream's renamed Git dependency URLs and locked revisions remain unchanged.
Both Android dependency graphs and builds use `--locked`; CI archives the
original/effective lockfiles and build identity.

Fresh target directories and Cargo-reported OUT_DIR capture remain mandatory.
`resukisu_35205_uapi.py` checks immutable UAPI sources, generated bindings
(UAPI=5 and EVENT_SERVICES=4), and the real service-event C with six mutation
controls. The actual bindgen 0.73.2 whitespace fixture from 35203 remains valid
because the UAPI headers and bindgen source contract did not change.

Run `apply.py` after Enhanced SUSFS/ZeroMount, then `test.py` and `--verify-only`
after downstream patches. Exact-C fault tests, negative controls and packaged
Image attestations remain mandatory. CI confirms 35205 from source history and
Kbuild, verifies compiled functions, and includes test receipts in AnyKernel3.

Host tests use kernel API mocks. Concurrent requests and physical-device boot
remain unverified. Device checks need this exact Image and the matching BakaSU
Manager, including UAPI5 debug info and single service-stage execution.
