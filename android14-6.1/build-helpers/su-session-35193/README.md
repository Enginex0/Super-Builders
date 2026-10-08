# ReSukiSU 35202 / SUSFS 2.3.0 / ZeroMount kernel integration

Base: successful [run 36781819535](https://github.com/kaos2310/Super-Builders/actions/runs/36781819535)
at Super-Builders `b0fec64478f22c97b9371af745b2da769a7230e5`.
Target: S928BXXU6ZZI4 / EUX, Android 14 / Linux 6.1.162, full-strict KMI.

Source verified on 2026-10-02:

- ReSukiSU `4c5c8cedaf3cecf297f9b529362e529f506e6891`: 4501 + 30700 = **35202**.
- SUSFS remains pinned to `24743360ea08d98f6ad72b856851abed8de5854f`, **v2.3.0**.
- The four commits after 35189 change CI, manager dependencies and the ksud
  cc lock from 1.4.7 to 1.5.1. The kernel, UAPI and ksuinit source trees are
  byte-identical to 35189. This adapter keeps the baseline transformations and
  tests, while requiring the exact 35202 source and compiled version.

The build retains OPEN_REDIRECT, Enhanced SUSFS, ZeroMount, UIDGate-v1,
Gunyah reclaim, the bootconfig static-key fix and strict Samsung DLKM CRC gates.
The historical 35189 adapter remains available for its source pin.

35202 retains the stale ksuinit libc lock record. `resukisu_35202_lock.py`
requires the exact commit, manifests and same-commit ksud lock, and replaces
only that record with Git libc `1a661633f11a261ff9c00b40875ef72f1cbec818`.
The repaired package record follows ksud at libc 0.2.190. Both Android dependency graphs and builds
use `--locked`; CI archives the original and effective locks and build identity.

Run `apply.py` after Enhanced SUSFS/ZeroMount integration, then `test.py` and
`--verify-only` after downstream patches. The inherited exact-C fault tests,
negative controls and packaged Image attestations remain mandatory in CI.
These tests use kernel API mocks; device validation is separate.
