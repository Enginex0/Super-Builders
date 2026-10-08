# ReSukiSU 35187 / SUSFS 2.3.0 / ZeroMount kernel integration

Base: successful [run 36514881342](https://github.com/kaos2310/Super-Builders/actions/runs/36514881342)
at Super-Builders `4d93c4e71993de95309f3975f0ea97da1750422e`.
Target: S928BXXU6ZZI4 / EUX, Android 14 / Linux 6.1.162, full-strict KMI.

Inputs verified on 2026-09-29:

- ReSukiSU `94dd3c93c2053a84fd752df6eb85db99b7d70ab8`: 4487 + 30700 = **35187**.
- SUSFS `24743360ea08d98f6ad72b856851abed8de5854f`: still current
  `gki-android14-6.1` HEAD, version **v2.3.0**.
- User-supplied module reference:
  `ZeroMount-v2.0.216-dev.guard6.12.brene69.susfs230-r1-arm64.zip`,
  SHA-256 `8fb128f3581bc6cf6007811eebc63adc37fc963fbb34abe99871d136c6fece81`.
  The module is a separate build, not part of this kernel artifact.

The ReSukiSU 35184..35187 diff changes the manager and ksud dependencies;
kernel sources and UAPI4 are identical. This exact-pin adapter preserves the
session decision, successful-exec FD installation, credential error handling,
WebView profile behavior and non-root capability inheritance.
The 35184 adapter remains available for its historical source pin.

The UIDGate-v1 consumer policy, Enhanced SUSFS and ZeroMount VFS hooks remain.
The conflicting ZeroMount task_mmu hook remains excluded. OPEN_REDIRECT is
enabled for the module's explicit rules; no redirect is installed automatically.
Its upstream UID schemes remain intact. The package verifier requires all nine
official SUSFS compile-time features, the three Enhanced extensions and UIDGate,
plus unique compiled integration symbols. UIDGate also verifies the config
embedded in the exact Image.

Local validation on 2026-09-29 reconstructed the pinned AOSP/Samsung/SUSFS
fixture and applied Enhanced SUSFS, ZeroMount and this adapter. Extracted
production C passed 257 session, 14 WebView and 205 KSTAT checks and rejected
18 deliberate mutations. All three harnesses compile for AArch64. UIDGate
passed 703 checks with CONFIG enabled and 703 disabled, 26 consumer checks,
negative mutation tests, 31 source scopes and 15 protected functions. These
host/wasm tests use kernel mocks; complete CI and device validation are separate.

## Locked userspace

35187 retains the stale ksuinit libc lock source first found in 35184.
resukisu_35187_lock.py checks this exact commit, the manifests and the
same-commit ksud lock before replacing only the libc record with Git revision
`1a661633f11a261ff9c00b40875ef72f1cbec818`. The package version remains 0.2.189.
Both Cargo builds and pre-build metadata use --locked. Seven exact-source,
mutation, idempotence and unrelated-edit rejection tests passed locally.
CI archives original/effective locks and build identity.

Run apply.py after Enhanced SUSFS/ZeroMount integration; run test.py and
--verify-only after downstream patches. Unknown pins and partial adapters are
rejected, and failed transformations roll back. No device was flashed.
