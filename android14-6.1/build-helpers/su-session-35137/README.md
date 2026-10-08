# ReSukiSU 35137 with SUSFS 2.3.0

This adapter targets ReSukiSU `3380d41f2043644d0ef6c0e0e91be6b229024d00`
and SUSFS `887928223bf685113f32837d5282117c9e4a04ca`, the
`gki-android14-6.1` head checked on 2026-09-12. The version is
`30700 + 4437 = 35137`; the native UAPI version remains 4.

Build base: [34684249719](https://github.com/kaos2310/Super-Builders/actions/runs/34684249719).
Behavior reference: [34262304602](https://github.com/kaos2310/Super-Builders/actions/runs/34262304602).

The latest SUSFS patch introduces a local session boolean and a post-exec
callback in `fs/exec.c`. ReSukiSU also returns zero when falling back to
`/system/bin/sh` because `ksud` is missing. That return code alone cannot identify
a real su session. The adapter retains the upstream success guard, supplies an
explicit boolean only after selecting `KSUD_PATH`, and carries the reference
root-profile error propagation and WebView UID 1053 profile handling forward.
The native UAPI4 definitions, scoped driver implementation and ksud interface
are checked against the immutable upstream source.

ReSukiSU 35137 includes upstream `052ca277`, which adds the task-stack header
for LTO and extends the transient exec flag to SUSFS. The adapter matches that
source, preserves the legacy flag gate for both hook choices, clears the flag
after each attempt, and keeps direct SUSFS installation tied to the local
session boolean and successful exec. ReSukiSU 35137 itself changes only four
SUSFS CLI help descriptions relative to 35136; its kernel, UAPI, manager and
checked-in Cargo lockfiles are identical.

SUSFS `ed8a8328` refactors mount lookup, SUS_KSTAT and OPEN_REDIRECT;
`88792822` additionally separates the mount minor-device ranges. The Samsung
namespace verifier follows the new unmounted-process lookup and clone rules.
The existing Enhanced KSTAT redirect now initializes target device/FUSE identity,
all spoof flags, mount ID and statfs before publishing an entry. Virtual-path
metadata is retained, and failures release references without publishing partial
entries. The upstream ctime-mask comparison typo is corrected to bit 8, matching
ReSukiSU userspace. Public request structures remain unchanged.

The older Enhanced header/open/stat hunks and ZeroMount stat hunk have stale
context after the SUSFS changes. Structural adapters place their declarations
and hooks in the intended functions and preserve upstream KSTAT structures.
The overlapping ZeroMount task_mmu hook remains excluded.

Run `apply.py` after the pinned SUSFS patch, then `test.py` after all downstream
patches. `apply.py --verify-only` never applies the adapter again. Writes are
restored if transformation or verification fails. Unexpected pins, ambiguous
source state and repeated application fail closed.

The C tests extract actual production functions rather than reimplementing
their behavior. They cover exec ordering, missing ksud, credential and allocation
failures, driver descriptor permissions, wrapper cleanup and WebView profiles.
The KSTAT tests also extract the actual upstream statfs/mount-ID lookup functions
and run registration against native and FUSE inode mocks. Seventeen deliberately
broken variants must fail, including lost metadata, reference leaks, a wrong ctime
bit, and stale or unscoped legacy exec flags. Local testing supports WebAssembly
and AArch64 object compilation; CI executes the tests as native Linux binaries.

The final gate checks generated config, Image identity and unique executable
symbols in unstripped vmlinux. The flash ZIP contains the final config,
`RESUKISU-SUSFS-INTEGRATION.json` and `RESUKISU-SUSFS-TESTS.json`.
These are build and mocked control-flow checks. Boot, SELinux behavior and live
SUSFS/ZeroMount module operation require testing this exact Image on the device.

Pre-launch evidence (2026-09-12): 256 session, 14 WebView and 189 KSTAT checks;
17 mutation controls; AArch64 compilation of all three C harnesses; exact-source
patch fixture from AOSP `4bd1b41bff8bb87bed8c3621fa2bb5b2e96f5d8c` plus the
checked-in ZZHL overlay; workflow actionlint. The Windows patch fixture uses
Git apply with reduced context and structural checks; GNU patch and the complete
kernel build are checked by CI. These checks do not establish a successful boot.
