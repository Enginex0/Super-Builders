# ReSukiSU 35184 with latest compatible SUSFS 2.3.0

Build base: [successful run 35443096947](https://github.com/kaos2310/Super-Builders/actions/runs/35443096947),
Super-Builders `4bad7d66a2e43c6ffbcd5046ce209207ec8a590d`.
The target remains S928BXXU6ZZI4 / EUX, Android 14 / Linux 6.1.162,
with the reference full-strict KMI profile, firmware inputs and feature selection.

Immutable inputs checked on 2026-09-28:

- ReSukiSU `fa8311f632a215b5381ec644627c6198d1e8a13e`: 4484 commits + 30700 = **35184**.
- SUSFS `24743360ea08d98f6ad72b856851abed8de5854f`: latest `gki-android14-6.1` revision,
  committed 2026-09-26; its declared version remains **v2.3.0**.

The session adapter carries the reference explicit session decision, successful
exec gate, credential error propagation and WebView UID 1053 handling forward.
The upstream UAPI4 definitions, scoped driver implementation, ksud interface and
non-root capability inheritance are verified. Upstream Cargo manifests and the
ksud lock are retained. The bounded ksuinit lock correction described below is
audited, and CI builds ARM64 ksud and ksuinit with Nightly and `--locked`.
The operation-aware DynamicManager GET fix and upstream ADB-root feature remain.

SUSFS now latches the unshared-mount allocation decision before setting its
ownership flag; the Samsung namespace verifier checks that sequence. The latest
KSTAT request uses `bool is_statically`, matching ReSukiSU's native Rust request.
Enhanced KSTAT redirect uses the new `statfs_by_dentry_wrapper` and
`calculate_f_flags_wrapper`, preserving the visible filesystem's mount flags.
The new upstream fixes for statfs flags, KSTAT cleanup, allocation failures,
OPEN_REDIRECT filename lifetime, and seqlock-protected bootconfig output remain.
The overlapping ZeroMount task_mmu hook stays excluded as in the reference run.

Run `apply.py` after the pinned SUSFS patch, then `test.py` after all downstream
patches. `apply.py --verify-only` checks without applying again. Failed transforms
restore the original bytes; incorrect pins and repeated application are rejected.
CI records both exact source commits, the derived version, final config, Image
hash and required vmlinux symbols in `RESUKISU-SUSFS-INTEGRATION.json`.

Local evidence (2026-09-28): 257 session, 14 WebView and 205 KSTAT checks;
18 rejected mutations, including lost mount flags; AArch64 compilation of all
three extracted C harnesses. The integration fixture applies the exact upstream
patch plus Enhanced SUSFS and ZeroMount to AOSP
`4bd1b41bff8bb87bed8c3621fa2bb5b2e96f5d8c` with the checked-in Samsung overlay.
Windows uses Git apply with reduced context plus structural checks. CI uses
GNU patch and performs the complete kernel build, KMI and packaging gates.
Mocked C checks do not establish a successful kernel build or device boot.

## ksuinit lock correction

Run 36461959250 stopped before compilation because the 35184 ksuinit manifest
patches libc to Git revision `1a661633f11a261ff9c00b40875ef72f1cbec818`, while its
checked-in lock still selects crates.io libc 0.2.189. The ksud lock at the same
ReSukiSU commit already contains the correct Git libc 0.2.189 record.

`resukisu_35184_lock.py` checks the exact source pin and unchanged manifests/ksud
lock, then copies only that libc record into the original ksuinit lock. It does
not regenerate either dependency graph or change any package version. It rejects
unexpected inputs and is idempotent. The verifier accepts only the exact derived
lock, before and after building, and records both original and repaired SHA-256
values. CI retains the original and effective lockfiles in the artifact and runs
`cargo metadata --locked` for both Android dependency graphs before compilation.
Both actual builds continue to require `--locked`.
