# ZeroMount compatibility with BakaSU

This adapter is restricted to ZeroMount `c3cb7ffdf749f2441928ec47798615a4c79fab65`
and its pinned Resetprop submodule. It changes two detection expressions:
`module/customize.sh` and `src/detect/susfs.rs` both accept `BAKASU=true`
or `KSU_SUKISU=true`.

BakaSU 35205+ exports the former flag. Without this adapter, ZeroMount's
Rust detector labels a kernel with built-in SUSFS and its userspace binary
as Embedded instead of Enhanced when there is no separate SUSFS module.
The installer flag check controls its status message and does not abort
installation by itself.

The workflow rebuilds the ARM64 Rust binary using the unchanged Cargo.lock.
Packaging preserves the official v2.0.216-dev release's WebUI and auxiliary
ARM64 files; the official archive must have SHA-256
`12f9fde9edde5317b86e3672b4b20981eaa16581d8e736ef781b7a628b1bd30f`.
It checks that the archived installer exactly matches the immutable upstream
source, replaces it and the ARM64 binary, and archives source/test/build receipts.
Other ABI binaries are excluded from this ARM64 module.

The 16 shell and 128 Rust cases exercise both flags independently, false/unset
values, missing kernel support, missing SUSFS binary and external module
presence. Restoring the original legacy-only Rust probe must fail. No device
installation or boot result is inferred from these host tests.
