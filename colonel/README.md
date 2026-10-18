# Colonel Tier - Super-Builders Integration

## Tier 3 in the Super-Builders tiered build system

```
Tier 1: KSU-Next base kernel
Tier 2: SUSFS + ZeroMount + KPM integration
Tier 3: Colonel SProf - VFS environment shaping + Kotoamatsukami obfuscation  <-- THIS
```

## What is Colonel?

Colonel (Snapdragon Profile) is a VFS environment shaping module that:
- Reads real hardware values from Qualcomm EUD (QFPROM/cpufreq)
- Builds spoofed /proc/* content
- Runs natively on the device (no VM, no container)
- Preserves KMI while flattening code patterns

## What is the Kotoamatsukami Wrapper?

The Clang 17 wrapper:
- Uses Clang 17 as a frontend
- Calls Kotoamatsukami obfuscation passes on the LLVM IR
- Re-compiles with Clang 12 (the inner compiler)
- Produces a kernel image that:
  - Flattens code patterns (defeats scanners)
  - Preserves KMI (Kernel Module Interface)
  - Looks like a normal kernel build

## Files in this tier

- `sprof/` - The Colonel SProf source code
- `toolchain/build_static.sh` - Static-link Clang 17 wrapper
- `toolchain/clang_wrapper_static.sh` - Underlying wrapper logic
- `toolchain/TOOLCHAIN.md` - Toolchain documentation
- `../.github/workflows/build-colonel.yml` - CI build workflow
- `../android12-5.10/build-helpers/colonel-tier.sh` - Local build helper

## Quick Start

### CI Build
```yaml
- uses: 015stray91/Super-Builders/.github/workflows/build-colonel.yml@015stray91
  with:
    kernel_branch: android-14-release-u1tgns34.42-86-2-32
    obf_passes: flatten,bogus-control-flow,substitution,indirect-call
```

### Local Build
```bash
# After cloning Super-Builders
git clone --branch 015stray91 https://github.com/015stray91/Super-Builders.git
cd Super-Builders

# Apply all three tiers
./android12-5.10/build-helpers/colonel-tier.sh kernel-source
cd kernel-source
make O=out Image.lz4 modules -j$(nproc)
```
