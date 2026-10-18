# Cross-References - Colonel Tier

Each repo references the others. When any one is cloned, the others are pulled in.

```
Kernel-1 (orchestrator)
  -> config/default.config references all 4 repos
  -> Clang 17 wrapper: Kotoamatsukami
  -> Build pipeline: Super-Builders
  -> Source: kernel-msm-1
  -> KSU source: KernelSU-Next

Super-Builders (build pipeline)
  -> colonel/ = Tier 3 (this)
  -> colonel/toolchain/build_static.sh = Clang 17 wrapper
  -> android12-5.10/ = build helpers
  -> .github/workflows/build-genevn-nuki.yml = main build
  -> references Kotoamatsukami@llvm-17-plugins
  -> references kernel-msm-1@android-14-release-u1tgns34.42-86-2-32
  -> references Kernel-1@main

Kotoamatsukami (Clang 17 obfuscator)
  -> colonel/ = SProf source lives here too
  -> compiler/clang_wrapper.sh = original wrapper
  -> compiler/clang_wrapper_static.sh = static-link wrapper
  -> references Super-Builders@015stray91

kernel-msm-1 (source)
  -> fs/koto/colonel/ = the actual SProf source
  -> fs/koto/ = KPM + ZeroMount + SUSFS + HybridMount
  -> references Kernel-1@main
  -> references Super-Builders@015stray91
  -> references Kotoamatsukami@llvm-17-plugins
```

## Pre-staged Setup
Before any clone, the toolchains are referenced:
- snapdragon-toolchain (Clang 12 + GCC 7.5) lives at:
  https://github.com/015stray91/android-kernel-tools
- aarch64 cross-compile: gcc-aarch64-linux-gnu (apt package)
- llvm-12 + clang-12: apt packages
- llvm-17 + clang-17: apt packages (for the wrapper)
- cmake + ninja-build: apt packages (for Kotoamatsukami)

When CI runs, it installs all toolchains BEFORE cloning, so everything is ready.
