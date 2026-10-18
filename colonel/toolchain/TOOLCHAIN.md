# Colonel Toolchain - Static-Linked Clang 17

## Overview
Static-linked Clang 17 toolchain that uses Kotoamatsukami obfuscator
to flatten kernel code patterns, defeat scanners, and preserve KMI.

## Architecture
```
FLAGS    = Logic    (kernel config enables capabilities)
C/H FILES = Movement (code implementation)
DISC     = Proof    (testing/validation)
PATCH    = Seal     (integration into kernel)
```

## Static Link
The Kotoamatsukami plugin (`Kotoamatsukami.so`) is statically linked
into the wrapper script, so no shared library dependencies are needed
at compile time.

## Usage

### 1. Build the Kotoamatsukami plugin
```bash
cd /path/to/Kotoamatsukami
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

### 2. Use the wrapper for kernel builds
```bash
export CC=/path/to/colonel/build_static.sh
export CLANG17=clang-17
export OBFUSCATE=1
export OBF_PASSES="flatten,bogus-control-flow,substitution"

# Standard kernel build
make O=out ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
```

### 3. Pass flags
- `OBFUSCATE=0` - disable obfuscation
- `OBF_PASSES="pass1,pass2"` - custom pass list
- `CLANG17=clang-17.0.6` - custom clang-17 path

## Available Kotoamatsukami Passes
- `flatten` - flattens control flow (defeats scanners)
- `bogus-control-flow` - inserts bogus control flow
- `substitution` - replaces instructions with equivalents
- `indirect-call` - inserts indirect function calls
- `indirect-branch` - inserts indirect branches
- `gv-encrypt` - encrypts global variables
- `anti-debug` - inserts anti-debugging techniques
- `add-junk-code` - adds junk code
- `loopen` - loop-based obfuscation
- `for-obs` - for loop based obfuscation
- `branch2call` - converts branches to calls

## KMI Preservation
The wrapper only modifies LLVM IR at the .ll stage, then uses
standard clang-17 compilation. The resulting .o files have
identical KMI to a non-obfuscated build - the symbol table,
sections, and module layout are unchanged.
