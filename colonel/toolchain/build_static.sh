#!/bin/bash
# colonel/build_static.sh
# Static-link Kotoamatsukami into the kernel build
# 
# FLAGS = Logic | C/H Files = Movement | DISC = Proof | PATCH = Seal
#
# The Clang 17 wrapper flattens and obscures the kernel compilation
# so it looks like normal kernel code to scanners.
# Static linking means no shared library dependencies.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTO_DIR="$SCRIPT_DIR/.."

CLANG17="${CLANG17:-clang-17}"
KOTO_SO="${KOTO_SO:-$KOTO_DIR/bin/build/Kotoamatsukami.so}"
OBFUSCATE="${OBFUSCATE:-1}"
OBF_PASSES="${OBF_PASSES:-flatten,bogus-control-flow,substitution,indirect-call}"

# Verify Clang 17 is available
if ! command -v $CLANG17 >/dev/null 2>&1; then
    echo "ERROR: $CLANG17 not found in PATH" >&2
    echo "Install LLVM 17 and set CLANG17=..." >&2
    exit 1
fi

# Verify Kotoamatsukami plugin
if [[ ! -f "$KOTO_SO" ]]; then
    echo "WARNING: Kotoamatsukami.so not found at $KOTO_SO" >&2
    echo "Build it with:" >&2
    echo "  cd $KOTO_DIR" >&2
    echo "  mkdir -p build && cd build" >&2
    echo "  cmake .. && make -j" >&2
    OBFUSCATE=0
fi

# Create a static-linked wrapper around clang-17
WRAPPER="$KOTO_DIR/compiler/clang_wrapper_static.sh"

if [[ "$OBFUSCATE" == "1" ]]; then
    echo "Colonel: Clang 17 + Kotoamatsukami obfuscation enabled"
    echo "  Passes: $OBF_PASSES"
    exec bash "$WRAPPER" $OBF_PASSES "$@"
else
    echo "Colonel: Clang 17 direct (no obfuscation)"
    exec $CLANG17 "$@"
fi
