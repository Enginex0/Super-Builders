#!/bin/bash
# Colonel Kernel Build Wrapper
# Uses Clang 17 + Kotoamatsukami passes to flatten code
# Defeats scanners while preserving KMI
#
# FLAGS = Logic | C/H Files = Movement | DISC = Proof | PATCH = Seal
#
# Usage:
#   export CC=path/to/build_kernel.sh
#   make O=out ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- ...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTO_DIR="$SCRIPT_DIR"
CLANG17="${CLANG17:-clang-17}"
OPT17="${OPT17:-opt-17}"
KOTO_SO="${KOTO_SO:-$KOTO_DIR/bin/build/Kotoamatsukami.so}"
KOTO_CONFIG="$KOTO_DIR/compiler/Kotoamatsukami.config"
KOTO_WRAPPER="$KOTO_DIR/compiler/clang_wrapper.sh"

OBFUSCATE="${OBFUSCATE:-1}"
OBF_PASSES="${OBF_PASSES:-flatten,bogus-control-flow,substitution,indirect-call}"

# If no source files, just use clang directly
if [[ "$#" -eq 0 ]]; then
    exec $CLANG17 "$@"
fi

# Check if this is a kernel compilation
is_kernel=false
for arg in "$@"; do
    case "$arg" in
        -c|-S|-E) is_kernel=true ;;
    esac
done

if [[ "$is_kernel" == "false" ]]; then
    exec $CLANG17 "$@"
fi

# For kernel builds with obfuscation
if [[ "$OBFUSCATE" == "1" ]]; then
    exec bash "$KOTO_WRAPPER" $OBF_PASSES "$@"
else
    exec $CLANG17 "$@"
fi
