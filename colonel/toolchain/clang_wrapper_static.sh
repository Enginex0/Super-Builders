#!/bin/bash
# Clang 17 Static-Linked Wrapper
# Uses Kotoamatsukami obfuscator passes
# Statically linked plugin (Kotoamatsukami.so)
# Defeats scanners, flattens code, preserves KMI

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTO_DIR="$SCRIPT_DIR/.."

KOTO_SO_DEFAULT="/home/slm015/compiler-node/kits/Kotoamatsukami.so"
KOTO_SO="${KOTO_SO:-$KOTO_SO_DEFAULT}"
CLANG17="${CLANG17:-clang-17}"
OPT17="${OPT17:-opt-17}"

# If the Kotoamatsukami plugin doesn't exist, use clang directly
if [[ ! -f "$KOTO_SO" ]]; then
    KOTO_SO="/usr/local/lib/Kotoamatsukami.so"
fi
if [[ ! -f "$KOTO_SO" ]]; then
    KOTO_SO="$KOTO_DIR/bin/build/Kotoamatsukami.so"
fi

# Parse args - identify source file
source_files=""
output_file=""
koto_passes=""
extra_args=()
in_output=false
in_target=false

for arg in "$@"; do
    case "$arg" in
        *.c|*.cc|*.cpp|*.S|*.s)
            source_files="$arg" ;;
        -o)
            in_output=true ;;
        -target|--target)
            in_target=true ;;
        split-basic-block|anti-debug|gv-encrypt|bogus-control-flow|add-junk-code|loopen|for-obs|branch2call-32|branch2call|indirect-call|indirect-branch|flatten|substitution)
            koto_passes+="$arg," ;;
        *)
            if [[ "$in_output" == "true" ]]; then
                output_file="$arg"
                in_output=false
            elif [[ "$in_target" == "true" ]]; then
                in_target=false
            else
                extra_args+=("$arg")
            fi
            ;;
    esac
done

# If no source file or no passes, just pass through
if [[ -z "$source_files" || -z "$koto_passes" ]]; then
    exec $CLANG17 "$@"
fi

# If Kotoamatsukami.so not found, pass through
if [[ ! -f "$KOTO_SO" ]]; then
    echo "WARNING: Kotoamatsukami.so not found, using clang-17 directly" >&2
    exec $CLANG17 "$@"
fi

# Build the pass string
passes_str="${koto_passes%,}"

# Step 1: clang-17 -emit-llvm -S
ll_file="${source_files%.c}.ll"
$CLANG17 -S -emit-llvm "${extra_args[@]}" "$source_files" -o "$ll_file"

# Step 2: opt-17 with Kotoamatsukami plugin
obfuscated_ll_file="${source_files%.c}.obfuscated.ll"
$OPT17 --load-pass-plugin="$KOTO_SO" "$ll_file" --passes="$passes_str" -S -o "$obfuscated_ll_file"

# Step 3: clang-17 to compile the obfuscated .ll
if [[ -n "$output_file" ]]; then
    $CLANG17 "$obfuscated_ll_file" "${extra_args[@]}" -Wno-unused-command-line-argument -o "$output_file"
else
    $CLANG17 -c "$obfuscated_ll_file" "${extra_args[@]}" -Wno-unused-command-line-argument -o "${source_files%.c}.o"
fi

# Cleanup
if [[ -z "${DEBUG:-}" || "$DEBUG" != "1" ]]; then
    rm -f "$ll_file" "$obfuscated_ll_file"
fi
