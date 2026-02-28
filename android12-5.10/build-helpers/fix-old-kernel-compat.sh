#!/bin/bash
# Runs BEFORE patch application — only fix vanilla kernel issues here
# Post-patch fixes (show_pad, etc.) are in each build workflow
set -euo pipefail

KERNEL_COMMON="$1"
SUBLEVEL="$2"

cd "$KERNEL_COMMON" || exit 1
