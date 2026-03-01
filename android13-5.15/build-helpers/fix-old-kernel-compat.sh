#!/bin/bash
# Pre-adapt old android13-5.15 kernel source for patch compatibility
# Called BEFORE applying 50_ patch
#
# Fix 1: glibc 2.38 (sublevel <123) — C99 for-loop syntax

set -euo pipefail

KERNEL_COMMON="$1"
SUBLEVEL="$2"

cd "$KERNEL_COMMON" || exit 1

if [[ "$SUBLEVEL" -lt 123 ]]; then
  echo "Applying glibc 2.38 compatibility fix for sublevel $SUBLEVEL (<123)"

  BTFIDS_MK="tools/bpf/resolve_btfids/Makefile"
  if [[ -f "$BTFIDS_MK" ]]; then
    sed -i 's/\$(Q)\$(MAKE) -C \$(SUBCMD_SRC) OUTPUT=\$(abspath \$(dir \$@))\/ \$(abspath \$@)/$(Q)$(MAKE) -C $(SUBCMD_SRC) EXTRA_CFLAGS="$(CFLAGS)" OUTPUT=$(abspath $(dir $@))\/ $(abspath $@)/' "$BTFIDS_MK" 2>/dev/null || true
  fi

  PARSE_OPTS="tools/lib/subcmd/parse-options.c"
  if [[ -f "$PARSE_OPTS" ]]; then
    sed -i '/char \*buf = NULL;/a\\tint i;' "$PARSE_OPTS" 2>/dev/null || true
    sed -i 's/for (int i = 0; subcommands\[i\]; i++) {/for (i = 0; subcommands[i]; i++) {/' "$PARSE_OPTS" 2>/dev/null || true
    sed -i '/if (subcommands) {/a\\t\tint i;' "$PARSE_OPTS" 2>/dev/null || true
    sed -i 's/for (int i = 0; subcommands\[i\]; i++)/for (i = 0; subcommands[i]; i++)/' "$PARSE_OPTS" 2>/dev/null || true
  fi

  echo "glibc 2.38 compatibility fix complete"
fi
