#!/bin/bash
# Pre-adapt old android13-5.10 kernel source for SUSFS patch compatibility
# Called BEFORE applying 50_ patch
#
# Fix 1: fdinfo.c (sublevel ≤107) — old inotify API lacks inotify_mark_user_mask()
# Fix 2: glibc 2.38 (sublevel ≤186) — C99 for-loop syntax + __isoc23_strtol

set -euo pipefail

KERNEL_COMMON="$1"
SUBLEVEL="$2"

cd "$KERNEL_COMMON" || exit 1

# --- Fix 1: fdinfo.c old inotify API ---
if [[ "$SUBLEVEL" -le 107 ]]; then
  echo "Applying fdinfo.c pre-adaptation for sublevel $SUBLEVEL (≤107)"
  FDINFO="fs/notify/fdinfo.c"

  # Add inotify_mark_user_mask() — doesn't exist in old kernels
  if ! grep -q 'inotify_mark_user_mask' "$FDINFO"; then
    sed -i '/^static void inotify_fdinfo/i \
static inline u32 inotify_mark_user_mask(struct fsnotify_mark *mark)\
{\
\treturn mark->mask \& IN_ALL_EVENTS;\
}\
' "$FDINFO"
  fi

  # Delete the /* ... */ comment block before u32 mask (inotify section only)
  sed -i '/\t\t\/\*$/,/\t\t \*\/$/d' "$FDINFO"

  # Remove u32 mask variable
  sed -i '/u32 mask = mark->mask & IN_ALL_EVENTS;/d' "$FDINFO"

  # Convert inotify format string (scoped — only matches "inotify wd:" lines)
  sed -i 's/\(seq_printf(m, "inotify wd:%x ino:%lx sdev:%x mask:%x \)ignored_mask:%x "/\1ignored_mask:0 "/' "$FDINFO"

  # Convert inotify args (scoped via inode_mark->wd context, unique to inotify)
  sed -i '/inode_mark->wd/{n;s/^\(\t\t\t   \)mask, mark->ignored_mask);/\1inotify_mark_user_mask(mark));/}' "$FDINFO"

  echo "fdinfo.c pre-adaptation complete"
fi

# --- Fix 2: glibc 2.38 C99 compat ---
if [[ "$SUBLEVEL" -le 186 ]]; then
  echo "Applying glibc 2.38 compatibility fix for sublevel $SUBLEVEL (≤186)"

  # Fix resolve_btfids Makefile — pass EXTRA_CFLAGS to subcmd build
  BTFIDS_MK="tools/bpf/resolve_btfids/Makefile"
  if [[ -f "$BTFIDS_MK" ]]; then
    sed -i 's/\$(Q)\$(MAKE) -C \$(SUBCMD_SRC) OUTPUT=\$(abspath \$(dir \$@))\/ \$(abspath \$@)/$(Q)$(MAKE) -C $(SUBCMD_SRC) EXTRA_CFLAGS="$(CFLAGS)" OUTPUT=$(abspath $(dir $@))\/ $(abspath $@)/' "$BTFIDS_MK" 2>/dev/null || true
  fi

  # Fix C99 for-loop declarations in parse-options.c
  PARSE_OPTS="tools/lib/subcmd/parse-options.c"
  if [[ -f "$PARSE_OPTS" ]]; then
    sed -i '/char \*buf = NULL;/a\\tint i;' "$PARSE_OPTS" 2>/dev/null || true
    sed -i 's/for (int i = 0; subcommands\[i\]; i++) {/for (i = 0; subcommands[i]; i++) {/' "$PARSE_OPTS" 2>/dev/null || true
    sed -i '/if (subcommands) {/a\\t\tint i;' "$PARSE_OPTS" 2>/dev/null || true
    sed -i 's/for (int i = 0; subcommands\[i\]; i++)/for (i = 0; subcommands[i]; i++)/' "$PARSE_OPTS" 2>/dev/null || true
  fi

  echo "glibc 2.38 compatibility fix complete"
fi
