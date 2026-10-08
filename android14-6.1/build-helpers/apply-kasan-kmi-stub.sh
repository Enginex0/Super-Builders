#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree}"
MAKEFILE="$COMMON_TREE/mm/Makefile"
STUB="$COMMON_TREE/mm/kasan_kmi_compat.c"
HW_TAGS="$COMMON_TREE/mm/kasan/hw_tags.c"
KASAN_HEADER="$COMMON_TREE/include/linux/kasan.h"
SLUB_HEADER="$COMMON_TREE/include/linux/slub_def.h"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ENTRY='obj-y += kasan_kmi_compat.o'

for required in "$MAKEFILE" "$HW_TAGS" "$KASAN_HEADER" "$SLUB_HEADER"; do
  [[ -f "$required" ]] || {
    echo "::error::Required kernel source file is missing: $required"
    exit 1
  }
done

[[ "$(grep -cFx 'DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);' "$HW_TAGS" || true)" -eq 1 ]] || {
  echo "::error::Unexpected kasan_flag_enabled definition in mm/kasan/hw_tags.c"
  exit 1
}
[[ "$(grep -cFx 'EXPORT_SYMBOL(kasan_flag_enabled);' "$HW_TAGS" || true)" -eq 1 ]] || {
  echo "::error::Unexpected kasan_flag_enabled export class in mm/kasan/hw_tags.c"
  exit 1
}

# CONFIG_KASAN_HW_TAGS adds a one-byte kasan_cache member to kmem_cache.
# Samsung's DLKMs were built against that layout even though the custom daily
# kernel intentionally disables all KASAN instrumentation.  Retain only the
# inert type and field so both the runtime layout and genksyms CRCs stay stock.
"$PYTHON_BIN" - "$KASAN_HEADER" "$SLUB_HEADER" <<'PY'
from pathlib import Path
import sys

kasan_header = Path(sys.argv[1])
slub_header = Path(sys.argv[2])

kasan_text = kasan_header.read_text()
kasan_marker = "Samsung KMI: retain the HW-tags kasan_cache layout with KASAN off."
if kasan_marker not in kasan_text:
    anchor = "#else /* CONFIG_KASAN */\n\nstatic inline void kasan_unpoison_range"
    if kasan_text.count(anchor) != 1:
        raise SystemExit("unexpected CONFIG_KASAN fallback anchor in include/linux/kasan.h")
    replacement = """#else /* CONFIG_KASAN */

/* Samsung KMI: retain the HW-tags kasan_cache layout with KASAN off. */
struct kasan_cache {
	bool is_kmalloc;
};

static inline void kasan_unpoison_range"""
    kasan_text = kasan_text.replace(anchor, replacement, 1)
    kasan_header.write_text(kasan_text)

slub_text = slub_header.read_text()
slub_marker = "Samsung KMI: layout only; KASAN instrumentation remains disabled."
if slub_marker not in slub_text:
    anchor = "#ifdef CONFIG_KASAN\n\tstruct kasan_cache kasan_info;\n#endif"
    if slub_text.count(anchor) != 1:
        raise SystemExit("unexpected kasan_info anchor in include/linux/slub_def.h")
    replacement = """/* Samsung KMI: layout only; KASAN instrumentation remains disabled. */
	struct kasan_cache kasan_info;"""
    slub_text = slub_text.replace(anchor, replacement, 1)
    slub_header.write_text(slub_text)
PY

cat > "$STUB" <<'STUB_EOF'
// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/kconfig.h>
#include <linux/static_key.h>

#if !IS_ENABLED(CONFIG_KASAN_HW_TAGS)
DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
EXPORT_SYMBOL(kasan_flag_enabled);
#endif
STUB_EOF

ENTRY_COUNT="$(grep -cFx "$ENTRY" "$MAKEFILE" || true)"
if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  TMP="$(mktemp "$COMMON_TREE/mm/Makefile.kasan-kmi.XXXXXX")"
  trap 'rm -f "$TMP"' EXIT
  awk -v entry="$ENTRY" '
    !inserted && index($0, "obj-$(CONFIG_KASAN)") && index($0, "kasan/") {
      print entry
      inserted = 1
    }
    { print }
    END {
      if (!inserted)
        exit 42
    }
  ' "$MAKEFILE" > "$TMP" || {
    echo "::error::Could not place the always-built KASAN KMI object in mm/Makefile"
    exit 1
  }
  mv "$TMP" "$MAKEFILE"
  trap - EXIT
elif [[ "$ENTRY_COUNT" -ne 1 ]]; then
  echo "::error::Duplicate KASAN KMI object entries in mm/Makefile"
  exit 1
fi

grep -qxF '#if !IS_ENABLED(CONFIG_KASAN_HW_TAGS)' "$STUB"
grep -qxF 'DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);' "$STUB"
grep -qxF 'EXPORT_SYMBOL(kasan_flag_enabled);' "$STUB"
[[ "$(grep -cFx "$ENTRY" "$MAKEFILE" || true)" -eq 1 ]]
grep -qF 'Samsung KMI: retain the HW-tags kasan_cache layout with KASAN off.' "$KASAN_HEADER"
grep -qF 'Samsung KMI: layout only; KASAN instrumentation remains disabled.' "$SLUB_HEADER"
[[ "$(grep -c $'^\tstruct kasan_cache kasan_info;$' "$SLUB_HEADER" || true)" -eq 1 ]]

echo "Installed always-built KASAN-off KMI compatibility stub and SLUB layout:"
echo "  $STUB"
echo "  $ENTRY"
echo "  $KASAN_HEADER"
echo "  $SLUB_HEADER"
