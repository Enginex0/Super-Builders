#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common tree}"
SOURCE="$COMMON_TREE/fs/susfs.c"

[[ -f "$SOURCE" ]] || {
  echo "::error::SUSFS implementation is unavailable: $SOURCE"
  exit 1
}

python3 - "$SOURCE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

declaration = re.compile(
    r"^(?P<indent>[ \t]*)DEFINE_STATIC_KEY_(?P<state>TRUE|FALSE)"
    r"\([ \t]*susfs_is_log_enabled[ \t]*\)[ \t]*;[ \t]*$",
    re.MULTILINE,
)
matches = list(declaration.finditer(text))
if len(matches) != 1:
    raise SystemExit(
        "Expected exactly one susfs_is_log_enabled static-key declaration, "
        f"found {len(matches)}"
    )

match = matches[0]
replacement = (
    f"{match.group('indent')}DEFINE_STATIC_KEY_FALSE(susfs_is_log_enabled);"
)
text = text[: match.start()] + replacement + text[match.end() :]

mutex_declaration = "static DEFINE_MUTEX(susfs_mutex_enable_log);"
if mutex_declaration not in text:
    text = text.replace(replacement, replacement + "\n" + mutex_declaration, 1)

enable_guard = "if (!static_key_enabled(&susfs_is_log_enabled))"
disable_guard = "if (static_key_enabled(&susfs_is_log_enabled))"
already_guarded = text.count(enable_guard) == 1 and text.count(disable_guard) == 1

enable = re.compile(
    r"^(?P<indent>[ \t]*)static_branch_enable"
    r"\(&susfs_is_log_enabled\);[ \t]*$",
    re.MULTILINE,
)
disable = re.compile(
    r"^(?P<indent>[ \t]*)static_branch_disable"
    r"\(&susfs_is_log_enabled\);[ \t]*$",
    re.MULTILINE,
)

if not already_guarded:
    enable_matches = list(enable.finditer(text))
    disable_matches = list(disable.finditer(text))
    if len(enable_matches) != 1 or len(disable_matches) != 1:
        raise SystemExit(
            "Expected one SUSFS logging enable and disable call, found "
            f"{len(enable_matches)} enable / {len(disable_matches)} disable"
        )

    text, enable_count = enable.subn(
        lambda m: (
            f"{m.group('indent')}{enable_guard}\n"
            f"{m.group('indent')}\tstatic_branch_enable(&susfs_is_log_enabled);"
        ),
        text,
        count=1,
    )
    text, disable_count = disable.subn(
        lambda m: (
            f"{m.group('indent')}{disable_guard}\n"
            f"{m.group('indent')}\tstatic_branch_disable(&susfs_is_log_enabled);"
        ),
        text,
        count=1,
    )
    if enable_count != 1 or disable_count != 1:
        raise SystemExit("Failed to guard the SUSFS logging static-key toggles")

function_start = text.find("void susfs_enable_log(void __user **user_info) {")
function_end = text.find("#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG", function_start)
if function_start < 0 or function_end < 0:
    raise SystemExit("SUSFS logging toggle function could not be isolated")
function = text[function_start:function_end]

mutex_lock = "mutex_lock(&susfs_mutex_enable_log);"
mutex_unlock = "mutex_unlock(&susfs_mutex_enable_log);"
if mutex_lock not in function and mutex_unlock not in function:
    if function.count("\tif (info.enabled) {") != 1:
        raise SystemExit("SUSFS logging enabled branch is not unique")
    function = function.replace(
        "\tif (info.enabled) {",
        f"\t{mutex_lock}\n\tif (info.enabled) {{",
        1,
    )
    if function.count("\n\tinfo.err = 0;") != 1:
        raise SystemExit("SUSFS logging success assignment is not unique")
    function = function.replace(
        "\n\tinfo.err = 0;",
        f"\n\t{mutex_unlock}\n\n\tinfo.err = 0;",
        1,
    )
    text = text[:function_start] + function + text[function_end:]

required = (
    "DEFINE_STATIC_KEY_FALSE(susfs_is_log_enabled);",
    mutex_declaration,
    enable_guard,
    disable_guard,
    mutex_lock,
    mutex_unlock,
    "static_branch_enable(&susfs_is_log_enabled);",
    "static_branch_disable(&susfs_is_log_enabled);",
)
missing = [needle for needle in required if text.count(needle) != 1]
if missing:
    raise SystemExit(f"SUSFS logging source audit failed: {missing}")

path.write_text(text, encoding="utf-8")
print("SUSFS logging static key: DEFINE_STATIC_KEY_FALSE")
print("SUSFS runtime logging toggle: balanced enable_log 1 / enable_log 0")
PY

KALLSYMS_HARDENER="$(dirname "$0")/harden-resukisu-zeromount-kallsyms.sh"
[[ -f "$KALLSYMS_HARDENER" ]] || {
  echo "::error::Missing kallsyms hardener: $KALLSYMS_HARDENER"
  exit 1
}
bash "$KALLSYMS_HARDENER" "$COMMON_TREE"
