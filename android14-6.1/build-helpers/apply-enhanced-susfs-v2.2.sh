#!/bin/bash
set -euo pipefail

COMMON="${1:?kernel common tree is required}"
KSU_ROOT="${2:?KernelSU root is required}"
SOURCE_PATCH="${3:?enhanced SUSFS patch is required}"
SUSFS_VERSION_LABEL="${SUSFS_EXPECTED_VERSION:-pinned}"
WORK_DIR="${RUNNER_TEMP:-/tmp}/susfs-enhanced"
HELPERS="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

[[ -d "$COMMON" ]] || { echo "::error::Kernel common tree is missing: $COMMON"; exit 1; }
[[ -d "$KSU_ROOT" ]] || { echo "::error::KernelSU tree is missing: $KSU_ROOT"; exit 1; }
[[ -s "$SOURCE_PATCH" ]] || { echo "::error::Enhanced SUSFS patch is missing: $SOURCE_PATCH"; exit 1; }
mkdir -p "$WORK_DIR"

extract_matching_hunks() {
  local source_patch="$1"
  local target_path="$2"
  local hunk_pattern="$3"
  local output_patch="$4"

  python3 - "$source_patch" "$target_path" "$hunk_pattern" "$output_patch" <<'PY'
import pathlib
import re
import sys

source, target, expression, output = sys.argv[1:]
lines = pathlib.Path(source).read_text(encoding="utf-8").splitlines(keepends=True)

start = None
for index, line in enumerate(lines):
    if line.startswith("--- ") and re.search(rf"/{re.escape(target)}(?:\t|\r?\n$)", line):
        start = index
        break
if start is None:
    raise SystemExit(f"No patch section found for {target}")

end = len(lines)
for index in range(start + 1, len(lines)):
    if lines[index].startswith("diff "):
        end = index
        break

section = lines[start:end]
first_hunk = next((index for index, line in enumerate(section) if line.startswith("@@")), None)
if first_hunk is None:
    raise SystemExit(f"No hunks found for {target}")

header = section[:first_hunk]
hunks = []
current = []
for line in section[first_hunk:]:
    if line.startswith("@@"):
        if current:
            hunks.append(current)
        current = [line]
    else:
        current.append(line)
if current:
    hunks.append(current)

pattern = re.compile(expression)
selected = [hunk for hunk in hunks if pattern.search("".join(hunk))]
if not selected:
    raise SystemExit(f"No matching hunks for {target}: {expression}")

pathlib.Path(output).write_text(
    "".join(header + [line for hunk in selected for line in hunk]),
    encoding="utf-8",
)
PY
}

apply_required_hunks() {
  local target_path="$1"
  local hunk_pattern="$2"
  local output_patch="$WORK_DIR/$(echo "$target_path" | tr '/' '_').patch"

  extract_matching_hunks "$SOURCE_PATCH" "$target_path" "$hunk_pattern" "$output_patch"

  if patch -d "$COMMON" -p1 -F3 --forward --batch --dry-run < "$output_patch" >/dev/null 2>&1; then
    echo "Applying enhanced SUSFS hooks for ${SUSFS_VERSION_LABEL}: $target_path"
    patch -d "$COMMON" -p1 -F3 --forward --batch --no-backup-if-mismatch < "$output_patch"
    return 0
  fi

  if patch -d "$COMMON" -R -p1 -F3 --forward --batch --dry-run < "$output_patch" >/dev/null 2>&1; then
    echo "Enhanced SUSFS hooks for ${SUSFS_VERSION_LABEL} already present: $target_path"
    return 0
  fi

  echo "::error::Required enhanced SUSFS hunks do not apply cleanly for ${SUSFS_VERSION_LABEL}: $target_path"
  patch -d "$COMMON" -p1 -F3 --forward --batch --dry-run < "$output_patch" || true
  return 1
}

apply_required_hunks 'fs/Kconfig' \
  'KSU_SUSFS_SUS_KSTAT_REDIRECT|KSU_SUSFS_UNICODE_FILTER|KSU_SUSFS_HIDDEN_NAME'
apply_required_hunks 'include/linux/susfs_def.h' \
  'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT'
python3 "$HELPERS/apply-enhanced-susfs-header.py" "$SOURCE_PATCH" "$COMMON/include/linux/susfs.h"
apply_required_hunks 'fs/namei.c' \
  'KSU_SUSFS_UNICODE_FILTER|susfs_check_unicode_bypass'
python3 "$HELPERS/apply-enhanced-susfs-vfs.py" enhanced "$COMMON" "$SOURCE_PATCH"

# fs/susfs.c in the pinned Android 14 / 6.1 tree uses mutexes instead of the
# no longer matches the older enhanced-feature patch context.  GNU patch can
# otherwise accept the legacy hunks with fuzz and place top-level helpers
# inside susfs_run_sus_path_loop(), which only fails much later at compile
# time. Port the feature blocks using fail-closed structural anchors shared by
# the pinned v2.2.0 and v2.3.0 GKI sources.
python3 - "$SOURCE_PATCH" "$COMMON/fs/susfs.c" "$HELPERS/susfs-kstat-redirect-v2.c" <<'PY'
from pathlib import Path
import re
import sys

patch_path, source_path, redirect_v2_path = map(Path, sys.argv[1:])
patch_lines = patch_path.read_text(encoding="utf-8").splitlines(keepends=True)
source = source_path.read_text(encoding="utf-8")


def patch_section(target):
    start = next(
        (
            index
            for index, line in enumerate(patch_lines)
            if line.startswith("--- ")
            and re.search(rf"/{re.escape(target)}(?:\t|\r?\n$)", line)
        ),
        None,
    )
    if start is None:
        raise SystemExit(f"No patch section found for {target}")

    end = next(
        (
            index
            for index in range(start + 1, len(patch_lines))
            if patch_lines[index].startswith("diff ")
        ),
        len(patch_lines),
    )
    section = patch_lines[start:end]
    first_hunk = next(
        (index for index, line in enumerate(section) if line.startswith("@@")),
        None,
    )
    if first_hunk is None:
        raise SystemExit(f"No hunks found for {target}")

    hunks = []
    current = []
    for line in section[first_hunk:]:
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        hunks.append(current)
    return hunks


def added_text_containing(hunks, token):
    matches = [
        "".join(
            line[1:]
            for line in hunk[1:]
            if line.startswith("+") and not line.startswith("+++")
        )
        for hunk in hunks
        if token in "".join(hunk)
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"Expected one fs/susfs.c hunk containing {token!r}, found {len(matches)}"
        )
    return matches[0]


def preprocessor_block(text, marker):
    lines = text.splitlines(keepends=True)
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if marker in line and re.match(r"^\s*#\s*if", line)
        ),
        None,
    )
    if start is None:
        raise SystemExit(f"Cannot find preprocessor block for {marker}")

    depth = 0
    for index in range(start, len(lines)):
        line = lines[index]
        if re.match(r"^\s*#\s*(?:if|ifdef|ifndef)\b", line):
            depth += 1
        elif re.match(r"^\s*#\s*endif\b", line):
            depth -= 1
            if depth == 0:
                return "".join(lines[start : index + 1])
    raise SystemExit(f"Unterminated preprocessor block for {marker}")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected one {label} anchor, found {count}")
    return text.replace(old, new, 1)


markers = (
    "bool susfs_check_unicode_bypass(",
    "struct susfs_hidden_name_entry {",
    "void susfs_add_sus_kstat_redirect(",
    "CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT\\n\", buf_ptr",
)
present = tuple(marker in source for marker in markers)
if all(present):
    print("Enhanced SUSFS source features already present: fs/susfs.c")
    raise SystemExit(0)
if any(present):
    raise SystemExit("Partial enhanced SUSFS source port detected in fs/susfs.c")

hunks = patch_section("fs/susfs.c")

for include in (
    "#include <linux/hashtable.h>\n",
    "#include <linux/pagemap.h>\n",
    "#include <linux/limits.h>\n",
    "#include <linux/spinlock.h>\n",
):
    if include not in source:
        source = replace_once(
            source,
            '#include "mount.h"\n',
            '#include "mount.h"\n' + include,
            "include",
        )

unicode_added = added_text_containing(hunks, "has_suspicious_unicode")
# The Unicode hunk reuses the old log-config #endif as its own closing
# directive, so that final line is patch context rather than an added line.
unicode_added += "#endif\n"
unicode_block = preprocessor_block(
    unicode_added, "CONFIG_KSU_SUSFS_UNICODE_FILTER"
)
source = replace_once(
    source,
    "\n/* sus_path */\n",
    "\n" + unicode_block + "\n\n/* sus_path */\n",
    "sus_path section",
)

hidden_added = added_text_containing(hunks, "struct susfs_hidden_name_entry")
hidden_block = preprocessor_block(hidden_added, "CONFIG_KSU_SUSFS_HIDDEN_NAME")
hidden_lock = "static DEFINE_SPINLOCK(susfs_hidden_inos_lock);\n"
hidden_register = r'''

static void susfs_register_hidden_ino(struct inode *inode)
{
	struct susfs_hidden_ino_entry *entry;
	struct susfs_hidden_ino_entry *existing;
	u32 key;

	if (!inode || !inode->i_sb)
		return;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;
	entry->ino = inode->i_ino;
	entry->sb = inode->i_sb;
	key = hash_long(entry->ino ^ (unsigned long)entry->sb, 10);

	spin_lock(&susfs_hidden_inos_lock);
	hash_for_each_possible(susfs_hidden_inos, existing, node, key) {
		if (existing->ino == entry->ino && existing->sb == entry->sb) {
			spin_unlock(&susfs_hidden_inos_lock);
			kfree(entry);
			return;
		}
	}
	hash_add_rcu(susfs_hidden_inos, &entry->node, key);
	spin_unlock(&susfs_hidden_inos_lock);
}
'''.lstrip("\n")
if hidden_lock not in hidden_block:
    raise SystemExit("Hidden-inode lock is missing from the enhanced patch")
hidden_block = hidden_block.replace(
    hidden_lock, hidden_lock + "\n" + hidden_register, 1
)

hidden_anchor = re.search(
    r"^const struct qstr susfs_fake_qstr_name[^\n]*\n", source, re.MULTILINE
)
if not hidden_anchor:
    raise SystemExit("Cannot locate SUSFS fake-qstr anchor")
source = (
    source[: hidden_anchor.end()]
    + "\n"
    + hidden_block
    + "\n"
    + source[hidden_anchor.end() :]
)

rewritten = []
registered_fuse = 0
registered_inode = 0
for line in source.splitlines(keepends=True):
    rewritten.append(line)
    indent = re.match(r"^(\s*)", line).group(1)
    if "set_bit(AS_FLAGS_SUS_PATH, &fi->inode.i_mapping->flags);" in line:
        rewritten.extend(
            (
                "#ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME\n",
                f"{indent}susfs_register_hidden_ino(&fi->inode);\n",
                "#endif\n",
            )
        )
        registered_fuse += 1
    elif "set_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags);" in line:
        rewritten.extend(
            (
                "#ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME\n",
                f"{indent}susfs_register_hidden_ino(inode);\n",
                "#endif\n",
            )
        )
        registered_inode += 1
source = "".join(rewritten)
if registered_fuse < 1 or registered_inode < 1:
    raise SystemExit(
        "Could not wire hidden-inode registration into the SUS_PATH code"
    )

hidden_name_anchor = (
    '\tSUSFS_LOGI("CMD_SUSFS_ADD_SUS_PATH -> ret: %d\\n", info.err);\n'
)
hidden_name_call = (
    "#ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME\n"
    "\tif (!info.err)\n"
    "\t\tsusfs_try_register_hidden_name(info.target_pathname);\n"
    "#endif\n"
)
source = replace_once(
    source,
    hidden_name_anchor,
    hidden_name_call + hidden_name_anchor,
    "SUS_PATH result",
)

redirect_added = added_text_containing(hunks, "void susfs_add_sus_kstat_redirect")
redirect_block = preprocessor_block(
    redirect_added, "CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT"
)
redirect_block = redirect_block.replace(
    "spin_lock(&susfs_spin_lock_sus_kstat);",
    "mutex_lock(&susfs_mutex_lock_sus_kstat);",
).replace(
    "spin_unlock(&susfs_spin_lock_sus_kstat);",
    "mutex_unlock(&susfs_mutex_lock_sus_kstat);",
)
if "struct kstatfs *buf, bool *is_fuse)" in source:
    # ed8a8328 moved statfs/mount identity into every KSTAT hash entry.
    # The legacy redirect only initialized the userspace kstat fields.
    redirect_block = redirect_v2_path.read_text(encoding="utf-8")
    if "susfs_prepare_redirect_entry" not in redirect_block:
        raise SystemExit("Missing refactored KSTAT redirect implementation")
kstat_end = (
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n\n"
    "/* spoof_uname */"
)
source = replace_once(
    source,
    kstat_end,
    redirect_block + "\n" + kstat_end,
    "SUS_KSTAT section end",
)

report_block = added_text_containing(
    hunks, 'copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT'
).strip("\n")
feature_start = source.find("void susfs_get_enabled_features(")
if feature_start < 0:
    raise SystemExit("Cannot locate susfs_get_enabled_features()")
report_anchor = "\n\tinfo->err = 0;\nout_copy_to_user:"
report_at = source.find(report_anchor, feature_start)
if report_at < 0:
    raise SystemExit("Cannot locate enabled-features result anchor")
source = (
    source[:report_at]
    + "\n"
    + report_block
    + "\n"
    + source[report_at:]
)

if "spin_lock(&susfs_spin_lock_sus_kstat)" in redirect_block:
    raise SystemExit("Legacy SUS_KSTAT redirect spinlock remains")
for marker in markers:
    if marker not in source:
        raise SystemExit(f"Missing enhanced SUSFS source marker: {marker}")

source_path.write_text(source, encoding="utf-8")
print(
    "Applied pinned-SUSFS fs/susfs.c port "
    f"(hidden inode anchors: fuse={registered_fuse}, inode={registered_inode})"
)
PY

python3 - "$KSU_ROOT" "$COMMON" <<'PY'
import pathlib
import re
import sys

ksu_root = pathlib.Path(sys.argv[1])
common = pathlib.Path(sys.argv[2])
candidates = [
    ksu_root / "kernel/supercall/dispatch.c",
    common / "drivers/kernelsu/supercall/dispatch.c",
]
seen = set()
handled = 0

for candidate in candidates:
    if not candidate.exists():
        continue
    resolved = candidate.resolve()
    if resolved in seen:
        continue
    seen.add(resolved)

    text = candidate.read_text(encoding="utf-8")
    if "CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT" in text:
        handled += 1
        continue

    braced_pattern = re.compile(
        r"(?P<indent>^[ \t]*)case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: \{\n"
        r"(?P=indent)[ \t]+susfs_add_sus_kstat\(arg\);\n"
        r"(?P=indent)[ \t]+return 0;\n"
        r"(?P=indent)\}\n",
        re.MULTILINE,
    )
    plain_pattern = re.compile(
        r"(?P<indent>^[ \t]*)case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:\n"
        r"(?P=indent)[ \t]+susfs_add_sus_kstat\(arg\);\n"
        r"(?P=indent)[ \t]+return 0;\n",
        re.MULTILINE,
    )
    match = braced_pattern.search(text)
    braced = match is not None
    if not match:
        match = plain_pattern.search(text)
    if not match:
        raise SystemExit(f"Cannot locate SUSFS kstat dispatch block in {candidate}")

    indent = match.group("indent")
    redirect_case = f"{indent}case CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT:"
    if braced:
        redirect_case += " {\n"
    else:
        redirect_case += "\n"
    redirect_case += (
        f"{indent}    susfs_add_sus_kstat_redirect(arg);\n"
        f"{indent}    return 0;\n"
    )
    if braced:
        redirect_case += f"{indent}}}\n"
    block = (
        match.group(0)
        + "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT\n"
        + redirect_case
        + "#endif // CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT\n"
    )
    candidate.write_text(text[:match.start()] + block + text[match.end():], encoding="utf-8")
    handled += 1
    print(f"Added kstat redirect dispatch: {candidate}")

if handled == 0:
    raise SystemExit("No SukiSU SUSFS dispatch source was found")
PY

# Pinned SUSFS retains the two external-directory command IDs as deprecated
# compatibility calls, while ReSukiSU's new dispatcher no longer acknowledges
# them. ZeroMount also still sends the pre-v2.2 SUS_PATH structure. Add a small
# dual-layout adapter around the current SUSFS functions so both the current
# ksu_susfs tool and ZeroMount remain supported. No legacy path implementation
# or overlapping filesystem hooks are reintroduced.
python3 - "$KSU_ROOT" "$COMMON" <<'PY'
import pathlib
import re
import sys

ksu_root = pathlib.Path(sys.argv[1])
common = pathlib.Path(sys.argv[2])
candidates = [
    ksu_root / "kernel/supercall/dispatch.c",
    common / "drivers/kernelsu/supercall/dispatch.c",
]
helper_markers = (
    "ksu_susfs_ack_deprecated_external_dir",
    "ksu_susfs_dispatch_path_compat",
)
command_markers = (
    "case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:",
    "case CMD_SUSFS_SET_SDCARD_ROOT_PATH:",
)
seen = set()
handled = 0

for candidate in candidates:
    if not candidate.exists():
        continue
    resolved = candidate.resolve()
    if resolved in seen:
        continue
    seen.add(resolved)

    text = candidate.read_text(encoding="utf-8")
    present = tuple(marker in text for marker in helper_markers + command_markers)
    if all(present):
        handled += 1
        print(f"ZeroMount external-dir compatibility already present: {candidate}")
        continue
    if any(present):
        raise SystemExit(f"Partial ZeroMount external-dir compatibility in {candidate}")

    dispatch_anchor = "int ksu_handle_susfs_cmd(unsigned int cmd, void __user **arg)\n"
    if text.count(dispatch_anchor) != 1:
        raise SystemExit(f"Expected one SUSFS dispatcher anchor in {candidate}")

    helper = r'''struct ksu_susfs_current_path {
    char target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int err;
};

struct ksu_susfs_legacy_path {
    unsigned long target_ino;
    char target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned int i_uid;
    int err;
};

static int ksu_susfs_dispatch_path_compat(void __user **arg, bool loop)
{
    struct ksu_susfs_legacy_path legacy = { 0 };
    struct ksu_susfs_current_path v2_path = { 0 };
    char current_first = 0;
    char legacy_first = 0;

    if (get_user(current_first, (char __user *)*arg))
        return -EFAULT;
    if (current_first == '/')
        goto dispatch_current;
    if (get_user(legacy_first,
                 (char __user *)*arg + sizeof(legacy.target_ino)))
        return -EFAULT;
    if (legacy_first != '/')
        goto dispatch_current;

    if (copy_from_user(&legacy, *arg, sizeof(legacy)))
        return -EFAULT;
    strscpy(v2_path.target_pathname, legacy.target_pathname,
            sizeof(v2_path.target_pathname));
    v2_path.err = legacy.err;
    if (copy_to_user(*arg, &v2_path, sizeof(v2_path)))
        return -EFAULT;

    if (loop)
        susfs_add_sus_path_loop(arg);
    else
        susfs_add_sus_path(arg);

    if (copy_from_user(&v2_path, *arg, sizeof(v2_path)))
        legacy.err = -EFAULT;
    else
        legacy.err = v2_path.err;
    if (copy_to_user(*arg, &legacy, sizeof(legacy)))
        return -EFAULT;
    return 0;

dispatch_current:
    if (loop)
        susfs_add_sus_path_loop(arg);
    else
        susfs_add_sus_path(arg);
    return 0;
}

struct ksu_susfs_compat_external_dir {
    char target_pathname[SUSFS_MAX_LEN_PATHNAME];
    bool is_inited;
    int cmd;
    int err;
};

static int ksu_susfs_ack_deprecated_external_dir(void __user **arg,
                                                  unsigned int cmd)
{
    struct ksu_susfs_compat_external_dir info = { 0 };

    if (copy_from_user(&info, *arg, sizeof(info)))
        return -EFAULT;
    if (info.cmd != (int)cmd)
        return -EINVAL;

    info.err = 0;
    if (copy_to_user(
            &((struct ksu_susfs_compat_external_dir __user *)*arg)->err,
            &info.err, sizeof(info.err)))
        return -EFAULT;
    return 0;
}

'''
    text = text.replace(dispatch_anchor, helper + dispatch_anchor, 1)

    path_cases = (
        ("CMD_SUSFS_ADD_SUS_PATH", "susfs_add_sus_path", "false"),
        ("CMD_SUSFS_ADD_SUS_PATH_LOOP", "susfs_add_sus_path_loop", "true"),
    )
    for command, function, loop in path_cases:
        pattern = re.compile(
            rf"(?P<indent>^[ \t]*)case {command}: \{{\n"
            rf"(?P=indent)[ \t]+{function}\(arg\);\n"
            rf"(?P=indent)[ \t]+return 0;\n"
            rf"(?P=indent)\}}\n",
            re.MULTILINE,
        )
        match = pattern.search(text)
        if not match:
            raise SystemExit(f"Cannot locate {command} dispatch in {candidate}")
        indent = match.group("indent")
        replacement = (
            f"{indent}case {command}: {{\n"
            f"{indent}    return ksu_susfs_dispatch_path_compat(arg, {loop});\n"
            f"{indent}}}\n"
        )
        text = text[:match.start()] + replacement + text[match.end():]

    path_loop_pattern = re.compile(
        r"(?P<indent>^[ \t]*)case CMD_SUSFS_ADD_SUS_PATH_LOOP: \{\n",
        re.MULTILINE,
    )
    match = path_loop_pattern.search(text)
    if not match:
        raise SystemExit(f"Cannot locate SUSFS path-loop dispatch in {candidate}")
    indent = match.group("indent")
    cases = (
        f"{indent}case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:\n"
        f"{indent}    return ksu_susfs_ack_deprecated_external_dir(arg, cmd);\n"
        f"{indent}case CMD_SUSFS_SET_SDCARD_ROOT_PATH:\n"
        f"{indent}    return ksu_susfs_ack_deprecated_external_dir(arg, cmd);\n"
    )
    text = text[:match.start()] + cases + text[match.start():]
    candidate.write_text(text, encoding="utf-8")
    handled += 1
    print(f"Added ZeroMount external-dir compatibility: {candidate}")

if handled == 0:
    raise SystemExit("No ReSukiSU SUSFS dispatch source was found")
PY

for symbol in \
  KSU_SUSFS_SUS_KSTAT_REDIRECT \
  KSU_SUSFS_UNICODE_FILTER \
  KSU_SUSFS_HIDDEN_NAME; do
  grep -Rqx "config ${symbol}" "$COMMON" --include='Kconfig*' || {
    echo "::error::Enhanced SUSFS symbol is missing after targeted apply: ${symbol}"
    exit 1
  }
done

grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$COMMON/include/linux/susfs_def.h"
grep -q 'struct st_susfs_sus_kstat_redirect' "$COMMON/include/linux/susfs.h"
grep -q 'void susfs_add_sus_kstat_redirect' "$COMMON/fs/susfs.c"
grep -q 'susfs_check_unicode_bypass' "$COMMON/fs/namei.c"
grep -q 'susfs_is_hidden_name' "$COMMON/fs/open.c"
grep -q 'susfs_is_hidden_name' "$COMMON/fs/stat.c"
grep -Rq 'case CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT:' \
  "$KSU_ROOT/kernel" "$COMMON/drivers/kernelsu" 2>/dev/null
grep -Rq 'ksu_susfs_ack_deprecated_external_dir' \
  "$KSU_ROOT/kernel" "$COMMON/drivers/kernelsu" 2>/dev/null
grep -Rq 'ksu_susfs_dispatch_path_compat' \
  "$KSU_ROOT/kernel" "$COMMON/drivers/kernelsu" 2>/dev/null
grep -Rq 'case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:' \
  "$KSU_ROOT/kernel" "$COMMON/drivers/kernelsu" 2>/dev/null
grep -Rq 'case CMD_SUSFS_SET_SDCARD_ROOT_PATH:' \
  "$KSU_ROOT/kernel" "$COMMON/drivers/kernelsu" 2>/dev/null

echo "Enhanced SUSFS features applied and audited for ${SUSFS_VERSION_LABEL}."
