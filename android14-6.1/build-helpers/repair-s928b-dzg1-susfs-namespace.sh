#!/bin/bash
set -euo pipefail

COMMON_TREE="$(cd "${1:?common tree}" && pwd)"
SOURCE="$COMMON_TREE/fs/namespace.c"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SUSFS_COMMIT="${2:-153f88df3be2501d2d33364f8fe05247aecb3cef}"
[[ -f "$SOURCE" ]] || {
  echo "::error::Samsung namespace source is unavailable: $SOURCE"
  exit 1
}

"$PYTHON_BIN" - "$SOURCE" "$SUSFS_COMMIT" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
text = source.read_text(encoding="utf-8")
latched_mounts = sys.argv[2] == "24743360ea08d98f6ad72b856851abed8de5854f"
refactored_mounts = latched_mounts or sys.argv[2] == "887928223bf685113f32837d5282117c9e4a04ca"

marker_re = re.compile(
    r"^#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    r"^[ \t]*copy_flags \|= CL_COPY_MNT_NS;\n"
    r"^#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n?",
    re.MULTILINE,
)
matches = list(marker_re.finditer(text))
if len(matches) != 1:
    raise SystemExit(
        f"Expected exactly one SUSFS copy_mnt_ns marker block, found {len(matches)}"
    )

# GNU patch with fuzz 3 can match this small hunk against copy_mount_options()
# in Samsung's tree. Remove the uniquely identified block first, then anchor it
# inside copy_mnt_ns() using the surrounding copy_flags statements.
text = marker_re.sub("", text, count=1)
signature = "struct mnt_namespace *copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,"
function_start = text.find(signature)
if function_start < 0:
    raise SystemExit("Samsung copy_mnt_ns() signature was not found")

next_signature = "\nstruct dentry *mount_subtree(struct vfsmount *m, const char *name)"
function_end = text.find(next_signature, function_start)
if function_end < 0:
    raise SystemExit("Samsung mount_subtree() boundary after copy_mnt_ns() was not found")

function = text[function_start:function_end]
anchor_re = re.compile(
    r"(^[ \t]*copy_flags = CL_COPY_UNBINDABLE \| CL_EXPIRE;\n"
    r"^[ \t]*if \(user_ns != ns->user_ns\)\n"
    r"^[ \t]*copy_flags \|= CL_SHARED_TO_SLAVE;\n)",
    re.MULTILINE,
)
anchors = list(anchor_re.finditer(function))
if len(anchors) != 1:
    raise SystemExit(
        f"Expected one Samsung copy_mnt_ns() copy_flags anchor, found {len(anchors)}"
    )

marker = (
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "\tcopy_flags |= CL_COPY_MNT_NS;\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
)
insert_at = function_start + anchors[0].end()
text = text[:insert_at] + marker + text[insert_at:]

if len(list(marker_re.finditer(text))) != 1:
    raise SystemExit("Relocated SUSFS copy_mnt_ns marker is not unique")
function_end += len(marker)
function = text[function_start:function_end]
marker_offset = function.find("copy_flags |= CL_COPY_MNT_NS;")
copy_tree_offset = function.find("new = copy_tree(")
if marker_offset < 0 or copy_tree_offset < 0 or marker_offset > copy_tree_offset:
    raise SystemExit("Relocated SUSFS marker is outside the copy_mnt_ns copy-tree path")
if "int copy_flags;" not in function[:marker_offset]:
    raise SystemExit("copy_flags is not declared before the relocated SUSFS marker")


def unique(token: str) -> int:
    count = text.count(token)
    if count != 1:
        raise SystemExit(f"Expected exactly one namespace marker, found {count}: {token}")
    return text.find(token)


def region(start_token: str, end_token: str, label: str) -> str:
    start = text.find(start_token)
    if start < 0:
        raise SystemExit(f"Cannot find {label} start: {start_token}")
    end = text.find(end_token, start + len(start_token))
    if end < 0:
        raise SystemExit(f"Cannot find {label} end: {end_token}")
    return text[start:end]


def ordered(scope: str, label: str, *tokens: str) -> None:
    offset = -1
    for token in tokens:
        found = scope.find(token, offset + 1)
        if found < 0:
            raise SystemExit(f"Missing or misordered {label} marker: {token}")
        offset = found


if "\r" in text:
    raise SystemExit("Samsung namespace source still contains CR line endings")

top_end = text.find("static unsigned int sysctl_mount_max")
if top_end < 0:
    raise SystemExit("Cannot find namespace declaration boundary")
top = text[:top_end]
ordered(
    top,
    "declaration",
    "#include <linux/susfs_def.h>",
    "extern bool susfs_is_current_ksu_domain(void);",
    "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;",
    "#define CL_COPY_MNT_NS BIT(25)",
)

free_id = region(
    "static void mnt_free_id(struct mount *mnt)",
    "static int mnt_alloc_group_id(struct mount *mnt)",
    "mnt_free_id",
)
ordered(
    free_id,
    "mnt_free_id",
    "VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT",
    "ida_free(&mnt_id_ida, mnt->mnt_id);",
)

group_id = region(
    "static int mnt_alloc_group_id(struct mount *mnt)",
    "void mnt_release_group_id(struct mount *mnt)",
    "mnt_alloc_group_id",
)
ordered(
    group_id,
    "mnt_alloc_group_id",
    "susfs_is_current_ksu_domain()",
    "DEFAULT_KSU_MNT_GROUP_ID",
    "bypass_orig_flow:",
    "if (res < 0)",
)

allocator_region = region(
    "int mnt_get_count(struct mount *mnt)",
    "static struct mount *alloc_vfsmnt(const char *name)",
    "SUSFS allocators",
)
ordered(
    allocator_region,
    "SUSFS allocators",
    "static struct mount *susfs_alloc_unshare_ksu_vfsmnt(",
    "static struct mount *susfs_alloc_non_unshare_ksu_vfsmnt(",
)

lookup = region(
    "struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)",
    "struct vfsmount *lookup_mnt(const struct path *path)",
    "__lookup_mnt",
)
ordered(
    lookup,
    "__lookup_mnt",
    "susfs_is_current_proc_umounted()" if refactored_mounts else "susfs_is_current_proc_umounted_for_zygote_next()",
    "hlist_for_each_entry_rcu(p, head, mnt_hash)",
    "p->mnt_id < DEFAULT_KSU_MNT_ID",
    "return NULL;",
    "hlist_for_each_entry_rcu(p, head, mnt_hash)",
)

create_mount = region(
    "struct vfsmount *vfs_create_mount(struct fs_context *fc)",
    "EXPORT_SYMBOL(vfs_create_mount);",
    "vfs_create_mount",
)
ordered(
    create_mount,
    "vfs_create_mount",
    "susfs_is_sdcard_android_data_not_decrypted",
    "susfs_alloc_non_unshare_ksu_vfsmnt(fc->source ?: \"none\")",
    "bypass_orig_flow:",
    "if (!mnt)",
)

clone = region(
    "static struct mount *clone_mnt(struct mount *old, struct dentry *root,",
    "static void cleanup_mnt(struct mount *mnt)",
    "clone_mnt",
)
if refactored_mounts:
    ordered(
        clone, "refactored clone_mnt",
        "if (flag & CL_COPY_MNT_NS)",
        "susfs_alloc_unshare_ksu_vfsmnt(old->mnt_devname, old->mnt_id)",
        "susfs_alloc_non_unshare_ksu_vfsmnt(old->mnt_devname)",
        "if (old->mnt_id >= DEFAULT_KSU_MNT_ID)",
        "susfs_alloc_non_unshare_ksu_vfsmnt(old->mnt_devname)",
        "bypass_orig_flow:",
        "if (unlikely(is_mnt_ksu_unshared))" if latched_mounts else "susfs_is_current_ksu_domain() && (flag & CL_COPY_MNT_NS)",
        "VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT",
    )
else:
    ordered(
        clone, "clone_mnt",
        "bool is_mnt_ksu_unshared = false;",
        "susfs_alloc_unshare_ksu_vfsmnt(old->mnt_devname, old->mnt_id)",
        "susfs_alloc_non_unshare_ksu_vfsmnt(old->mnt_devname)",
        "bypass_orig_flow:",
        "VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT",
    )

if latched_mounts:
    ordered(clone, "latched mount allocation",
            "bool is_mnt_ksu_unshared = false;",
            "susfs_alloc_unshare_ksu_vfsmnt(old->mnt_devname, old->mnt_id)",
            "is_mnt_ksu_unshared = true;",
            "if (unlikely(is_mnt_ksu_unshared))",
            "VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT")

copy_namespace = region(signature, next_signature, "copy_mnt_ns")
ordered(
    copy_namespace,
    "copy_mnt_ns",
    "int copy_flags;",
    "copy_flags |= CL_COPY_MNT_NS;",
    "new = copy_tree(",
)

tail = text[text.rfind("#endif /* CONFIG_SYSCTL */") :]
ordered(
    tail,
    "exported SUSFS mount helpers",
    "int susfs_get_non_sus_mnt_id_from_mnt(struct mount *orig_mnt)",
    "struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt)",
)

for token in (
    "#include <linux/susfs_def.h>",
    "#define CL_COPY_MNT_NS BIT(25)",
    "static struct mount *susfs_alloc_unshare_ksu_vfsmnt(",
    "static struct mount *susfs_alloc_non_unshare_ksu_vfsmnt(",
    "int susfs_get_non_sus_mnt_id_from_mnt(struct mount *orig_mnt)",
    "struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt)",
):
    unique(token)

with source.open("w", encoding="utf-8", newline="") as output:
    output.write(text)
PY

grep -q '^struct mnt_namespace \*copy_mnt_ns' "$SOURCE"
test "$(grep -cF 'copy_flags |= CL_COPY_MNT_NS;' "$SOURCE")" = 1
echo "Verified complete Samsung ZZHL SUSFS namespace integration and function scope"
