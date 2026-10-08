#!/usr/bin/env python3
"""Place legacy Enhanced/ZeroMount additions in named VFS functions, without fuzz."""
from pathlib import Path
import argparse
import re


def added_hunks(patch, target):
    text = patch.read_text(encoding="utf-8")
    sections = re.split(r"(?=^--- )", text, flags=re.M)
    matches = [s for s in sections if re.match(r"--- [^\n]*?/" + re.escape(target) + r"(?:\t|\n)", s)]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one patch section: {target}")
    return ["".join(line[1:] for line in h.splitlines(keepends=True) if line.startswith("+") and not line.startswith("+++"))
            for h in re.split(r"^@@[^\n]*\n", matches[0], flags=re.M)[1:]]


def once(source, anchor, replacement):
    if source.count(anchor) != 1:
        raise RuntimeError(f"Missing/ambiguous VFS anchor: {anchor!r}")
    return source.replace(anchor, replacement, 1)


def function(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: re.sub(r"[^\n]", " ", m[0]), source, flags=re.S)
    matches = list(re.finditer(r"^(?:static\s+)?(?:inline\s+)?(?:int|long|void)\s+" + name + r"\([^;{]*\)\s*\{", masked, re.M))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one function: {name}")
    match = matches[0]
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[match.start():end]


def insert_in(source, name, anchor, addition):
    body = function(source, name)
    return once(source, body, once(body, anchor, addition + anchor))


def enhanced(common, patch):
    outputs = {}
    declarations = """
#ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME
extern bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid);
#endif
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER
extern bool susfs_check_unicode_bypass(const char __user *filename);
#endif
"""
    for name in ("fs/open.c", "fs/stat.c"):
        path = common / name
        source = path.read_text(encoding="utf-8")
        if "susfs_check_unicode_bypass" in source:
            raise RuntimeError(f"Enhanced VFS already applied: {name}")
        hunks = [h for h in added_hunks(patch, name) if re.search(r'KSU_SUSFS_HIDDEN_NAME|KSU_SUSFS_UNICODE_FILTER', h)]
        source = once(source, '#include "internal.h"\n', '#include "internal.h"\n' + declarations)
        if name == "fs/open.c":
            if len(hunks) != 3:
                raise RuntimeError("Expected three open.c additions")
            source = insert_in(source, "do_faccessat", "\tinode = d_backing_inode(path.dentry);", hunks[1])
            source = insert_in(source, "do_sys_openat2", "\ttmp = getname(filename);", hunks[2])
        else:
            if len(hunks) != 4:
                raise RuntimeError("Expected four stat.c additions")
            source = insert_in(source, "vfs_statx", "\tif (flags & ~(AT_SYMLINK_NOFOLLOW", hunks[1])
            source = insert_in(source, "vfs_statx", "\terror = vfs_getattr(&path, stat, request_mask, flags);", hunks[2])
            source = insert_in(source, "do_readlinkat", "\tif (bufsiz <= 0)", hunks[3])
        outputs[path] = source
    for path, source in outputs.items():
        path.write_text(source, encoding="utf-8", newline="\n")
    print("PASS: Enhanced open/stat hooks inserted in the intended functions")


def zeromount(common, patch):
    path = common / "fs/stat.c"
    source = path.read_text(encoding="utf-8")
    if "zeromount_stat_hook" in source:
        raise RuntimeError("ZeroMount stat hook already applied")
    hunks = added_hunks(patch, "fs/stat.c")
    if len(hunks) != 3:
        raise RuntimeError("Expected three ZeroMount stat additions")
    source = once(source, '#include "mount.h"\n', '#include "mount.h"\n' + hunks[0])
    body = function(source, "vfs_statx")
    source = once(source, body, hunks[1] + body)
    # Keep Unicode filtering before path redirection and preserve error handling.
    source = insert_in(source, "vfs_statx", "\tif (flags & ~(AT_SYMLINK_NOFOLLOW", hunks[2])
    if "zeromount_stat_hook" in function(source, "do_readlinkat"):
        raise RuntimeError("ZeroMount stat hook escaped vfs_statx")
    path.write_text(source, encoding="utf-8", newline="\n")
    print("PASS: ZeroMount stat redirection scoped to vfs_statx")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("enhanced", "zeromount"))
    parser.add_argument("common", type=Path)
    parser.add_argument("patch", type=Path)
    args = parser.parse_args()
    (enhanced if args.mode == "enhanced" else zeromount)(args.common, args.patch)
