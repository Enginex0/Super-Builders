#!/usr/bin/env python3
"""Bounded consumer-side UID gate for SUSFS 24743360 / ReSukiSU 35203 / BakaSU 35204/35205/35212/35215/35220.

All anchors are planned before writes. An on-tree receipt makes reapplication
idempotent and detects later changes to the gated functions or protected hooks.
This is a Super-Builders extension, not a claimed upstream SUSFS feature.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
SUSFS_PIN = "24743360ea08d98f6ad72b856851abed8de5854f"
KSU_PINS = {"8770c7e324a22895703c4916b8a16520e0b81c79", "97c102ba05ee2915390cacae6d11e1727d6ca350", "9dbce02e511ea6b6305a238b84e456f6a92e1d0b", "e5423590bec3e24daffa4e9555c9592071319c68", "1bfed00f597e65700d70fee0feb1d424fc21a2e5", "8450dd287ef6ee25ca2b6b858b43c9354c73060c"}
SYMBOL = "CONFIG_KSU_SUSFS_UID_GATED_HIDING"
STATE = ".susfs-uid-gate-v1.json"
HEADER = "include/linux/susfs_uid_gate.h"
KCONFIG = '''config KSU_SUSFS_UID_GATED_HIDING
	bool "Restrict SUSFS visibility hiding to Android app UIDs"
	depends on KSU_SUSFS
	default n
	help
	  Additional real-UID gate for SUSFS path/name/map/mount hiding,
	  metadata, uname and bootconfig spoofing. System app-ids below 10000
	  bypass hiding in every Android user. Existing SUSFS rules still apply.
	  Does not change KernelSU authorization, unmount control, OPEN_REDIRECT
	  UID schemes, global symbol/log suppression or ZeroMount routing.
	  Local Super-Builders UIDGate-v1 extension; no new userspace ABI.

'''


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def body_span(text, name):
    """Return one C definition's body, including dual #if signatures."""
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: re.sub(r"[^\n]", " ", m[0]), text, flags=re.S)
    matches = list(re.finditer(r"\b" + re.escape(name) + r"\([^;{}\n]*\)\s*(?:#endif[^\n]*\s*)?\{", masked))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one definition: {name}, got {len(matches)}")
    start = matches[0].end() - 1
    pos, depth = start + 1, 1
    while depth and pos < len(masked):
        depth += (masked[pos] == "{") - (masked[pos] == "}")
        pos += 1
    if depth:
        raise RuntimeError(f"Unbalanced C: {name}")
    return start, pos


def once(text, old, new, label):
    if text.count(old) != 1:
        raise RuntimeError(f"Anchor drift at {label}: {text.count(old)} matches")
    return text.replace(old, new, 1)


# The existing predicate, thread flags and redirect code are NOT modified.
PROTECTED = {
    "include/linux/susfs_def.h": (
        "susfs_is_current_app_uid", "susfs_is_current_proc_umounted",
        "susfs_is_current_proc_umounted_app", "susfs_is_current_proc_no_su",
        "susfs_set_current_proc_umounted", "susfs_clear_current_proc_umounted",
        "susfs_is_current_proc_umounted_for_zygote_next",
        "susfs_set_current_proc_umounted_for_zygote_next",
        "susfs_clear_current_proc_umounted_for_zygote_next",
        "susfs_set_current_proc_no_su", "susfs_clear_current_proc_no_su"),
    "fs/susfs.c": ("susfs_open_redirect_spoof_do_sys_openat",
                   "susfs_open_redirect_spoof_vfs_readlink",
                   "susfs_open_redirect_spoof_do_proc_readlink",
                   "susfs_open_redirect_spoof_show_map_vma_srcu"),
}


def plan(original):
    files = dict(original)
    scopes = []

    def edit(path, old, new, name=None):
        if name:
            a, b = body_span(files[path], name)
            body = once(files[path][a:b], old, new, f"{path}:{name}")
            files[path] = files[path][:a] + body + files[path][b:]
            scopes.append((path, name))
        else:
            files[path] = once(files[path], old, new, path)

    def guard(name, anchor, result="false"):
        edit("fs/susfs.c", anchor,
             f"\tif (!susfs_uid_gate_current())\n\t\treturn {result};\n\n".replace("return ;", "return;") + anchor,
             name)

    edit("kernel/Kconfig", "config KSU_SUSFS_SUS_PATH\n", KCONFIG + "config KSU_SUSFS_SUS_PATH\n")
    edit("include/linux/susfs_def.h", "#include <linux/string.h>\n",
         "#include <linux/string.h>\n#include <linux/susfs_uid_gate.h>\n")
    edit("include/linux/susfs_def.h", "#define SUSFS_IS_INODE_SUS_MAP(inode) \\\n",
         "#define SUSFS_IS_INODE_SUS_MAP(inode) \\\n\t\tsusfs_uid_gate_current() && \\\n")
    guard("susfs_check_unicode_bypass", "\tif (!filename)")
    guard("susfs_is_hidden_name", "\tif (!caller_uid)")
    guard("susfs_is_hidden_ino", "\trcu_read_lock();")
    guard("susfs_is_inode_sus_path", "\tif (!susfs_is_current_proc_umounted_app()) {")
    guard("susfs_is_inode_sus_kstat", "\tif (!inode)")
    guard("susfs_sus_kstat_spoof_generic_fillattr", "\tswitch (result_mask) {", "")
    guard("susfs_sus_kstat_spoof_show_map_vma", "\tif (inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {", "")
    guard("susfs_sus_kstat_spoof_vfs_statfs", "\tif (*is_fuse)", "-EINVAL")
    guard("susfs_sus_kstat_spoof_inotify_fdinfo", "\trcu_read_lock();", "")
    guard("susfs_sus_kstat_spoof_proc_fd_seq_show", "\trcu_read_lock();", "")
    guard("susfs_spoof_uname", "\tdo {", "")
    feature = (f"#ifdef {SYMBOL}\n"
               f'\tinfo->err = copy_config_to_buf("{SYMBOL}\\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);\n'
               "\tif (info->err) goto out_copy_to_user;\n"
               "\tbuf_ptr = info->enabled_features + copied_size;\n#endif\n\n")
    edit("fs/susfs.c", "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n", feature + "#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n",
         "susfs_get_enabled_features")
    for suffix in ("vfsmnt", "mountinfo", "vfsstat"):
        anchor = "\tif (r->mnt_id >= DEFAULT_KSU_MNT_ID)"
        edit("fs/proc_namespace.c", anchor,
             f"\tif (!susfs_uid_gate_current())\n\t\treturn show_{suffix}(m, mnt);\n\n" + anchor,
             "susfs_show_" + suffix)
    for path in ("fs/statfs.c", "fs/proc/fd.c", "fs/notify/fdinfo.c"):
        edit(path, "likely(susfs_is_current_proc_umounted())",
             "likely(susfs_uid_gate_current() && susfs_is_current_proc_umounted())")
    # Android14 GKI patches bootconfig, not cmdline. Gate the caller so bypass
    # follows seq_puts(saved_boot_config), instead of yielding an empty file.
    edit("fs/proc/bootconfig.c", "#include <linux/slab.h>\n",
         "#include <linux/slab.h>\n#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
         "#include <linux/susfs_uid_gate.h>\n#endif\n")
    # The bootconfig jump-label runtime fix is applied before UIDGate so the
    # receipt hashes the final production callsite rather than a transient form.
    edit("fs/proc/bootconfig.c", "if (static_key_enabled(&susfs_is_fake_cmdline_or_bootconfig_buffer_set))",
         "if (susfs_uid_gate_current() && static_key_enabled(&susfs_is_fake_cmdline_or_bootconfig_buffer_set))",
         "boot_config_proc_show")
    files[HEADER] = (HERE / "susfs_uid_gate.h").read_text(encoding="utf-8")
    for path, names in PROTECTED.items():
        for name in names:
            a, b = body_span(original[path], name)
            c, d = body_span(files[path], name)
            if original[path][a:b] != files[path][c:d]:
                raise RuntimeError(f"Protected code changed: {name}")
            scopes.append((path, name))
    return files, scopes


PATHS = ("kernel/Kconfig", "include/linux/susfs_def.h", "fs/susfs.c", "fs/proc_namespace.c",
         "fs/statfs.c", "fs/proc/fd.c", "fs/notify/fdinfo.c", "fs/proc/bootconfig.c")


def tree_path(common, ksu, name):
    return (ksu if name == "kernel/Kconfig" else common) / name


def read_tree(common, ksu):
    return {p: tree_path(common, ksu, p).read_text(encoding="utf-8") for p in PATHS}


def source_pin(ksu):
    return subprocess.check_output(["git", "-C", str(ksu), "rev-parse", "HEAD"], text=True).strip()


def identity(common, ksu, pin):
    actual = source_pin(ksu)
    if actual not in KSU_PINS or pin != SUSFS_PIN:
        raise RuntimeError("UIDGate-v1 requires exact ReSukiSU 35203 / BakaSU 35204/35205/35212/35215/35220 and SUSFS 24743360 pins")
    if not re.search(r'#define\s+SUSFS_VERSION\s+"v2\.3\.0"', (common / "include/linux/susfs.h").read_text()):
        raise RuntimeError("Unexpected SUSFS source version")


def scope_hashes(files, scopes):
    result = {}
    for path, name in scopes:
        a, b = body_span(files[path], name)
        result[path + ":" + name] = digest(files[path][a:b])
    # These small consumer files receive no subsequent source transforms.
    for path in ("fs/statfs.c", "fs/proc/fd.c", "fs/notify/fdinfo.c", "include/linux/susfs_def.h"):
        result[path] = digest(files[path])
    return result


def verify(common, ksu):
    state = json.loads((common / STATE).read_text())
    if state["susfs_commit"] != SUSFS_PIN or state["resukisu_commit"] not in KSU_PINS or state["resukisu_commit"] != source_pin(ksu):
        raise RuntimeError("Invalid UIDGate receipt identity")
    files = read_tree(common, ksu)
    if (common / HEADER).read_bytes() != (HERE / "susfs_uid_gate.h").read_bytes():
        raise RuntimeError("UID gate header drift")
    if files["kernel/Kconfig"].count(KCONFIG) != 1:
        raise RuntimeError("UID gate Kconfig drift")
    if scope_hashes(files, state["scopes"]) != state["scope_sha256"]:
        raise RuntimeError("UID gate consumer/protected source drift")
    return state


def apply(common, ksu):
    if (common / STATE).exists():
        return verify(common, ksu)
    original = read_tree(common, ksu)
    if (common / HEADER).exists() or any(SYMBOL in s for s in original.values()):
        raise RuntimeError("Partial or foreign UID-gate implementation; refusing to overwrite")
    files, scopes = plan(original)  # No file writes before ALL anchors pass.
    state = {"extension": "Super-Builders-UIDGate-v1", "susfs_commit": SUSFS_PIN,
             "resukisu_commit": source_pin(ksu), "base_run": 36463712058,
             "scopes": scopes, "scope_sha256": scope_hashes(files, scopes),
             "header_sha256": digest(files[HEADER])}
    for path, value in files.items():
        tree_path(common, ksu, path).write_text(value, encoding="utf-8", newline="\n")
    (common / STATE).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return verify(common, ksu)


def require_config(text):
    for key in (SYMBOL, "CONFIG_KSU_SUSFS"):
        if re.findall(rf"^(?:{key}=.*|# {key} is not set)$", text, re.M) != [key + "=y"]:
            raise RuntimeError(f"Missing or conflicting compiled config: {key}=y")


def attest(state, config, image):
    require_config(config.read_text())
    blob = image.read_bytes()
    if blob.count(b"IKCFG_ST") != 1:
        raise RuntimeError("Expected one embedded IKCONFIG in packaged Image")
    start = blob.index(b"IKCFG_ST") + 8
    end = blob.index(b"IKCFG_ED", start)
    embedded = gzip.decompress(blob[start:end])
    require_config(embedded.decode())
    if SYMBOL.encode() + b"\n\0" not in blob:
        raise RuntimeError("Packaged Image lacks compiled enabled-features advertisement")
    return dict(state, image_sha256=digest(blob), final_config_sha256=digest(config.read_bytes()),
                embedded_config_sha256=digest(embedded), embedded_uid_gate="y",
                compiled_feature_advertisement=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", type=Path, required=True)
    parser.add_argument("--ksu", type=Path, required=True)
    parser.add_argument("--susfs-commit", required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    identity(args.common, args.ksu, args.susfs_commit)
    state = verify(args.common, args.ksu) if args.verify_only else apply(args.common, args.ksu)
    if args.config or args.image:
        if not (args.config and args.image):
            parser.error("--config and --image must be used together")
        state = attest(state, args.config, args.image)
    if args.receipt:
        args.receipt.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print("PASS: Super-Builders UIDGate-v1" + (" source + packaged Image" if args.image else " source"))


if __name__ == "__main__":
    main()
