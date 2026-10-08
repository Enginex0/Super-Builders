#!/usr/bin/env python3
"""Patch the two exact ZeroMount c3cb7ff BakaSU/SUSFS detection sites."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "c3cb7ffdf749f2441928ec47798615a4c79fab65"
RESET_PROP_PIN = "1f88c1a09b1e1673e12a60fe4e85ed96a416727d"
OLD_SHELL = 'if [ "$KSU_SUKISU" = "true" ]; then'
NEW_SHELL = 'if [ "${BAKASU:-}" = "true" ] || [ "${KSU_SUKISU:-}" = "true" ]; then'
OLD_RUST = 'let sukisu = std::env::var("KSU_SUKISU").map(|v| v == "true").unwrap_or(false);'
NEW_RUST = """let sukisu = ["BAKASU", "KSU_SUKISU"].into_iter().any(|name| {
        std::env::var(name).map(|v| v == "true").unwrap_or(false)
    });"""
PATCHES = {
    "module/customize.sh": (OLD_SHELL, NEW_SHELL),
    "src/detect/susfs.rs": (OLD_RUST, NEW_RUST),
}
def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])
def sha(data):
    return hashlib.sha256(data).hexdigest()
def expected(root):
    if git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise RuntimeError("ZeroMount compatibility patch requires exact c3cb7ff")
    if git(root / "external/resetprop-rs", "rev-parse", "HEAD").decode().strip() != RESET_PROP_PIN:
        raise RuntimeError("ZeroMount Resetprop submodule pin mismatch")
    for name in ("Cargo.toml", "Cargo.lock", ".gitmodules"):
        if (root / name).read_bytes() != git(root, "show", f"{PIN}:{name}"):
            raise RuntimeError(f"Unreviewed ZeroMount build input: {name}")
    files = {}
    for name, (old, new) in PATCHES.items():
        original = git(root, "show", f"{PIN}:{name}")
        text = original.decode()
        if text.count(old) != 1:
            raise RuntimeError(f"Missing unique detection site: {name}")
        files[name] = (original, text.replace(old, new, 1).encode())
    return files
def apply(root, verify_only=False):
    files = expected(root)
    # Validate all inputs before changing either file.
    for name, (original, patched) in files.items():
        allowed = (patched,) if verify_only else (original, patched)
        if (root / name).read_bytes() not in allowed:
            raise RuntimeError(f"Unexpected ZeroMount compatibility input: {name}")
    if not verify_only:
        for name, (_, patched) in files.items():
            (root / name).write_bytes(patched)
    return {
        "zeromount_commit": PIN,
        "resetprop_submodule_commit": RESET_PROP_PIN,
        "accepted_manager_flags": ["BAKASU=true", "KSU_SUKISU=true"],
        "classification_requires_kernel_susfs": True,
        "enhanced_without_external_module_requires_susfs_binary": True,
        "files": {name: {"upstream_sha256": sha(a), "patched_sha256": sha(b)}
                  for name, (a, b) in files.items()},
    }
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    receipt = apply(args.source.resolve(), args.verify_only)
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
if __name__ == "__main__":
    main()
