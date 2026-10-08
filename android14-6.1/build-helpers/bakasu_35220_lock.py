#!/usr/bin/env python3
"""Repair the one stale libc source in BakaSU 35220's ksuinit lockfile."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

PIN = "8450dd287ef6ee25ca2b6b858b43c9354c73060c"
LIBC_REV = "1a661633f11a261ff9c00b40875ef72f1cbec818"
LOCK = "userspace/ksuinit/Cargo.lock"


def upstream(root, relative):
    return subprocess.check_output(["git", "-C", str(root), "show", f"{PIN}:{relative}"])


def libc_block(data):
    matches = re.findall(rb'(?m)^\[\[package\]\]\nname = "libc"\n(?:(?!\[\[).)*', data, re.S)
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one libc package in upstream lockfile")
    return matches[0]


def repair_bytes(original, ksud_lock, manifests):
    """Copy the exact 35220 ksud libc record (0.2.190); never run a dependency update."""
    patch = {"git": "https://github.com/rust-lang/libc", "rev": LIBC_REV}
    for manifest in manifests:
        if tomllib.loads(manifest.decode())["patch"]["crates-io"]["libc"] != patch:
            raise RuntimeError("Unexpected upstream libc manifest patch")
    old, replacement = libc_block(original), libc_block(ksud_lock)
    previous = tomllib.loads(old.decode())["package"][0]
    selected = tomllib.loads(replacement.decode())["package"][0]
    if previous != {
        "name": "libc", "version": "0.2.189",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "checksum": "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2",
    }:
        raise RuntimeError("Unexpected upstream ksuinit libc record")
    if selected != {
        "name": "libc", "version": "0.2.190",
        "source": f"git+https://github.com/rust-lang/libc?rev={LIBC_REV}#7b0ab5528dc7f361f3a0b4c06c2cad9971617f75",
    }:
        raise RuntimeError("Unexpected upstream ksud libc record")
    return original.replace(old, replacement, 1)


def expected_lock(root):
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        raise RuntimeError("This lockfile repair applies only to exact BakaSU 35220")
    paths = ("userspace/ksuinit/Cargo.toml", "userspace/ksud/Cargo.toml", "userspace/ksud/Cargo.lock")
    inputs = [upstream(root, name) for name in paths]
    for name, data in zip(paths, inputs):
        if (root / name).read_bytes() != data:
            raise RuntimeError(f"Lockfile repair input differs from upstream: {name}")
    original = upstream(root, LOCK)
    repaired = repair_bytes(original, inputs[2], inputs[:2])
    evidence = {
        "base_commit": PIN,
        "reason": "ksuinit manifest pins Git libc but its upstream lock still selects crates.io",
        "libc_revision": LIBC_REV,
        "record_source": "userspace/ksud/Cargo.lock at the same upstream commit",
        "upstream_sha256": hashlib.sha256(original).hexdigest(),
        "repaired_sha256": hashlib.sha256(repaired).hexdigest(),
    }
    return original, repaired, evidence


def verify(root):
    _, repaired, evidence = expected_lock(root)
    if (root / LOCK).read_bytes() != repaired:
        raise RuntimeError("ksuinit lock differs from the exact audited libc repair")
    return evidence


def apply(root):
    original, repaired, evidence = expected_lock(root)
    path = root / LOCK
    actual = path.read_bytes()
    if actual not in (original, repaired):
        raise RuntimeError("Refusing to overwrite an unexpected ksuinit lockfile")
    if actual != repaired:
        path.write_bytes(repaired)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps((verify if args.verify_only else apply)(args.source.resolve()), indent=2))


if __name__ == "__main__":
    main()
