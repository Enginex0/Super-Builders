#!/usr/bin/env python3
"""Verify pinned BakaSU Rust inputs and the generated ARM64 userspace binaries."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
import resukisu_35184_lock
import resukisu_35187_lock
import resukisu_35189_lock
import resukisu_35193_lock
import resukisu_35201_lock
import resukisu_35202_lock
import resukisu_35203_lock
import resukisu_35203_uapi
import resukisu_35205_lock
import resukisu_35204_lock
import resukisu_35205_uapi
import resukisu_35204_uapi
import bakasu_35212_lock
import bakasu_35212_uapi
import bakasu_35215_lock
import bakasu_35215_uapi
import bakasu_35220_lock
import bakasu_35220_uapi


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_pinned_file(source, commit, relative):
    data = (source / relative).read_bytes()
    upstream = subprocess.check_output(['git', '-C', str(source), 'show', f'{commit}:{relative}'])
    if data != upstream:
        raise RuntimeError(f'{relative} differs from the pinned upstream file')
    return digest(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--version', required=True, type=int)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--verify-build', action='store_true')
    parser.add_argument('--build-messages', type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        raise RuntimeError('A full immutable source commit is required')
    if run('git', '-C', str(source), 'rev-parse', 'HEAD') != args.commit:
        raise RuntimeError('BakaSU checkout differs from the requested pin')
    count = int(run('git', '-C', str(source), 'rev-list', '--count', 'HEAD'))
    if 30700 + count != args.version:
        raise RuntimeError('BakaSU version formula mismatch')
    version_name = run('git', '-C', str(source), 'describe', '--tags', '--always')
    if version_name.startswith('v'):
        version_name = version_name[1:]

    rust = run('rustc', '+nightly', '--version', '--verbose')
    release = re.search(r'^release: (\d+)\.(\d+)\.(\d+)(.*)$', rust, re.M)
    # Edition 2024 raises the effective minimum above bindgen's Rust 1.71 floor.
    if not release or tuple(map(int, release.group(1, 2, 3))) < (1, 85, 0) or 'nightly' not in release[4]:
        raise RuntimeError('Rust Nightly >= 1.85 is required for Edition 2024')
    cargo = run('cargo', '+nightly', '--version')

    # Hash every source that defines the userspace dependency graph or generated
    # VERSION_CODE / bindgen contract. The checkout is immutable, so a successful
    # Android ksud build proves the OUT_DIR files existed when rustc consumed them;
    # their post-build Cargo location is intentionally not part of the interface.
    locked_paths = [
        'userspace/ksud/Cargo.toml',
        'userspace/ksud/Cargo.lock',
        'userspace/ksud/build.rs',
        'userspace/ksud/src/defs.rs',
        'userspace/ksud/src/android/uapi/mod.rs',
        'userspace/ksud/src/android/uapi/ksu_uapi.h',
        'userspace/ksuinit/Cargo.toml',
        'userspace/ksuinit/Cargo.lock',
    ]
    locked_paths += sorted(p.relative_to(source).as_posix() for p in (source / "uapi").rglob("*.h"))
    locked_paths += ["userspace/ksud/src/android/init_event.rs", "userspace/ksud/src/android/ksucalls.rs"]
    uapi_audit = {m.PIN: m for m in (resukisu_35203_uapi, resukisu_35204_uapi, resukisu_35205_uapi, bakasu_35212_uapi, bakasu_35215_uapi, bakasu_35220_uapi)}.get(args.commit)
    uapi = uapi_audit.verify_sources(source) if uapi_audit else None
    repair = {m.PIN: m for m in (resukisu_35184_lock, resukisu_35187_lock, resukisu_35189_lock, resukisu_35193_lock, resukisu_35201_lock, resukisu_35202_lock, resukisu_35203_lock, resukisu_35204_lock, resukisu_35205_lock, bakasu_35212_lock, bakasu_35215_lock, bakasu_35220_lock)}.get(args.commit)
    repairs = {}
    locked = {}
    for relative in locked_paths:
        if repair is not None and relative == repair.LOCK:
            repairs[relative] = repair.verify(source)
            locked[relative] = repairs[relative]['repaired_sha256']
        else:
            locked[relative] = verify_pinned_file(source, args.commit, relative)

    lock = tomllib.loads((source / 'userspace/ksud/Cargo.lock').read_text())
    bindgen = [p['version'] for p in lock['package'] if p['name'] == 'bindgen']
    if bindgen != ['0.73.2']:
        raise RuntimeError(f'Expected locked bindgen 0.73.2, got {bindgen}')

    clang = run(os.environ['CLANG_PATH'], '--version')
    libpath = Path(os.environ['LIBCLANG_PATH']) / 'libclang.so'
    lib = ctypes.CDLL(str(libpath))
    lib.clang_createIndex.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.clang_createIndex.restype = ctypes.c_void_p
    lib.clang_disposeIndex.argtypes = [ctypes.c_void_p]
    index = lib.clang_createIndex(0, 0)
    if not index:
        raise RuntimeError('libclang could not create a Clang index')
    lib.clang_disposeIndex(index)

    receipt = dict(commit=args.commit, version=args.version, version_name=version_name,
                   commit_count=count, rustc=rust, cargo=cargo, clang=clang,
                   libclang=str(libpath.resolve()), locked_source_sha256=locked,
                   lockfile_repairs=repairs, uapi=uapi,
                   bindgen='0.73.2', target='aarch64-linux-android',
                   runtime_test='not performed', build_verified=False)
    if args.verify_build:
        previous = json.loads(args.receipt.read_text())
        for key in ('commit', 'version', 'version_name', 'locked_source_sha256', 'lockfile_repairs', 'uapi', 'rustc', 'cargo'):
            if previous[key] != receipt[key]:
                raise RuntimeError(f'Build inputs changed: {key}')

        ndk_home = os.environ.get('ANDROID_NDK_HOME')
        ndk_root = os.environ.get('ANDROID_NDK_ROOT')
        if not ndk_home or ndk_home != ndk_root:
            raise RuntimeError(f'Android NDK roots differ: HOME={ndk_home!r}, ROOT={ndk_root!r}')
        cargo_ndk = run('cargo', '+nightly', 'ndk', '--version')
        if not re.search(r'\b4\.1\.2\b', cargo_ndk):
            raise RuntimeError(f'Expected cargo-ndk 4.1.2, got {cargo_ndk!r}')

        outputs = {}
        binary_data = {}
        for crate in ('ksud', 'ksuinit'):
            path = source / f'userspace/{crate}/target/aarch64-linux-android/release/{crate}'
            data = path.read_bytes()
            if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183:
                raise RuntimeError(f'{crate} is not an ELF64 little-endian AArch64 binary')
            binary_data[crate] = data
            outputs[crate] = dict(sha256=digest(data), size=len(data))

        # VERSION_CODE is used by `su -V` and module environment generation;
        # VERSION_NAME is used by clap's Android --version string. Both therefore
        # must survive in the final linked ksud binary. This validates the generated
        # build.rs values without depending on Cargo's private OUT_DIR layout.
        ksud = binary_data['ksud']
        if str(args.version).encode() not in ksud:
            raise RuntimeError(f'ksud binary does not contain expected version code {args.version}')
        if version_name.encode() not in ksud:
            raise RuntimeError(f'ksud binary does not contain expected version name {version_name!r}')

        if uapi is not None:
            receipt["generated_uapi_bindings"] = uapi_audit.verify_bindings(source, args.build_messages)
        receipt.update(build_verified=True, binaries=outputs,
                       generated_version_verified_in_binary=True,
                       generated_bindings_verified_by_successful_android_compile=True,
                       cargo_ndk=cargo_ndk, ndk=ndk_home)
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
