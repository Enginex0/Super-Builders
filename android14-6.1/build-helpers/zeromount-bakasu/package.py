#!/usr/bin/env python3
"""Package patched ARM64 ZeroMount using a checksum-pinned official ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import apply as patch

BASE_SHA256 = "12f9fde9edde5317b86e3672b4b20981eaa16581d8e736ef781b7a628b1bd30f"
def sha(data):
    return hashlib.sha256(data).hexdigest()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--base-zip", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--tests", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--bakasu-version", required=True, type=int)
    parser.add_argument("--bakasu-commit", required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    receipt = patch.apply(source, verify_only=True)
    if sha(args.base_zip.read_bytes()) != BASE_SHA256:
        raise RuntimeError("Official ZeroMount module ZIP digest mismatch")
    binary = args.binary.read_bytes()
    if binary[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", binary, 18)[0] != 183:
        raise RuntimeError("Patched ZeroMount must be a real AArch64 ELF binary")
    if b"BAKASU" not in binary or b"KSU_SUKISU" not in binary:
        raise RuntimeError("Compiled ZeroMount lacks the two manager flag names")
    tests = json.loads(args.tests.read_text())
    if tests["shell_flag_cases"] != 16 or tests["rust_susfs_mode_cases"] != 128 or not tests["legacy_only_mutation_rejected"]:
        raise RuntimeError("Required BakaSU detector matrix was not completed")
    if args.bakasu_version != 35220 or args.bakasu_commit != "8450dd287ef6ee25ca2b6b858b43c9354c73060c":
        raise RuntimeError("ZeroMount package requires exact BakaSU 35220 pin")
    receipt.update(official_base_zip_sha256=BASE_SHA256, arm64_binary_sha256=sha(binary),
                   architecture="arm64-v8a", detection_tests=tests,
                   bakasu_version=args.bakasu_version, bakasu_commit=args.bakasu_commit,
                   susfs_version="v2.3.0",
                   susfs_commit="24743360ea08d98f6ad72b856851abed8de5854f",
                   full_r33_features_compatible=[
                       "Guard6.13","BRENE68/69","UIDGate2","BootGuard2",
                       "Droidspaces VFS","OPEN_REDIRECT","writer-adapters"
                   ])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"ZeroMount-v2.0.216-dev-BakaSU-{args.bakasu_version}-compat-arm64.zip"
    modified = {"customize.sh": (source / "module/customize.sh").read_bytes(),
                "bin/arm64-v8a/zeromount": binary}
    with zipfile.ZipFile(args.base_zip) as base, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        if base.testzip() is not None:
            raise RuntimeError("Damaged official module ZIP")
        # Check that the official installer is from the exact reviewed source.
        original = patch.git(source, "show", f"{patch.PIN}:module/customize.sh")
        if base.read("customize.sh") != original:
            raise RuntimeError("Official ZIP installer differs from pinned c3cb7ff source")
        for item in base.infolist():
            parts = Path(item.filename).parts
            if item.is_dir() or (parts[0] in ("bin", "lib") and len(parts) > 1 and parts[1] not in ("arm64-v8a",)):
                continue
            data = modified.pop(item.filename, base.read(item.filename))
            if item.filename == "module.prop":
                text = data.decode()
                text = text.replace("version=v2.0.216-dev", "version=v2.0.216-dev-bakasu-compat")
                data = text.encode()
            archive.writestr(item, data)
        if modified:
            raise RuntimeError(f"Official module ZIP lacks required ARM64 entries: {list(modified)}")
        archive.writestr("BAKASU-COMPAT-IDENTITY.json", json.dumps(receipt, indent=2) + "\n")
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert archive.read("bin/arm64-v8a/zeromount") == binary
        assert patch.NEW_SHELL in archive.read("customize.sh").decode()
    receipt["module_zip_sha256"] = sha(output.read_bytes())
    (args.output_dir / "BUILD-IDENTITY.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (args.output_dir / "SHA256SUMS").write_text(receipt["module_zip_sha256"] + "  " + output.name + "\n")
    print(json.dumps(receipt, indent=2))
if __name__ == "__main__":
    main()
