#!/usr/bin/env python3
"""Exercise the real patched shell and Rust SUSFS classification expressions."""
import argparse
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
import apply as patch

PRELUDE = """
#[derive(Clone, Copy, Debug, PartialEq)]
enum SusfsMode { Enhanced, Embedded, Absent }
#[derive(Clone, Copy, PartialEq)]
enum ExternalSusfsModule { None, Susfs4ksu }
struct Caps { susfs_mode: SusfsMode }
fn classify(kernel_has_susfs: bool, binary_found: bool, external: bool) -> String {
    let external_module = if external { ExternalSusfsModule::Susfs4ksu } else { ExternalSusfsModule::None };
    let mut caps = Caps { susfs_mode: SusfsMode::Absent };
"""
POSTLUDE = """
    format!("{:?}", caps.susfs_mode)
}
fn main() {
    let flags: Vec<bool> = std::env::args().skip(1).map(|s| s == "1").collect();
    println!("{}", classify(flags[0], flags[1], flags[2]));
}
"""
def detection_source(source):
    text = (source / "src/detect/susfs.rs").read_text()
    start = text.index("    let sukisu = ")
    end = text.index("\n\n    debug!(", start)
    return text[start:end]
def run_matrix(binary):
    checks = 0
    for baka, legacy in itertools.product((None, "true", "false", "TRUE"), repeat=2):
        env = dict(os.environ)
        env.pop("BAKASU", None)
        env.pop("KSU_SUKISU", None)
        if baka is not None: env["BAKASU"] = baka
        if legacy is not None: env["KSU_SUKISU"] = legacy
        family = baka == "true" or legacy == "true"
        for kernel, found, external in itertools.product((False, True), repeat=3):
            expected = "Absent" if not kernel else ("Enhanced" if external or (family and found) else "Embedded")
            actual = subprocess.check_output([str(binary), *["1" if v else "0" for v in (kernel, found, external)]], env=env, text=True).strip()
            if actual != expected:
                raise RuntimeError(f"Wrong SUSFS classification: BAKASU={baka} legacy={legacy} kernel={kernel} binary={found} external={external}: {actual} != {expected}")
            checks += 1
    return checks
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    source, work = args.source.resolve(), args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    shell = (source / "module/customize.sh").read_text()
    assert shell.count(patch.NEW_SHELL) == 1
    assert patch.OLD_SHELL not in shell
    expr = patch.NEW_SHELL.removeprefix("if ").removesuffix("; then")
    shell_checks = 0
    for baka, legacy in itertools.product((None, "true", "false", "TRUE"), repeat=2):
        env = dict(os.environ)
        env.pop("BAKASU", None); env.pop("KSU_SUKISU", None)
        if baka is not None: env["BAKASU"] = baka
        if legacy is not None: env["KSU_SUKISU"] = legacy
        actual = subprocess.check_output(["sh", "-c", f"if {expr}; then echo yes; else echo no; fi"], env=env, text=True).strip()
        assert (actual == "yes") == (baka == "true" or legacy == "true")
        shell_checks += 1
    body = detection_source(source)
    rust = work / "classification.rs"
    binary = work / "classification"
    rust.write_text(PRELUDE + body + POSTLUDE)
    subprocess.run([args.rustc, "--edition=2021", str(rust), "-o", str(binary)], check=True)
    rust_checks = run_matrix(binary)
    # Restoring the original legacy-only probe must fail the BakaSU matrix.
    mutant = work / "classification-legacy.rs"
    mutant.write_text(PRELUDE + body.replace(patch.NEW_RUST, patch.OLD_RUST, 1) + POSTLUDE)
    mutant_binary = work / "classification-legacy"
    subprocess.run([args.rustc, "--edition=2021", str(mutant), "-o", str(mutant_binary)], check=True)
    try:
        run_matrix(mutant_binary)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Legacy-only SUSFS detector mutation was not rejected")
    receipt = {"shell_flag_cases": shell_checks, "rust_susfs_mode_cases": rust_checks,
               "legacy_only_mutation_rejected": True,
               "device_installation_tested": False}
    (work / "DETECTION-TESTS.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
if __name__ == "__main__":
    main()
