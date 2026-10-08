#!/bin/bash
set -euo pipefail

BASELINE="${1:?Samsung DLKM CRC baseline}"
ARTIFACT_ROOT="${2:?downloaded diagnostics root}"
OUTPUT_DIR="${3:?aggregate output directory}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

[[ -s "$BASELINE" ]] || { echo "::error::Missing baseline: $BASELINE"; exit 1; }
mkdir -p "$OUTPUT_DIR"

"$PYTHON_BIN" - "$BASELINE" "$ARTIFACT_ROOT" "$OUTPUT_DIR" <<'PY'
from pathlib import Path
import sys

baseline_path = Path(sys.argv[1])
artifact_root = Path(sys.argv[2])
output = Path(sys.argv[3])

preferred_order = [
    "gki-control",
    "resukisu-minimal",
    "resukisu-base",
    "resukisu-susfs",
    "resukisu-zeromount",
    "resukisu-zeromount-droidspaces",
    "resukisu-platform-features",
    "full",
]

baseline: dict[str, tuple[str, str, str]] = {}
for raw in baseline_path.read_text(errors="replace").splitlines():
    if not raw or raw.startswith("#"):
        continue
    parts = raw.split("\t")
    if len(parts) >= 3:
        baseline[parts[0]] = (parts[1].lower(), parts[2].lower(), parts[3] if len(parts) > 3 else "")

variants: dict[str, dict] = {}
for env_path in artifact_root.rglob("summary.env"):
    values: dict[str, str] = {}
    for raw in env_path.read_text(errors="replace").splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key] = value
    profile = values.get("KMI_PROFILE")
    symvers_path = env_path.parent / "Module.symvers"
    if not profile or not symvers_path.is_file():
        continue
    crcs: dict[str, str] = {}
    for raw in symvers_path.read_text(errors="replace").splitlines():
        parts = raw.split()
        if len(parts) >= 2:
            crcs[parts[1]] = parts[0].lower()
    variants[profile] = {"values": values, "crcs": crcs, "path": env_path.parent}

if not variants:
    raise SystemExit("no KMI diagnostic variants with summary.env and Module.symvers were found")

order = [name for name in preferred_order if name in variants]
order.extend(sorted(set(variants) - set(order)))

def counts(crcs: dict[str, str]) -> tuple[int, int, int, int]:
    exact = reference = variant = missing = 0
    for symbol, (device_crc, reference_crc, _) in baseline.items():
        actual = crcs.get(symbol)
        if actual is None:
            missing += 1
        elif actual == device_crc:
            exact += 1
        elif actual == reference_crc:
            reference += 1
        else:
            variant += 1
    return exact, reference, variant, missing

with (output / "variant-summary.tsv").open("w", newline="\n") as out:
    out.write("profile\texact\treference\tvariant\tmissing\tstrict_ready\tconfig_sha256\tsymvers_sha256\n")
    for profile in order:
        exact, reference, variant, missing = counts(variants[profile]["crcs"])
        values = variants[profile]["values"]
        strict_ready = "yes" if exact == len(baseline) else "no"
        out.write(
            f"{profile}\t{exact}\t{reference}\t{variant}\t{missing}\t{strict_ready}\t"
            f"{values.get('CONFIG_SHA256', 'unknown')}\t{values.get('MODULE_SYMVERS_SHA256', 'unknown')}\n"
        )

with (output / "stage-deltas.tsv").open("w", newline="\n") as out:
    out.write("from_profile\tto_profile\tchanged_crc\tbecame_device_exact\tlost_device_exact\tbecame_missing\tbecame_present\n")
    for previous, current in zip(order, order[1:]):
        before = variants[previous]["crcs"]
        after = variants[current]["crcs"]
        changed = became_exact = lost_exact = became_missing = became_present = 0
        for symbol, (device_crc, _, _) in baseline.items():
            old = before.get(symbol)
            new = after.get(symbol)
            if old != new:
                changed += 1
            if old != device_crc and new == device_crc:
                became_exact += 1
            if old == device_crc and new != device_crc:
                lost_exact += 1
            if old is not None and new is None:
                became_missing += 1
            if old is None and new is not None:
                became_present += 1
        out.write(
            f"{previous}\t{current}\t{changed}\t{became_exact}\t{lost_exact}\t{became_missing}\t{became_present}\n"
        )

with (output / "symbol-crc-matrix.tsv").open("w", newline="\n") as out:
    out.write("symbol\tdevice_crc\tfull_reference_crc\tmodules\t" + "\t".join(order) + "\n")
    for symbol in sorted(baseline):
        device_crc, reference_crc, modules = baseline[symbol]
        actual = [variants[profile]["crcs"].get(symbol, "MISSING") for profile in order]
        out.write(f"{symbol}\t{device_crc}\t{reference_crc}\t{modules}\t" + "\t".join(actual) + "\n")

with (output / "first-divergence.tsv").open("w", newline="\n") as out:
    out.write("symbol\tdevice_crc\tfirst_nonexact_profile\tfirst_nonexact_crc\tmodules\n")
    for symbol in sorted(baseline):
        device_crc, _, modules = baseline[symbol]
        for profile in order:
            actual = variants[profile]["crcs"].get(symbol, "MISSING")
            if actual != device_crc:
                out.write(f"{symbol}\t{device_crc}\t{profile}\t{actual}\t{modules}\n")
                break

rows = []
for profile in order:
    exact, reference, variant, missing = counts(variants[profile]["crcs"])
    rows.append((profile, exact, reference, variant, missing))

gki = next((row for row in rows if row[0] == "gki-control"), None)
full = next((row for row in rows if row[0] == "full"), None)
conclusion = "The strict gate remains blocked until every profile required for the device has zero non-exact symbols."
if gki and gki[1] != len(baseline):
    conclusion = (
        "The unmodified GKI control already differs from Samsung DLKMs; exact Samsung source/config/toolchain "
        "alignment is required before feature-level refactoring can reach strict KMI."
    )
elif gki and gki[1] == len(baseline) and full and full[1] != len(baseline):
    conclusion = "The GKI control is exact; custom config or feature stages introduce the remaining KMI drift."
elif full and full[1] == len(baseline):
    conclusion = "The full profile is CRC-exact and is eligible for the separate strict build gate."

with (output / "summary.md").open("w", newline="\n") as out:
    out.write("# S928B KMI variant comparison\n\n")
    out.write(f"Baseline symbols: **{len(baseline)}**\n\n")
    out.write("| Profile | Device-exact | Reference | Variant | Missing | Strict ready |\n")
    out.write("|---|---:|---:|---:|---:|---|\n")
    for profile, exact, reference, variant, missing in rows:
        out.write(
            f"| {profile} | {exact} | {reference} | {variant} | {missing} | "
            f"{'yes' if exact == len(baseline) else 'no'} |\n"
        )
    out.write("\n## Automatic conclusion\n\n")
    out.write(conclusion + "\n")

print((output / "summary.md").read_text())
PY
