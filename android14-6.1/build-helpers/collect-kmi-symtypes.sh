#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?kernel root}"
REPORT_DIR="${2:?CRC report directory}"
KMI_PROFILE="${3:?KMI profile}"
KMI_MODE="${4:?KMI mode}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

[[ "$KMI_MODE" == "symtypes" || "$KMI_MODE" == "strict" ]] || {
  echo "::error::Symtypes collection is diagnostic-only: $KMI_MODE"
  exit 1
}
[[ -s "$REPORT_DIR/Module.symvers" ]] || {
  echo "::error::Audited Module.symvers is missing from $REPORT_DIR"
  exit 1
}

mkdir -p "$REPORT_DIR/source"

CONFIG_FILE=""
for candidate in \
  "$KERNEL_ROOT/out/android14-6.1/common/.config" \
  "$KERNEL_ROOT/bazel-bin/common/kernel_aarch64/.config"; do
  [[ -s "$candidate" ]] || continue
  CONFIG_FILE="$candidate"
  break
done
if [[ -z "$CONFIG_FILE" ]]; then
  while IFS= read -r candidate; do
    grep -qx 'CONFIG_ARM64=y' "$candidate" 2>/dev/null || continue
    CONFIG_FILE="$candidate"
    break
  done < <(find -L "$KERNEL_ROOT/bazel-bin/common" "$KERNEL_ROOT/out/android14-6.1" \
    -type f \( -name .config -o -name '*kernel*aarch64*config*' \) -print 2>/dev/null || true)
fi
[[ -n "$CONFIG_FILE" && -s "$CONFIG_FILE" ]] || {
  echo "::error::Final config was not found for $KMI_PROFILE"
  exit 1
}
cp "$CONFIG_FILE" "$REPORT_DIR/final.config"

{
  printf 'repository\tcommit\n'
  [[ -z "${COMMON_UPSTREAM_COMMIT:-}" ]] || \
    printf 'common-upstream\t%s\n' "$COMMON_UPSTREAM_COMMIT"
  [[ -z "${MANIFEST_UPSTREAM_COMMIT:-}" ]] || \
    printf 'manifest-upstream\t%s\n' "$MANIFEST_UPSTREAM_COMMIT"
  for repository in common build KernelSU; do
    [[ -d "$KERNEL_ROOT/$repository/.git" ]] || continue
    printf '%s\t%s\n' "$repository" "$(git -C "$KERNEL_ROOT/$repository" rev-parse HEAD)"
  done
} > "$REPORT_DIR/source-revisions.tsv"

if [[ -n "${SAMSUNG_SOURCE_PROFILE:-}" && -s "$SAMSUNG_SOURCE_PROFILE" ]]; then
  cp "$SAMSUNG_SOURCE_PROFILE" "$REPORT_DIR/source/samsung-release-profile.env"
fi

git -C "$KERNEL_ROOT/common" diff --no-ext-diff --binary > "$REPORT_DIR/source/common-working-tree.patch" || true
git -C "$KERNEL_ROOT/common" status --short > "$REPORT_DIR/source/common-status.txt" || true

EXPORTS_RAW="$REPORT_DIR/source/export-macros.txt"
git -C "$KERNEL_ROOT/common" grep -nE \
  'EXPORT_(TRACEPOINT_)?SYMBOL(_GPL|_NS|_NS_GPL)?[[:space:]]*\(' \
  -- '*.c' '*.h' > "$EXPORTS_RAW" || true

"$PYTHON_BIN" - "$REPORT_DIR" "$EXPORTS_RAW" <<'PY'
from pathlib import Path
import re
import sys

report = Path(sys.argv[1])
exports_raw = Path(sys.argv[2])
mismatches: set[str] = set()
for name in ("compatible-differences.tsv", "unexpected.tsv", "missing.tsv"):
    path = report / name
    if not path.is_file():
        continue
    for line in path.read_text(errors="replace").splitlines()[1:]:
        if line.strip():
            mismatches.add(line.split("\t", 1)[0])

export_locations: dict[str, set[str]] = {}
macro = re.compile(
    r"EXPORT_(?P<trace>TRACEPOINT_)?SYMBOL(?:_GPL|_NS|_NS_GPL)?\s*\(\s*(?P<symbol>[A-Za-z0-9_]+)"
)
if exports_raw.is_file():
    for raw in exports_raw.read_text(errors="replace").splitlines():
        parts = raw.split(":", 2)
        if len(parts) != 3:
            continue
        source, line, text = parts
        match = macro.search(text)
        if not match:
            continue
        symbol = match.group("symbol")
        if match.group("trace"):
            symbol = "__tracepoint_" + symbol
        export_locations.setdefault(symbol, set()).add(f"{source}:{line}")

with (report / "mismatch-export-locations.tsv").open("w", newline="\n") as out:
    out.write("symbol\texport_locations\n")
    for symbol in sorted(mismatches):
        locations = ";".join(sorted(export_locations.get(symbol, ()))) or "UNMAPPED"
        out.write(f"{symbol}\t{locations}\n")
PY

SYMTYPES_LIST="$REPORT_DIR/symtypes-files.list"
: > "$SYMTYPES_LIST"
for root in bazel-bin/common out/android14-6.1; do
  [[ -e "$KERNEL_ROOT/$root" ]] || continue
  (
    cd "$KERNEL_ROOT"
    find -L "$root" -type f -name '*.symtypes' -print 2>/dev/null
  ) >> "$SYMTYPES_LIST"
done
LC_ALL=C sort -u -o "$SYMTYPES_LIST" "$SYMTYPES_LIST"
SYMTYPES_COUNT=$(wc -l < "$SYMTYPES_LIST")
(( SYMTYPES_COUNT > 0 )) || {
  echo "::error::KBUILD_SYMTYPES produced no .symtypes files"
  exit 1
}

{
  printf 'path\tsha256\tbytes\n'
  while IFS= read -r relative; do
    [[ -n "$relative" ]] || continue
    absolute="$KERNEL_ROOT/$relative"
    printf '%s\t%s\t%s\n' "$relative" \
      "$(sha256sum "$absolute" | awk '{print $1}')" \
      "$(stat -c '%s' "$absolute")"
  done < "$SYMTYPES_LIST"
} > "$REPORT_DIR/symtypes-manifest.tsv"

(
  cd "$KERNEL_ROOT"
  tar --dereference -czf "$REPORT_DIR/symtypes.tar.gz" -T "$SYMTYPES_LIST"
)

CONFIG_SHA256=$(sha256sum "$REPORT_DIR/final.config" | awk '{print $1}')
MODULE_SYMVERS_SHA256=$(sha256sum "$REPORT_DIR/Module.symvers" | awk '{print $1}')
cat >> "$REPORT_DIR/summary.env" <<EOF
CONFIG_SHA256=$CONFIG_SHA256
MODULE_SYMVERS_SHA256=$MODULE_SYMVERS_SHA256
SYMTYPES_COUNT=$SYMTYPES_COUNT
EOF

cat > "$REPORT_DIR/README.md" <<EOF
# Non-flashable KMI diagnostics: $KMI_PROFILE

- Mode: **$KMI_MODE**
- Symtypes files: **$SYMTYPES_COUNT**
- Final config SHA-256: \`$CONFIG_SHA256\`
- Module.symvers SHA-256: \`$MODULE_SYMVERS_SHA256\`

This artifact intentionally contains no kernel Image and no AnyKernel ZIP.
It is for CRC and type-difference attribution before strict KMI is enabled.
EOF

cat "$REPORT_DIR/README.md"
