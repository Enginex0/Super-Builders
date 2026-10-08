#!/bin/bash
set -euo pipefail

COMMON_TREE="$(cd "${1:?common tree}" && pwd)"
DEFCONFIG="${2:?gki defconfig}"

[[ -f "$DEFCONFIG" ]] || {
  echo "::error::Samsung GKI defconfig is unavailable: $DEFCONFIG"
  exit 1
}

KERNEL_ROOT="$(cd "$COMMON_TREE/.." && pwd)"
CLANG_ROOT="$KERNEL_ROOT/prebuilts/clang/host/linux-x86"
CLANG_BIN="$(find "$CLANG_ROOT" -path '*/bin/clang' \( -type f -o -type l \) -print 2>/dev/null | LC_ALL=C sort | tail -n 1)"
[[ -n "$CLANG_BIN" && -x "$CLANG_BIN" ]] || {
  echo "::error::Pinned Android clang was not found below $CLANG_ROOT"
  exit 1
}

TMP_PARENT="${RUNNER_TEMP:-/tmp}"
mkdir -p "$TMP_PARENT"
OUT_DIR="$(mktemp -d "$TMP_PARENT/s928b-kleaf-defconfig.XXXXXX")"
cleanup() {
  rm -rf -- "$OUT_DIR"
}
trap cleanup EXIT

CLANG_DIR="$(dirname "$CLANG_BIN")"
BEFORE_SHA256="$(sha256sum "$DEFCONFIG" | awk '{print $1}')"

generate_savedefconfig() {
  rm -f "$OUT_DIR/.config" "$OUT_DIR/defconfig"
  PATH="$CLANG_DIR:$PATH" \
    KCONFIG_NOTIMESTAMP=1 \
    make -s -C "$COMMON_TREE" O="$OUT_DIR" ARCH=arm64 \
      LLVM=1 LLVM_IAS=1 CC=clang LD=ld.lld gki_defconfig
  PATH="$CLANG_DIR:$PATH" \
    KCONFIG_NOTIMESTAMP=1 \
    make -s -C "$COMMON_TREE" O="$OUT_DIR" ARCH=arm64 \
      LLVM=1 LLVM_IAS=1 CC=clang LD=ld.lld savedefconfig
  [[ -s "$OUT_DIR/defconfig" ]] || {
    echo "::error::Kernel savedefconfig produced no output"
    exit 1
  }
}

# Samsung's release defconfig is functionally valid but is not serialized in
# the canonical order required by Kleaf's check_defconfig action. Normalize it
# with the exact overlaid Kconfig tree and pinned Android clang. This changes
# only the representation: Kconfig resolves the same values before writing the
# minimal defconfig.
generate_savedefconfig
install -m 0644 "$OUT_DIR/defconfig" "$DEFCONFIG"

# Prove that the normalized file is a fixed point. Kleaf performs the same
# semantic check later; retaining this check makes configuration drift fail
# before the expensive kernel compilation begins.
FIRST_PASS="$OUT_DIR/defconfig.first"
cp "$DEFCONFIG" "$FIRST_PASS"
generate_savedefconfig
if ! cmp -s "$FIRST_PASS" "$OUT_DIR/defconfig"; then
  echo "::error::Samsung GKI defconfig normalization is not stable"
  diff -u "$FIRST_PASS" "$OUT_DIR/defconfig" || true
  exit 1
fi

AFTER_SHA256="$(sha256sum "$DEFCONFIG" | awk '{print $1}')"
echo "Samsung DZG1 GKI defconfig normalized for Kleaf check_defconfig."
echo "  before: $BEFORE_SHA256"
echo "  after:  $AFTER_SHA256"
