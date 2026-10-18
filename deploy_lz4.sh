#!/bin/bash
# Native LZ4 1.10.0 + NEON Acceleration Deployment - NUKI/NURFS
# Uses in-tree lz4/ (kept for native ZRAM) -> lib/lz4
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_SRC="$SCRIPT_DIR/lz4"
TARGET_DIR="$SCRIPT_DIR/lib/lz4"

if [ ! -d "$PATCH_SRC" ]; then
  echo "deploy_lz4: no lz4/ dir at $PATCH_SRC, skipping (lib/lz4 already populated)"
  exit 0
fi

echo "====> Deploying LZ4 from $PATCH_SRC -> $TARGET_DIR"
mkdir -p "$TARGET_DIR/lz4armv8"

for f in lz4.c lz4hc.c lz4.h lz4hc.h; do
  [ -f "$PATCH_SRC/$f" ] && cp -v "$PATCH_SRC/$f" "$TARGET_DIR/"
done
for f in lz4armv8/lz4accel.c lz4armv8/lz4accel.h lz4armv8/lz4armv8.S; do
  [ -f "$PATCH_SRC/$f" ] && cp -v "$PATCH_SRC/$f" "$TARGET_DIR/$f"
done

if ! grep -q "lz4armv8/lz4accel.h" "$TARGET_DIR/lz4.c" 2>/dev/null; then
  sed -i '1s/^/#include "lz4armv8\/lz4accel.h"\n/' "$TARGET_DIR/lz4.c" || true
fi

if [ -f "$PATCH_SRC/Makefile" ]; then
  echo "====> Using lz4/Makefile if present"
fi

echo "deploy_lz4: done"
