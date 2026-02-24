#!/bin/bash
set -euo pipefail

SUSFS_COMMIT="${1:-4c065ad}"
KERNEL_ROOT="/mnt/external/claudetest-gki-build/kernel-test/android12-5.10-2024-05"
KERNEL_DIR="$KERNEL_ROOT/common"
SUSFS_DIR="/tmp/susfs-upstream"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

if [ ! -d "$KERNEL_DIR" ]; then
  echo "ERROR: Kernel source not found at $KERNEL_DIR"
  exit 1
fi

if [ ! -d "$SUSFS_DIR" ]; then
  echo "ERROR: SUSFS clone not found at $SUSFS_DIR"
  echo "  git clone https://gitlab.com/simonpunk/susfs4ksu.git -b gki-android12-5.10 $SUSFS_DIR"
  exit 1
fi

echo "=== Phase 0: Clean kernel source ==="
cd "$KERNEL_DIR"
git checkout .
rm -f fs/susfs.c include/linux/susfs_def.h include/linux/susfs.h
git clean -fd fs/ include/linux/ kernel/ 2>/dev/null || true
STATUS=$(git status --porcelain)
if [ -n "$STATUS" ]; then
  fail "kernel tree not clean after checkout"
  echo "$STATUS"
  exit 1
fi
pass "kernel tree clean"

echo ""
echo "=== Phase 1: Apply upstream SUSFS @ ${SUSFS_COMMIT:0:12} ==="
git -C "$SUSFS_DIR" checkout "$SUSFS_COMMIT" 2>/dev/null
echo "  commit: $(git -C "$SUSFS_DIR" log --oneline -1)"

SUSFS_PATCHES="$SUSFS_DIR/kernel_patches"
cp "$SUSFS_PATCHES/fs/susfs.c" ./fs/
cp "$SUSFS_PATCHES/include/linux/"*.h ./include/linux/

PATCH_OUT=$(patch -p1 --no-backup-if-mismatch < "$SUSFS_PATCHES/50_add_susfs_in_gki-android12-5.10.patch" 2>&1)
REJECTS=$(find . -name "*.rej" \( -path "*/fs/*" -o -path "*/include/*" -o -path "*/kernel/*" -o -path "*/security/*" \) 2>/dev/null || true)
if [ -n "$REJECTS" ]; then
  fail "GKI patch has rejects"
  for r in $REJECTS; do cat "$r"; done
  exit 1
fi
find . -name "*.rej" -delete 2>/dev/null || true
pass "GKI patch applied"

if grep -q 'goto show_pad;' ./fs/proc/task_mmu.c && ! grep -q '^show_pad:' ./fs/proc/task_mmu.c; then
  sed -i -e 's/goto show_pad;/return 0;/' ./fs/proc/task_mmu.c
  pass "show_pad goto fixed"
fi

echo ""
echo "=== Phase 2: Apply safe cleanups ==="

for f in fs/susfs.c fs/stat.c fs/statfs.c fs/namei.c fs/readdir.c fs/namespace.c kernel/kallsyms.c fs/proc/task_mmu.c fs/proc/base.c; do
  [ -f "$f" ] || continue
  sed -i 's/inode->i_mapping->flags & BIT_SUS_PATH/test_bit(AS_FLAGS_SUS_PATH, \&inode->i_mapping->flags)/g' "$f"
  sed -i 's/inode->i_mapping->flags & BIT_SUS_MOUNT/test_bit(AS_FLAGS_SUS_MOUNT, \&inode->i_mapping->flags)/g' "$f"
  sed -i 's/inode->i_mapping->flags & BIT_SUS_KSTAT/test_bit(AS_FLAGS_SUS_KSTAT, \&inode->i_mapping->flags)/g' "$f"
  sed -i 's/inode->i_mapping->flags & BIT_SUS_MAPS/test_bit(AS_FLAGS_SUS_MAP, \&inode->i_mapping->flags)/g' "$f"
done
sed -i 's/filp->f_inode->i_mapping->flags & BIT_OPEN_REDIRECT/test_bit(AS_FLAGS_OPEN_REDIRECT, \&filp->f_inode->i_mapping->flags)/g' fs/namei.c
sed -i 's/base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR/test_bit(AS_FLAGS_ANDROID_DATA_ROOT_DIR, \&base->d_inode->i_mapping->flags)/g' fs/susfs.c
sed -i 's/base->d_inode->i_mapping->flags & BIT_ANDROID_SDCARD_ROOT_DIR/test_bit(AS_FLAGS_SDCARD_ROOT_DIR, \&base->d_inode->i_mapping->flags)/g' fs/susfs.c
for f in fs/proc/task_mmu.c fs/proc/base.c; do
  [ -f "$f" ] || continue
  sed -i 's/file_inode(vma->vm_file)->i_mapping->flags & BIT_SUS_MAPS/test_bit(AS_FLAGS_SUS_MAP, \&file_inode(vma->vm_file)->i_mapping->flags)/g' "$f"
done

sed -i '/^#define BIT_/d' include/linux/susfs_def.h

sed -i '/spin_lock(&inode->i_lock);/d' fs/susfs.c
sed -i '/spin_unlock(&inode->i_lock);/d' fs/susfs.c

pass "safe cleanups applied"

echo ""
echo "=== Phase 3: Grep check — no BIT_* references remain ==="

REMAINING=$(grep -rn 'BIT_SUS_\|BIT_OPEN_\|BIT_ANDROID_' --include='*.c' --include='*.h' fs/ kernel/ include/linux/susfs_def.h 2>/dev/null || true)
if [ -n "$REMAINING" ]; then
  fail "BIT_* references remain after cleanup"
  echo "$REMAINING"
else
  pass "all BIT_* references replaced"
fi

echo ""
echo "=== Phase 4: Cleanup ==="
cd "$KERNEL_DIR"
git checkout .
rm -f fs/susfs.c include/linux/susfs_def.h include/linux/susfs.h
git clean -fd fs/ include/linux/ kernel/ 2>/dev/null || true
pass "kernel tree restored"

echo ""
echo "========================================"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
  echo "  VERDICT: FIX $FAIL ISSUES BEFORE PUSHING"
  exit 1
else
  echo "  VERDICT: READY FOR CI"
  exit 0
fi
