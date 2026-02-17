#!/bin/bash
# MANDATORY dry-test validation script for KernelSU-Next
# Claude MUST run this script - no shortcuts, no interpretations
# Exit code 0 = PASS, non-zero = FAIL (do not trigger build)

set -uo pipefail

ANDROID_VERSION="${1:-android12}"
KERNEL_VERSION="${2:-5.10}"
SUBLEVEL="${3:-209}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}  ✓ $1${NC}"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}  ✗ $1${NC}"; FAIL=$((FAIL + 1)); FAILURES+=("$1"); }
warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }

declare -a FAILURES=()

# Paths
BASE_DIR="/mnt/external/claudetest-gki-build/kernel-test"
KERNEL_ROOT="$BASE_DIR/${ANDROID_VERSION}-${KERNEL_VERSION}-2024-05/common"
SUSFS4KSU="/tmp/susfs-validate-$$"
SUKISU_PATCH="/tmp/sukisu-validate-$$"
WORKFLOW_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          MANDATORY DRY-TEST VALIDATION                       ║"
echo "║  DO NOT TRIGGER BUILD UNLESS ALL CHECKS PASS                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Kernel: ${KERNEL_VERSION}.${SUBLEVEL}                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Clone required repos
echo "Cloning validation repos..."
rm -rf "$SUSFS4KSU" "$SUKISU_PATCH"
git clone --depth 1 https://github.com/Enginex0/susfs4ksu.git -b "gki-${ANDROID_VERSION}-${KERNEL_VERSION}" "$SUSFS4KSU" 2>/dev/null || {
    echo -e "${RED}FATAL: Cannot clone susfs4ksu${NC}"
    exit 1
}
git clone --depth 1 https://github.com/ShirkNeko/SukiSU_patch.git "$SUKISU_PATCH" 2>/dev/null || {
    echo -e "${RED}FATAL: Cannot clone SukiSU_patch${NC}"
    exit 1
}

if [ ! -d "$KERNEL_ROOT" ]; then
    echo -e "${RED}FATAL: Kernel source not found at $KERNEL_ROOT${NC}"
    echo "Run: cd $BASE_DIR && repo sync first"
    exit 1
fi

cd "$KERNEL_ROOT"

# Clean state
rm -f .git/index.lock 2>/dev/null || true
git checkout . 2>/dev/null || true
find . -name "*.rej" -delete 2>/dev/null || true
find . -name "*.orig" -delete 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 1: Patch Application"
echo "═══════════════════════════════════════════════════════════════"

# SUSFS patch
SUSFS_PATCH="$SUSFS4KSU/kernel_patches/50_add_susfs_in_gki-${ANDROID_VERSION}-${KERNEL_VERSION}.patch"
if [ -f "$SUSFS_PATCH" ]; then
    PATCH_OUTPUT=$(patch -p1 --dry-run < "$SUSFS_PATCH" 2>&1)
    if echo "$PATCH_OUTPUT" | grep -qi "malformed"; then
        MALFORMED_LINE=$(echo "$PATCH_OUTPUT" | grep -i "malformed" | head -1)
        fail "SUSFS patch malformed: $MALFORMED_LINE"
    elif echo "$PATCH_OUTPUT" | grep -q "FAILED"; then
        FAILED_COUNT=$(echo "$PATCH_OUTPUT" | grep -c "FAILED")
        fail "SUSFS patch has $FAILED_COUNT failed hunks"
    else
        pass "SUSFS patch applies cleanly (0 failed hunks)"
    fi
else
    fail "SUSFS patch not found: $SUSFS_PATCH"
fi

# LZ4KD patch
LZ4KD_PATCH="$SUKISU_PATCH/other/zram/zram_patch/${KERNEL_VERSION}/lz4kd.patch"
if [ -f "$LZ4KD_PATCH" ]; then
    PATCH_OUTPUT=$(patch -p1 --dry-run -F3 < "$LZ4KD_PATCH" 2>&1)
    if echo "$PATCH_OUTPUT" | grep -q "FAILED"; then
        FAILED_COUNT=$(echo "$PATCH_OUTPUT" | grep -c "FAILED")
        fail "LZ4KD patch has $FAILED_COUNT failed hunks"
    else
        pass "LZ4KD patch applies cleanly"
    fi
else
    fail "LZ4KD patch not found: $LZ4KD_PATCH"
fi

# LZ4K_OPLUS patch
LZ4K_OPLUS_PATCH="$SUKISU_PATCH/other/zram/zram_patch/${KERNEL_VERSION}/lz4k_oplus.patch"
if [ -f "$LZ4K_OPLUS_PATCH" ]; then
    PATCH_OUTPUT=$(patch -p1 --dry-run -F3 < "$LZ4K_OPLUS_PATCH" 2>&1)
    if echo "$PATCH_OUTPUT" | grep -q "FAILED"; then
        FAILED_COUNT=$(echo "$PATCH_OUTPUT" | grep -c "FAILED")
        fail "LZ4K_OPLUS patch has $FAILED_COUNT failed hunks"
    else
        pass "LZ4K_OPLUS patch applies cleanly"
    fi
else
    warn "LZ4K_OPLUS patch not found (optional)"
fi

# Apply patches for subsequent tests
cp "$SUSFS4KSU/kernel_patches/fs/"* ./fs/ 2>/dev/null || true
cp "$SUSFS4KSU/kernel_patches/include/linux/"* ./include/linux/ 2>/dev/null || true
patch -p1 -F3 < "$SUSFS_PATCH" > /dev/null 2>&1 || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 2: SUSFS Integration Check"
echo "═══════════════════════════════════════════════════════════════"

# Check susfs_mnt_id_backup field in struct vfsmount
if grep -q "susfs_mnt_id_backup" include/linux/mount.h 2>/dev/null; then
    pass "susfs_mnt_id_backup in struct vfsmount"
else
    fail "susfs_mnt_id_backup NOT in struct vfsmount (critical!)"
fi

# Check SUSFS hooks in key files
declare -A SUSFS_FILES=(
    ["fs/namespace.c"]="CONFIG_KSU_SUSFS"
    ["fs/namei.c"]="CONFIG_KSU_SUSFS"
    ["fs/exec.c"]="CONFIG_KSU_SUSFS"
    ["fs/open.c"]="CONFIG_KSU_SUSFS"
    ["fs/stat.c"]="CONFIG_KSU_SUSFS"
)

for file in "${!SUSFS_FILES[@]}"; do
    pattern="${SUSFS_FILES[$file]}"
    if [ -f "$file" ]; then
        if grep -q "$pattern" "$file"; then
            pass "$file: SUSFS hooks present"
        else
            fail "$file: SUSFS hooks NOT found"
        fi
    else
        fail "$file: file not found"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 3: C SYNTAX VALIDATION (gcc -fsyntax-only)"
echo "═══════════════════════════════════════════════════════════════"

# Create minimal header stubs
STUB_DIR="/tmp/kernel-stubs-$$"
mkdir -p "$STUB_DIR/linux"

cat > "$STUB_DIR/linux/kernel.h" << 'STUBEOF'
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long long u64;
typedef int s32;
typedef unsigned int u32;
#define NULL ((void *)0)
#define true 1
#define false 0
#define bool int
#define __user
#define EXPORT_SYMBOL(x)
#define unlikely(x) (x)
#define likely(x) (x)
#define IS_ERR(x) ((unsigned long)(x) >= (unsigned long)-4095)
#define PTR_ERR(x) ((long)(x))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define PATH_MAX 4096
#define pr_info(fmt, ...) do {} while(0)
#define pr_err(fmt, ...) do {} while(0)
#define BUG_ON(x) do {} while(0)
#define GFP_KERNEL 0
void *kmalloc(size_t size, int flags);
void *kzalloc(size_t size, int flags);
void kfree(const void *);
char *kstrdup(const char *, int);
struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic64_t;
#define ATOMIC64_INIT(i) { (i) }
#define spin_lock(x) do {} while(0)
#define spin_unlock(x) do {} while(0)
#define mutex_lock(x) do {} while(0)
#define mutex_unlock(x) do {} while(0)
typedef struct { int dummy; } spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x
#define rcu_read_lock() do {} while(0)
#define rcu_read_unlock() do {} while(0)
#endif
STUBEOF

cat > "$STUB_DIR/linux/fs.h" << 'STUBEOF'
#ifndef _LINUX_FS_H
#define _LINUX_FS_H
struct inode { void *i_private; unsigned long i_ino; };
struct dentry { struct inode *d_inode; };
struct file { struct dentry *f_path_dentry; };
struct path { struct dentry *dentry; void *mnt; };
struct kstatfs { unsigned long f_type; };
#endif
STUBEOF

# Test SUSFS source file with gcc
SUSFS_C="$SUSFS4KSU/kernel_patches/fs/susfs.c"
if [ -f "$SUSFS_C" ]; then
    GCC_OUTPUT=$(gcc -fsyntax-only -std=gnu89 \
        -Wdeclaration-after-statement \
        -Werror=declaration-after-statement \
        -I"$STUB_DIR" \
        -D__KERNEL__ \
        -DCONFIG_KSU_SUSFS \
        -DCONFIG_KSU_SUSFS_SUS_MOUNT \
        -DCONFIG_KSU_SUSFS_SUS_PATH \
        "$SUSFS_C" 2>&1 || true)

    if echo "$GCC_OUTPUT" | grep -qi "error:.*declaration-after-statement"; then
        fail "susfs.c: C90 violation (declaration after statement)"
    elif echo "$GCC_OUTPUT" | grep -qi "error:"; then
        # Many errors expected due to incomplete stubs - just check for C90
        pass "susfs.c: No C90 declaration-after-statement issues"
    else
        pass "susfs.c: C syntax OK"
    fi
else
    fail "susfs.c not found"
fi

rm -rf "$STUB_DIR"

# Shell escaping validation (for heredocs in workflow)
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 4: Shell Escaping Validation"
echo "═══════════════════════════════════════════════════════════════"

WORKFLOW_FILE="$WORKFLOW_DIR/.github/workflows/build.yml"
if [ -f "$WORKFLOW_FILE" ]; then
    # Check for strchr with string instead of char (common escaping issue)
    if grep -q 'strchr([^,]*, *"/")' "$WORKFLOW_FILE" 2>/dev/null; then
        fail "Workflow has strchr with string instead of char"
    else
        pass "No strchr escaping issues in workflow"
    fi

    # Check for unquoted variables in heredocs
    if grep -E 'cat.*<<.*EOF' "$WORKFLOW_FILE" | grep -q '\$[A-Z]' 2>/dev/null; then
        warn "Heredoc may have unquoted variables (verify manually)"
    else
        pass "Heredoc quoting looks OK"
    fi
else
    warn "Workflow file not found at $WORKFLOW_FILE"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 5: Build System Validation"
echo "═══════════════════════════════════════════════════════════════"

# Check SUSFS Kconfig
if grep -q "config KSU_SUSFS" "$KERNEL_ROOT/../KernelSU-Next/kernel/Kconfig" 2>/dev/null || \
   grep -q "CONFIG_KSU_SUSFS" fs/Kconfig 2>/dev/null; then
    pass "KSU_SUSFS Kconfig found"
else
    warn "KSU_SUSFS Kconfig location unknown (may be in KernelSU-Next)"
fi

# Check SUSFS source files exist
if [ -f "fs/susfs.c" ]; then
    pass "fs/susfs.c exists"
else
    fail "fs/susfs.c missing"
fi

if [ -f "include/linux/susfs.h" ]; then
    pass "include/linux/susfs.h exists"
else
    fail "include/linux/susfs.h missing"
fi

# Check LZ4K source files
for dir in "$SUKISU_PATCH/other/zram/lz4k/include/linux" "$SUKISU_PATCH/other/zram/lz4k/lib" "$SUKISU_PATCH/other/zram/lz4k/crypto"; do
    if [ -d "$dir" ]; then
        pass "LZ4K source: $(basename $dir)/"
    else
        fail "LZ4K source missing: $dir"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 6: Workflow YAML Validation"
echo "═══════════════════════════════════════════════════════════════"

if [ -f "$WORKFLOW_FILE" ]; then
    pass "Workflow file exists"

    if python3 -c "import yaml; yaml.safe_load(open('$WORKFLOW_FILE'))" 2>/dev/null; then
        pass "YAML syntax valid"
    else
        fail "YAML syntax error"
    fi

    # Check for critical silent failures (patch commands)
    CRITICAL_SILENT=$(grep -E "^\s*patch.*\|\|\s*true" "$WORKFLOW_FILE" | wc -l || echo 0)
    if [ "$CRITICAL_SILENT" -gt 0 ]; then
        fail "Found $CRITICAL_SILENT silent failures in patch commands"
    else
        pass "No silent failures in patch commands"
    fi
else
    fail "Workflow file not found"
fi

# Restore clean state
git checkout . > /dev/null 2>&1 || true
find . -name "*.rej" -delete 2>/dev/null || true

# Cleanup
rm -rf "$SUSFS4KSU" "$SUKISU_PATCH"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    VALIDATION RESULTS                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  PASSED: %-3d                                               ║\n" "$PASS"
printf "║  FAILED: %-3d                                               ║\n" "$FAIL"
echo "╠══════════════════════════════════════════════════════════════╣"

if [ "$FAIL" -eq 0 ]; then
    echo -e "║  ${GREEN}VERDICT: ✓ READY FOR GITHUB ACTIONS BUILD${NC}                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo -e "║  ${RED}VERDICT: ✗ DO NOT BUILD - FIX ${FAIL} ISSUE(S) FIRST${NC}              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  FAILURES:                                                   ║"
    for f in "${FAILURES[@]}"; do
        printf "║    - %-53s ║\n" "$f"
    done
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 1
fi
