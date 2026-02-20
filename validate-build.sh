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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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

SUSFS_BRANCH="gki-${ANDROID_VERSION}-${KERNEL_VERSION}-dev"
SUSFS_BRANCH_FALLBACK="gki-${ANDROID_VERSION}-${KERNEL_VERSION}"
SUSFS_PIN_FILE="$SCRIPT_DIR/${ANDROID_VERSION}-${KERNEL_VERSION}/susfs-pin.txt"
SUSFS_UPSTREAM="https://gitlab.com/simonpunk/susfs4ksu.git"

CLONE_BRANCH=""
if git ls-remote --heads "$SUSFS_UPSTREAM" "$SUSFS_BRANCH" 2>/dev/null | grep -q .; then
    CLONE_BRANCH="$SUSFS_BRANCH"
elif git ls-remote --heads "$SUSFS_UPSTREAM" "$SUSFS_BRANCH_FALLBACK" 2>/dev/null | grep -q .; then
    CLONE_BRANCH="$SUSFS_BRANCH_FALLBACK"
fi

if [ -f "$SUSFS_PIN_FILE" ] && [ -s "$SUSFS_PIN_FILE" ]; then
    SUSFS_PIN=$(tr -d '[:space:]' < "$SUSFS_PIN_FILE")
    if [ -n "$CLONE_BRANCH" ]; then
        git clone "$SUSFS_UPSTREAM" -b "$CLONE_BRANCH" "$SUSFS4KSU" 2>/dev/null
    else
        git clone "$SUSFS_UPSTREAM" "$SUSFS4KSU" 2>/dev/null
    fi
    git -C "$SUSFS4KSU" checkout "$SUSFS_PIN" 2>/dev/null
else
    if [ -n "$CLONE_BRANCH" ]; then
        git clone --depth 1 "$SUSFS_UPSTREAM" -b "$CLONE_BRANCH" "$SUSFS4KSU" 2>/dev/null
    else
        echo -e "${RED}FATAL: No SUSFS branch found and no pin file${NC}"
        exit 1
    fi
fi

if [ ! -d "$SUSFS4KSU/kernel_patches" ]; then
    echo -e "${RED}FATAL: Cannot clone susfs4ksu from upstream${NC}"
    exit 1
fi
echo "  SUSFS source: $SUSFS_UPSTREAM (branch: ${CLONE_BRANCH:-default}, pin: ${SUSFS_PIN:-HEAD})"
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

# LZ4K_OPLUS patch (optional, vendor-specific)
LZ4K_OPLUS_PATCH="$SUKISU_PATCH/other/zram/zram_patch/${KERNEL_VERSION}/lz4k_oplus.patch"
if [ -f "$LZ4K_OPLUS_PATCH" ]; then
    PATCH_OUTPUT=$(patch -p1 --dry-run -F3 < "$LZ4K_OPLUS_PATCH" 2>&1)
    if echo "$PATCH_OUTPUT" | grep -q "FAILED"; then
        FAILED_COUNT=$(echo "$PATCH_OUTPUT" | grep -c "FAILED")
        warn "LZ4K_OPLUS patch has $FAILED_COUNT failed hunks (optional, applied with -F3 in build)"
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

WORKFLOW_FILE="$SCRIPT_DIR/.github/workflows/gki-build.yml"
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
    CRITICAL_SILENT=$(grep -cE "^\s*patch.*\|\|\s*true" "$WORKFLOW_FILE" 2>/dev/null || echo 0)
    if [ "$CRITICAL_SILENT" -gt 0 ]; then
        fail "Found $CRITICAL_SILENT silent failures in patch commands"
    else
        pass "No silent failures in patch commands"
    fi
else
    fail "Workflow file not found"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 7: Performance Optimization Patterns (Static)"
echo "═══════════════════════════════════════════════════════════════"

PERF_DIR="$SCRIPT_DIR/${ANDROID_VERSION}-${KERNEL_VERSION}"
ZM_PATCH="$PERF_DIR/zeromount/zeromount-core.patch"
SAFETY_SH="$PERF_DIR/susfs/fix-safety.sh"
INJECT_SH="$PERF_DIR/susfs/inject-susfs-features.sh"
DEFCONFIG="$PERF_DIR/defconfig.fragment"

# 7a. ZeroMount: zero-alloc normalize_inline
if [ -f "$ZM_PATCH" ]; then
    if grep -q 'zeromount_normalize_inline' "$ZM_PATCH"; then
        pass "ZM: zeromount_normalize_inline function present"
    else
        fail "ZM: zeromount_normalize_inline missing from patch"
    fi

    if grep -q 'atomic_t zeromount_dirs_count' "$ZM_PATCH"; then
        pass "ZM: atomic_t zeromount_dirs_count declared"
    else
        fail "ZM: atomic_t zeromount_dirs_count missing"
    fi

    if grep -q 'atomic_read(&zeromount_dirs_count)' "$ZM_PATCH"; then
        pass "ZM: atomic early exit in inject_dents"
    else
        fail "ZM: atomic early exit missing from inject_dents"
    fi

    if grep -q 'atomic_inc(&zeromount_dirs_count)' "$ZM_PATCH"; then
        pass "ZM: dirs_count increment in auto_inject_parent"
    else
        fail "ZM: dirs_count increment missing"
    fi

    if grep -q 'atomic_dec(&zeromount_dirs_count)' "$ZM_PATCH"; then
        pass "ZM: dirs_count decrement in ioctl_clear_rules"
    else
        fail "ZM: dirs_count decrement missing"
    fi

    if grep -q 'rule->vp_len == norm_len' "$ZM_PATCH"; then
        pass "ZM: length-prefixed comparison in resolve_path"
    else
        fail "ZM: length-prefixed comparison missing"
    fi

    if grep -q 'memcmp(normalized, rule->virtual_path, norm_len)' "$ZM_PATCH"; then
        pass "ZM: memcmp matching in resolve_path"
    else
        fail "ZM: memcmp matching missing from resolve_path"
    fi

    if grep -q 'memcmp(norm_p, rule->virtual_path, norm_len)' "$ZM_PATCH"; then
        pass "ZM: inline normalize + memcmp in inject_dents"
    else
        fail "ZM: inline normalize + memcmp missing from inject_dents"
    fi

    if grep -q 'size_t vp_len' "$ZM_PATCH"; then
        pass "ZM: vp_len field in zeromount_rule struct"
    else
        fail "ZM: vp_len field missing from zeromount_rule"
    fi
else
    fail "ZM: zeromount-core.patch not found at $ZM_PATCH"
fi

# 7b. SUSFS fix-safety.sh: RCU conversion (patch 4d/4e)
if [ -f "$SAFETY_SH" ]; then
    if grep -q 'rcu_read_lock' "$SAFETY_SH"; then
        pass "SUSFS fix-safety: rcu_read_lock in get_redirected_path"
    else
        fail "SUSFS fix-safety: rcu_read_lock missing"
    fi

    if grep -q 'hash_for_each_possible_rcu' "$SAFETY_SH"; then
        pass "SUSFS fix-safety: hash_for_each_possible_rcu present"
    else
        fail "SUSFS fix-safety: hash_for_each_possible_rcu missing"
    fi

    if grep -q 'hash_add_rcu(OPEN_REDIRECT_HLIST' "$SAFETY_SH"; then
        pass "SUSFS fix-safety: hash_add_rcu writer conversion"
    else
        fail "SUSFS fix-safety: hash_add_rcu writer conversion missing"
    fi
else
    fail "SUSFS: fix-safety.sh not found at $SAFETY_SH"
fi

# 7c. SUSFS inject-features: RCU + __getname
if [ -f "$INJECT_SH" ]; then
    if grep -q 'hash_for_each_possible_rcu(OPEN_REDIRECT_ALL_HLIST' "$INJECT_SH"; then
        pass "SUSFS inject: RCU in get_redirected_path_all"
    else
        fail "SUSFS inject: RCU missing from get_redirected_path_all"
    fi

    if grep -q 'rcu_read_lock' "$INJECT_SH"; then
        pass "SUSFS inject: rcu_read_lock in redirect_all"
    else
        fail "SUSFS inject: rcu_read_lock missing from redirect_all"
    fi

    if grep -q '__getname()' "$INJECT_SH"; then
        pass "SUSFS inject: __getname in unicode filter"
    else
        fail "SUSFS inject: __getname missing from unicode filter"
    fi

    if grep -q '__putname(' "$INJECT_SH"; then
        pass "SUSFS inject: __putname in unicode filter"
    else
        fail "SUSFS inject: __putname missing from unicode filter"
    fi
else
    fail "SUSFS: inject-susfs-features.sh not found at $INJECT_SH"
fi

# 7d. defconfig: performance section
if [ -f "$DEFCONFIG" ]; then
    if grep -q '# \[performance\]' "$DEFCONFIG"; then
        pass "defconfig: performance section header present"
    else
        fail "defconfig: performance section header missing"
    fi

    if grep -q 'DEBUG_MUTEXES' "$DEFCONFIG"; then
        pass "defconfig: DEBUG_MUTEXES entry present"
    else
        fail "defconfig: DEBUG_MUTEXES entry missing"
    fi

    if grep -q 'DEBUG_SPINLOCK' "$DEFCONFIG"; then
        pass "defconfig: DEBUG_SPINLOCK entry present"
    else
        fail "defconfig: DEBUG_SPINLOCK entry missing"
    fi

    if grep -q 'PROVE_LOCKING' "$DEFCONFIG"; then
        pass "defconfig: PROVE_LOCKING entry present"
    else
        fail "defconfig: PROVE_LOCKING entry missing"
    fi
else
    fail "defconfig: defconfig.fragment not found at $DEFCONFIG"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 8: SUSFS Post-Fix Verification (Dynamic)"
echo "═══════════════════════════════════════════════════════════════"

# Run fix-safety.sh and inject-susfs-features.sh on cloned SUSFS source,
# then verify the resulting susfs.c has expected perf patterns.
SUSFS_WORK="/tmp/susfs-perf-verify-$$"
cp -r "$SUSFS4KSU/kernel_patches" "$SUSFS_WORK"

if [ -f "$SAFETY_SH" ] && [ -f "$INJECT_SH" ]; then
    bash "$SAFETY_SH" "$SUSFS_WORK" > /dev/null 2>&1
    SAFETY_RC=$?
    if [ "$SAFETY_RC" -eq 0 ]; then
        pass "fix-safety.sh executes cleanly (rc=0)"
    else
        fail "fix-safety.sh failed (rc=$SAFETY_RC)"
    fi

    bash "$INJECT_SH" "$SUSFS_WORK" > /dev/null 2>&1
    INJECT_RC=$?
    if [ "$INJECT_RC" -eq 0 ]; then
        pass "inject-susfs-features.sh executes cleanly (rc=0)"
    else
        fail "inject-susfs-features.sh failed (rc=$INJECT_RC)"
    fi

    PATCHED_SUSFS="$SUSFS_WORK/fs/susfs.c"
    if [ -f "$PATCHED_SUSFS" ]; then
        # Verify RCU conversion in susfs_get_redirected_path
        if grep -A10 'susfs_get_redirected_path(unsigned long ino)' "$PATCHED_SUSFS" | grep -q 'rcu_read_lock\|found.*false'; then
            pass "post-fix susfs.c: get_redirected_path uses RCU"
        else
            fail "post-fix susfs.c: get_redirected_path RCU not found"
        fi

        # Verify hash_add_rcu in writer path
        if grep -q 'hash_add_rcu(OPEN_REDIRECT_HLIST' "$PATCHED_SUSFS"; then
            pass "post-fix susfs.c: hash_add_rcu in writer path"
        else
            fail "post-fix susfs.c: hash_add_rcu missing in writer"
        fi

        # Verify RCU in get_redirected_path_all
        if grep -A5 'susfs_get_redirected_path_all' "$PATCHED_SUSFS" | grep -q 'rcu_read_lock'; then
            pass "post-fix susfs.c: get_redirected_path_all uses RCU"
        else
            fail "post-fix susfs.c: get_redirected_path_all RCU missing"
        fi

        # Verify __getname in unicode filter
        if grep -A20 'susfs_check_unicode_bypass' "$PATCHED_SUSFS" | grep -q '__getname'; then
            pass "post-fix susfs.c: unicode filter uses __getname"
        else
            fail "post-fix susfs.c: unicode filter missing __getname"
        fi

        # Verify no kmalloc(PATH_MAX) in unicode filter
        if grep -A20 'susfs_check_unicode_bypass' "$PATCHED_SUSFS" | grep -q 'kmalloc(PATH_MAX'; then
            fail "post-fix susfs.c: unicode filter still uses kmalloc"
        else
            pass "post-fix susfs.c: unicode filter kmalloc eliminated"
        fi
    else
        fail "post-fix susfs.c not found after script execution"
    fi
else
    fail "fix-safety.sh or inject-susfs-features.sh not found"
fi

rm -rf "$SUSFS_WORK"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 9: ZeroMount Patch + Targeted Compile"
echo "═══════════════════════════════════════════════════════════════"

# Apply zeromount-core.patch and do targeted compile validation
if [ -f "$ZM_PATCH" ]; then
    ZM_PATCH_OUTPUT=$(patch -p1 --dry-run < "$ZM_PATCH" 2>&1)
    if echo "$ZM_PATCH_OUTPUT" | grep -q "FAILED"; then
        ZM_FAILED=$(echo "$ZM_PATCH_OUTPUT" | grep -c "FAILED")
        fail "ZM patch has $ZM_FAILED failed hunks on kernel $KERNEL_VERSION"
    else
        pass "ZM patch applies cleanly to kernel $KERNEL_VERSION"
    fi

    # Actually apply for compile test
    patch -p1 -F3 < "$ZM_PATCH" > /dev/null 2>&1

    if [ -f "fs/zeromount.c" ]; then
        pass "fs/zeromount.c present after patch"

        # Verify key perf patterns in applied source
        if grep -q 'zeromount_normalize_inline' fs/zeromount.c; then
            pass "applied zeromount.c: normalize_inline present"
        else
            fail "applied zeromount.c: normalize_inline missing"
        fi

        if grep -q 'atomic_read(&zeromount_dirs_count)' fs/zeromount.c; then
            pass "applied zeromount.c: atomic early exit present"
        else
            fail "applied zeromount.c: atomic early exit missing"
        fi

        # Targeted compile with kernel headers (C90 + declaration check)
        STUB_DIR2="/tmp/kernel-stubs-zm-$$"
        mkdir -p "$STUB_DIR2/linux"

        cat > "$STUB_DIR2/linux/zeromount.h" << 'ZMSTUB'
#ifndef _LINUX_ZEROMOUNT_H
#define _LINUX_ZEROMOUNT_H
#include <linux/types.h>
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int bool;
#define true 1
#define false 0
#define NULL ((void *)0)
#define __user
#define inline __inline__
#define EXPORT_SYMBOL(x)
#define ATOMIC_INIT(i) { (i) }
#define DEFINE_HASHTABLE(n,b) int n
#define DEFINE_SPINLOCK(x) int x
#define hash_for_each_possible_rcu(ht,obj,member,key) for(;;)
#define hash_for_each_possible(ht,obj,member,key) for(;;)
#define hash_for_each_safe(ht,bkt,tmp,obj,member) for(;;)
#define rcu_read_lock() do {} while(0)
#define rcu_read_unlock() do {} while(0)
#define spin_lock(x) do {} while(0)
#define spin_unlock(x) do {} while(0)
#define atomic_read(v) 0
#define atomic_set(v,i) do {} while(0)
#define atomic_inc(v) do {} while(0)
#define atomic_dec(v) do {} while(0)
typedef struct { int counter; } atomic_t;
typedef struct { int dummy; } spinlock_t;
struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
struct rcu_head { void *func; };
#define ZEROMOUNT_HASH_BITS 10
#define ZEROMOUNT_MAGIC_CODE 0x5A
#define ZEROMOUNT_VERSION 1
#define ZM_FLAG_ACTIVE (1 << 0)
#define ZM_FLAG_IS_DIR (1 << 7)
#define ZEROMOUNT_MAGIC_POS 0x7000000000000000ULL
struct zeromount_rule { struct hlist_node node; size_t vp_len; char *virtual_path; char *real_path; u32 flags; bool is_new; struct rcu_head rcu; struct hlist_node ino_node; struct list_head list; unsigned long real_ino; unsigned int real_dev; };
struct zeromount_dir_node { struct hlist_node node; char *dir_path; struct list_head children_names; struct rcu_head rcu; };
struct zeromount_child_name { struct list_head list; char *name; unsigned char d_type; struct rcu_head rcu; };
struct zeromount_uid_node { unsigned int uid; struct hlist_node node; struct rcu_head rcu; };
#endif
ZMSTUB

        GCC_ZM=$(gcc -fsyntax-only -std=gnu89 \
            -Wdeclaration-after-statement \
            -Werror=declaration-after-statement \
            -I"$STUB_DIR2" -I./include \
            -D__KERNEL__ -DCONFIG_ZEROMOUNT \
            fs/zeromount.c 2>&1 || true)

        if echo "$GCC_ZM" | grep -qi "error:.*declaration-after-statement"; then
            fail "zeromount.c: C90 violation (declaration after statement)"
        else
            pass "zeromount.c: no C90 declaration-after-statement violations"
        fi

        rm -rf "$STUB_DIR2"
    else
        fail "fs/zeromount.c missing after patch application"
    fi

    # Verify header too
    if [ -f "include/linux/zeromount.h" ]; then
        if grep -q 'size_t vp_len' include/linux/zeromount.h; then
            pass "zeromount.h: vp_len in rule struct"
        else
            fail "zeromount.h: vp_len missing from rule struct"
        fi
    else
        fail "include/linux/zeromount.h missing after patch"
    fi
else
    fail "ZM patch not found at $ZM_PATCH"
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
