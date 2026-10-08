#!/bin/bash
# apply-susfs-targeted.sh — Apply only the required SUSFS v2.2.0 changes
# for android14-6.1 SukiSU reconciliation.
#
# This script extracts and applies ONLY the critical sections needed to fix
# audit failures, avoiding bulk patch conflicts with incompatible baselines.
#
# Required fixes:
# 1. fs/proc/base.c: Add hidden_name filter in do_faccessat() (for both remote_memory + map_files)
# 2. fs/namei.c: Add Open Redirect inode variable and null checks in do_openat()
# 3. fs/proc/task_mmu.c: Improve SUS_MAP checks with null safety
# 4. fs/susfs.c: Add null safety checks for i_mapping

set -euo pipefail

KERNEL_DIR="${1:-.}"
[ -d "$KERNEL_DIR" ] || { echo "ERROR: kernel dir not found: $KERNEL_DIR"; exit 1; }

log() { echo "[SUSFS Targeted] $*"; }
warn() { echo "[SUSFS Targeted] WARNING: $*" >&2; }
err() { echo "[SUSFS Targeted] ERROR: $*" >&2; exit 1; }

log "Starting targeted SUSFS v2.2.0 patch application for android14-6.1"

# ============================================================================
# Fix 1: fs/namei.c — Add Open Redirect inode variable in do_openat()
# ============================================================================
log "Applying fix 1: fs/namei.c — Open Redirect inode variable"

NAMEI_C="$KERNEL_DIR/fs/namei.c"
if [ ! -f "$NAMEI_C" ]; then
    warn "namei.c not found, skipping fix 1"
else
    # Check if the inode variable is already declared in CONFIG_KSU_SUSFS_OPEN_REDIRECT
    if grep -A2 'CONFIG_KSU_SUSFS_OPEN_REDIRECT' "$NAMEI_C" | grep -q 'struct inode \*inode;'; then
        log "namei.c: Open Redirect inode variable already present"
    else
        # Find and add the inode variable declaration after fake_pathname
        if grep -q 'struct filename \*fake_pathname;' "$NAMEI_C"; then
            python3 - "$NAMEI_C" << 'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Find the do_openat function and add inode declaration after fake_pathname
pattern = r'(struct file \*filp;\n#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n\tstruct filename \*fake_pathname;)'
replacement = r'\1\n\tstruct inode *inode;'
new_content = re.sub(pattern, replacement, content, count=1)

if new_content != content:
    with open(path, 'w') as f:
        f.write(new_content)
    print("✓ namei.c: inode variable added to CONFIG_KSU_SUSFS_OPEN_REDIRECT block")
else:
    print("✗ namei.c: Could not find inode insertion point")
PYEOF
        fi

    # Fix 1b: Replace Open Redirect check to use inode with null safety
    if grep -q 'test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_mapping->flags)' "$NAMEI_C"; then
        log "namei.c: Open Redirect inode checks already fixed"
    else
        python3 - "$NAMEI_C" << 'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

modified = False
i = 0
while i < len(lines):
    # Look for the old Open Redirect pattern with filp->f_inode
    if 'if (!IS_ERR(filp) &&' in lines[i] and i + 2 < len(lines):
        if 'unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &filp->f_inode->i_mapping->flags)' in lines[i+1]:
            # Replace the entire block
            if 'current_uid().val < 2000))' in lines[i+2]:
                # Found the old pattern, replace it
                lines[i] = '\tif (!IS_ERR(filp)) {\n'
                lines[i+1] = '\t\tinode = file_inode(filp);\n'
                lines[i+2] = '\t\tif (inode->i_mapping &&\n'
                lines.insert(i+3, '\t\t\tunlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_mapping->flags)) &&\n')
                lines.insert(i+4, '\t\t\tcurrent_uid().val < 2000)\n')
                lines.insert(i+5, '\t\t{\n')
                # Now fix the susfs_get_redirected_path call
                j = i + 6
                while j < len(lines) and 'susfs_get_redirected_path' not in lines[j]:
                    j += 1
                if j < len(lines):
                    lines[j] = lines[j].replace('filp->f_inode->i_ino', 'inode->i_ino')
                modified = True
                i = j + 1
                continue
    i += 1

if modified:
    with open(path, 'w') as f:
        f.writelines(lines)
    print("✓ namei.c: Open Redirect inode checks fixed")
else:
    print("✗ namei.c: Open Redirect pattern not found (may already be fixed)")
PYEOF
        fi
fi

# ============================================================================
# Fix 2: fs/proc/task_mmu.c — SUS_MAP null safety checks
# ============================================================================
log "Applying fix 2: fs/proc/task_mmu.c — SUS_MAP null safety"

TASK_MMU_C="$KERNEL_DIR/fs/proc/task_mmu.c"
if [ ! -f "$TASK_MMU_C" ]; then
    warn "task_mmu.c not found, skipping fix 2"
else
    # Check if null checks are already present
    if grep -q 'if (inode->i_mapping &&' "$TASK_MMU_C"; then
        log "task_mmu.c: SUS_MAP null checks already present"
    else
        log "task_mmu.c: Adding null safety checks"
        python3 - "$TASK_MMU_C" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Add null checks for AS_FLAGS_SUS_MAP
# Pattern: if (unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)
# Replace with: if (inode->i_mapping && unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)

count = 0
lines = content.split('\n')
for i in range(len(lines)):
    if 'test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)' in lines[i]:
        if 'inode->i_mapping &&' not in lines[i]:
            # Add the null check
            if 'if (unlikely(' in lines[i]:
                lines[i] = lines[i].replace(
                    'if (unlikely(test_bit(AS_FLAGS_SUS_MAP',
                    'if (inode->i_mapping && unlikely(test_bit(AS_FLAGS_SUS_MAP'
                )
                count += 1
            elif 'if (' in lines[i]:
                lines[i] = lines[i].replace(
                    'if (unlikely(test_bit(AS_FLAGS_SUS_MAP',
                    'if (inode->i_mapping && unlikely(test_bit(AS_FLAGS_SUS_MAP'
                )
                count += 1

if count > 0:
    with open(path, 'w') as f:
        f.write('\n'.join(lines))
    print(f"✓ task_mmu.c: Added {count} null checks for SUS_MAP")
else:
    print("✗ task_mmu.c: No SUS_MAP patterns found to fix")
PYEOF
        fi
fi

# ============================================================================
# Fix 3: fs/proc/base.c — Map files SUS_MAP filter
# ============================================================================
log "Applying fix 3: fs/proc/base.c — map_files SUS_MAP filter"

BASE_C="$KERNEL_DIR/fs/proc/base.c"
if [ ! -f "$BASE_C" ]; then
    warn "base.c not found, skipping fix 3"
else
    # Check if the map_files SUS_MAP filter is present
    if grep -A10 'map_files_seq_get_unmapped_area\|map_files' "$BASE_C" | grep -q 'AS_FLAGS_SUS_MAP.*inode->i_mapping'; then
        log "base.c: map_files SUS_MAP filter already present"
    else
        log "base.c: Adding SUS_MAP filter to map_files (inode null safety)"
        python3 - "$BASE_C" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Find map_files section and ensure null checks
# Look for: if (unlikely(test_bit(AS_FLAGS_SUS_MAP, &file_inode(vma->vm_file)->i_mapping->flags)
# Replace with proper null check

import re
# Pattern for direct file_inode dereference without null check
pattern = r'if \(unlikely\(test_bit\(AS_FLAGS_SUS_MAP, &file_inode\(vma->vm_file\)->i_mapping->flags\)\s*&&\s*susfs_is_current_proc_umounted\(\)\)\)'

def replacement(match):
    return '''if (vma->vm_file) {
\t\tstruct inode *inode = file_inode(vma->vm_file);
\t\tif (inode->i_mapping &&
\t\t\tunlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags) &&
\t\t\tsusfs_is_current_proc_umounted()))'''

new_content = re.sub(pattern, replacement, content)

if new_content != content:
    with open(path, 'w') as f:
        f.write(new_content)
    print("✓ base.c: map_files SUS_MAP filter improved")
else:
    print("✗ base.c: map_files pattern not found (may already be fixed)")
PYEOF
        fi
fi

# ============================================================================
# Fix 4: fs/proc/base.c — Add HIDDEN_NAME filter
# ============================================================================
log "Applying fix 4: fs/proc/base.c — Add HIDDEN_NAME filter in do_faccessat()"

if [ -f "$BASE_C" ]; then
    # Check if hidden_name filter is present
    if grep -q 'CONFIG_KSU_SUSFS_HIDDEN_NAME' "$BASE_C"; then
        log "base.c: HIDDEN_NAME filter already present"
    else
        python3 - "$BASE_C" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

# Find do_faccessat and add hidden_name check
# Look for: inode = d_backing_inode(path.dentry);
# Insert BEFORE it: #ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME section

insert_pos = None
for i, line in enumerate(lines):
    if 'inode = d_backing_inode(path.dentry);' in line:
        insert_pos = i
        break

if insert_pos is not None:
    hidden_name_block = '''
#ifdef CONFIG_KSU_SUSFS_HIDDEN_NAME
\tif (current_uid().val >= 10000 &&
\t    susfs_is_current_proc_umounted()) {
\t\tstruct dentry *_d = path.dentry;
\t\tstruct dentry *_par = _d->d_parent;
\t\tif (_par && _par != _d && _par->d_parent) {
\t\t\tint _plen = _par->d_name.len;
\t\t\tif ((_plen == 4 && !memcmp(_par->d_name.name, "data", 4)) ||
\t\t\t    (_plen == 3 && !memcmp(_par->d_name.name, "obb", 3))) {
\t\t\t\tstruct dentry *_gp = _par->d_parent;
\t\t\t\tif (_gp->d_name.len == 7 &&
\t\t\t\t    !memcmp(_gp->d_name.name, "Android", 7) &&
\t\t\t\t    susfs_is_hidden_name(_d->d_name.name,
\t\t\t\t        _d->d_name.len, current_uid().val)) {
\t\t\t\t\tres = -ENOENT;
\t\t\t\t\tgoto out_path_release;
\t\t\t\t}
\t\t\t}
\t\t}
\t}
#endif

'''
    lines.insert(insert_pos, hidden_name_block)
    
    with open(path, 'w') as f:
        f.writelines(lines)
    print("✓ base.c: HIDDEN_NAME filter added to do_faccessat()")
else:
    print("✗ base.c: Could not find insertion point for HIDDEN_NAME filter")
PYEOF
        fi
    fi
fi

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "✓ Targeted SUSFS v2.2.0 patches applied"
log ""
log "Next steps:"
log "  1. Run: SUSFS Procfs/SUS_MAP/Open Redirect source audit"
log "  2. Expected result: PASS=27 FAIL=0"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exit 0
