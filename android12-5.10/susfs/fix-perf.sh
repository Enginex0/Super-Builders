#!/bin/bash
# fix-perf.sh - VFS performance patches for SUSFS
#
# Patches applied in two phases:
#   Phase A: GKI patch file (before patch is applied to kernel tree)
#   Phase B: susfs_def.h and susfs.c (after sources are copied to kernel tree)
#
# Sections:
#   P1 - Inline fast-path for link_path_walk SUS_PATH check
#   P2 - Two-level readdir guard (parent flag + gated ilookup)
#   P5 - Remove RCU retry from OPEN_REDIRECT redirect path
#   F6 - Unified susfs_should_hide_dirent() function
#   M2 - Hidden-ino hash table replacing ilookup in filldir
#   M4 - Extend kallsyms filter to hide zeromount symbols
#
# 5.10 readdir.c has 5 filldir variants (vs 3 in 5.15):
#   fillonedir      (readdir_callback)
#   filldir         (getdents_callback)
#   filldir64       (getdents_callback64)
#   compat_fillonedir (compat_readdir_callback)
#   compat_filldir  (compat_getdents_callback)
#
# Usage: ./fix-perf.sh <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>

set -euo pipefail

KERNEL_DIR="$1"
SUSFS_DIR="$2"
GKI_PATCH="$3"

if [ -z "$KERNEL_DIR" ] || [ -z "$SUSFS_DIR" ] || [ -z "$GKI_PATCH" ]; then
    echo "Usage: $0 <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>"
    exit 1
fi

if [ ! -f "$GKI_PATCH" ]; then
    echo "FATAL: GKI patch not found: $GKI_PATCH"
    exit 1
fi

SUSFS_DEF_H="$SUSFS_DIR/include/linux/susfs_def.h"
SUSFS_C="$SUSFS_DIR/fs/susfs.c"

echo "=== fix-perf ==="
fix_count=0


# =============================================================================
# Phase A: GKI patch file modifications (BEFORE patch is applied)
# =============================================================================

# --- P1: Inline fast-path for link_path_walk SUS_PATH check ---
# Replace the susfs_is_inode_sus_path() function call with inline checks
# that skip the FUSE and UID ownership overhead in the hot path.
# Target: the ONLY instance with "dentry = nd->path.dentry;" context.

if grep -A1 'dentry = nd->path.dentry;' "$GKI_PATCH" 2>/dev/null | grep -q 'susfs_is_inode_sus_path(dentry->d_inode)'; then
    echo "[+] P1: Inlining fast-path for link_path_walk SUS_PATH check"
    awk '
    /^\+[\t]+if \(dentry->d_inode && susfs_is_inode_sus_path\(dentry->d_inode\)\)/ {
        # Only match if we saw the nd->path.dentry context on the previous line
        if (prev_is_nd_path) {
            print "+\t\tif (dentry->d_inode &&"
            print "+\t\t    current_uid().val >= 10000 &&"
            print "+\t\t    susfs_is_current_proc_umounted() &&"
            print "+\t\t    unlikely(test_bit(AS_FLAGS_SUS_PATH,"
            print "+\t\t\t\t      &dentry->d_inode->i_mapping->flags))) {"
            prev_is_nd_path = 0
            next
        }
    }
    { prev_is_nd_path = ($0 ~ /^\+[\t]+dentry = nd->path\.dentry;/); print }
    ' "$GKI_PATCH" > "$GKI_PATCH.tmp" && mv "$GKI_PATCH.tmp" "$GKI_PATCH"
    ((fix_count++)) || true
else
    echo "[=] P1: link_path_walk fast-path already applied or not found"
fi


# --- P5: Remove RCU retry from OPEN_REDIRECT redirect path ---
# The redirected file is always a real file at a known location.
# Skip the RCU fast-path attempt and ESTALE retry — go straight to ref-walk.

if grep -A2 'set_nameidata(&nd, dfd, fake_pathname);' "$GKI_PATCH" 2>/dev/null | grep -q 'LOOKUP_RCU'; then
    echo "[+] P5: Simplifying OPEN_REDIRECT retry to single ref-walk"
    awk '
    BEGIN { in_redirect = 0 }
    /^\+\t\t\tset_nameidata\(&nd, dfd, fake_pathname\);/ {
        in_redirect = 1
        print
        next
    }
    in_redirect && /^\+\t\t\tfilp = path_openat\(&nd, op, flags \| LOOKUP_RCU\);/ {
        # Replace RCU attempt with plain ref-walk
        print "+\t\t\tfilp = path_openat(&nd, op, flags);"
        next
    }
    in_redirect && /^\+\t\t\tif \(unlikely\(filp == ERR_PTR\(-ECHILD\)\)\)/ {
        # Skip -ECHILD retry line
        next
    }
    in_redirect && /^\+\t\t\t\tfilp = path_openat\(&nd, op, flags\);/ {
        # Skip the fallback ref-walk (we already do ref-walk above)
        next
    }
    in_redirect && /^\+\t\t\tif \(unlikely\(filp == ERR_PTR\(-ESTALE\)\)\)/ {
        # Skip -ESTALE retry line
        next
    }
    in_redirect && /^\+\t\t\t\tfilp = path_openat\(&nd, op, flags \| LOOKUP_REVAL\);/ {
        # Skip REVAL retry
        next
    }
    in_redirect && /^\+\t\t\trestore_nameidata\(\);/ {
        in_redirect = 0
        print
        next
    }
    { print }
    ' "$GKI_PATCH" > "$GKI_PATCH.tmp" && mv "$GKI_PATCH.tmp" "$GKI_PATCH"
    ((fix_count++)) || true
else
    echo "[=] P5: OPEN_REDIRECT retry already simplified or not found"
fi


# --- P2 (Phase A, part c): Readdir modifications in GKI patch ---
# Five changes to readdir.c in the patch (5.10 has 5 filldir variants):
#   1. Add parent_inode field to each callback struct
#   2. Set buf.parent_inode in each syscall function
#   3. Replace the ilookup block in each filldir variant
#
# Also adds the susfs_should_hide_dirent() inline function (F6)
# and the susfs_is_hidden_ino() extern declaration (M2)

# P2c + F6: Full readdir rewrite in GKI patch
if grep -q 'ilookup(buf->sb, ino)' "$GKI_PATCH" 2>/dev/null; then
    echo "[+] P2/F6: Rewriting readdir hooks with two-level guard + unified function"
    awk '
    BEGIN {
        # Track whether we already injected the shared function
        injected_shared_fn = 0
        # Track readdir.c section — the extern anchor exists in both
        # namei.c and readdir.c; we must inject into readdir.c only
        in_readdir = 0
    }

    # Detect readdir.c diff section
    /^diff --git a\/fs\/readdir\.c/ { in_readdir = 1 }
    # Reset on next diff section
    in_readdir && /^diff --git/ && !/readdir\.c/ { in_readdir = 0 }

    # --- Insert extern + susfs_should_hide_dirent() once, after the #include + extern block ---
    # M2: adds extern for susfs_is_hidden_ino() and replaces ilookup with hash lookup
    # Must be in the readdir.c section (extern appears in namei.c too)
    in_readdir && !injected_shared_fn && /^\+extern bool susfs_is_inode_sus_path\(struct inode \*inode\);/ {
        print
        # Add extern for the hidden-ino hash table lookup (M2)
        print "+extern bool susfs_is_hidden_ino(struct super_block *sb, unsigned long ino);"
        # Inject the shared function after these externs
        print "+static inline bool susfs_should_hide_dirent(struct super_block *sb,"
        print "+\t\t\t\t\t\tstruct inode *parent_inode,"
        print "+\t\t\t\t\t\tunsigned long ino)"
        print "+"
        print "+{"
        print "+\tif (current_uid().val < 10000)"
        print "+\t\treturn false;"
        print "+\tif (!susfs_is_current_proc_umounted())"
        print "+\t\treturn false;"
        print "+\tif (!parent_inode ||"
        print "+\t    !test_bit(AS_FLAGS_SUS_PATH_PARENT,"
        print "+\t\t      &parent_inode->i_mapping->flags))"
        print "+\t\treturn false;"
        print "+\treturn susfs_is_hidden_ino(sb, ino);"
        print "+}"
        injected_shared_fn = 1
        next
    }

    # --- Add parent_inode to each callback struct ---
    # Pattern: after "+	struct super_block *sb;" inside an #ifdef block
    # Matches all 5 callback structs in 5.10 readdir.c
    /^\+\tstruct super_block \*sb;$/ {
        print
        print "+\tstruct inode *parent_inode;"
        next
    }

    # --- Set buf.parent_inode in each syscall function ---
    # Pattern: after "+	buf.sb = f.file->f_inode->i_sb;"
    # Matches all 5 syscall functions in 5.10 readdir.c
    /^\+\tbuf\.sb = f\.file->f_inode->i_sb;$/ {
        print
        print "+\tbuf.parent_inode = f.file->f_inode;"
        next
    }

    # --- Replace each ilookup block with the unified function call ---
    # Pattern: the multi-line ilookup+susfs_is_inode_sus_path block
    # Matches all 5 filldir variants in 5.10 readdir.c
    /^\+\tinode = ilookup\(buf->sb, ino\);/ {
        # Consume the entire block until orig_flow:
        # Expected pattern (10 lines):
        #   +	inode = ilookup(buf->sb, ino);
        #   +	if (!inode) {
        #   +		goto orig_flow;
        #   +	}
        #   +	if (susfs_is_inode_sus_path(inode)) {
        #   +		iput(inode);
        #   +		return 0;
        #   +	}
        #   +	iput(inode);
        #   +orig_flow:
        consumed = 0
        while (consumed < 9) {
            if (getline > 0) {
                consumed++
                if ($0 ~ /^\+orig_flow:/) break
            } else break
        }
        # Emit the replacement one-liner
        print "+\tif (susfs_should_hide_dirent(buf->sb, buf->parent_inode, ino))"
        print "+\t\treturn 0;"
        next
    }

    # --- Remove the per-filldir "struct inode *inode;" declaration ---
    # These are now unused since susfs_should_hide_dirent has its own local
    # Matches all 5 filldir variants in 5.10 readdir.c
    /^\+\tstruct inode \*inode;$/ {
        next
    }

    { print }
    ' "$GKI_PATCH" > "$GKI_PATCH.tmp" && mv "$GKI_PATCH.tmp" "$GKI_PATCH"
    ((fix_count++)) || true
else
    echo "[=] P2/F6: readdir already rewritten or ilookup pattern not found"
fi


# --- M4: Extend kallsyms filter to hide zeromount symbols ---
# Add zeromount to the existing symbol filter chain in the GKI patch.

if grep -q 'susfs_starts_with(iter->name, "is_zygote")' "$GKI_PATCH" 2>/dev/null && \
   ! grep -q 'susfs_starts_with(iter->name, "zeromount")' "$GKI_PATCH" 2>/dev/null; then
    echo "[+] M4: Extending kallsyms filter for zeromount symbols"
    # Replace the closing `)` of the is_zygote check with ` ||`
    # then add the zeromount check with the closing `)` on the next line
    sed -i 's/susfs_starts_with(iter->name, "is_zygote"))/susfs_starts_with(iter->name, "is_zygote") ||\n+\t\t\tsusfs_starts_with(iter->name, "zeromount"))/' "$GKI_PATCH"
    ((fix_count++)) || true
else
    echo "[=] M4: zeromount symbol hiding already present or anchor not found"
fi


# --- Recalculate @@ hunk headers after Phase A line-count mutations ---
# P1/P5/P2/F6/M4 add or remove lines within hunks without updating the
# @@ old,count +new,count @@ headers. patch(1) requires exact counts.
recalc_hunk_headers() {
    local patch_file="$1"
    awk '
    function flush_hunk() {
        if (hunk_n == 0) return
        split(hdr_parts[2], om, ",")
        split(hdr_parts[3], nm, ",")
        printf "@@ %s,%d %s,%d @@", om[1], old_count, nm[1], new_count
        for (i = 5; i <= length(hdr_parts); i++) printf " %s", hdr_parts[i]
        printf "\n"
        for (i = 1; i <= hunk_n; i++) printf "%s\n", hunk_buf[i]
    }

    BEGIN { hunk_n = 0; old_count = 0; new_count = 0 }

    /^diff --git/ || /^---/ || /^\+\+\+/ || /^index / || /^old mode/ || /^new mode/ || /^new file/ || /^deleted file/ || /^similarity/ || /^rename/ || /^copy/ {
        flush_hunk()
        hunk_n = 0; old_count = 0; new_count = 0
        print
        next
    }

    /^@@ / {
        flush_hunk()
        hunk_n = 0; old_count = 0; new_count = 0
        split($0, hdr_parts, " ")
        next
    }

    hunk_n >= 0 && hdr_parts[1] == "@@" {
        hunk_n++
        hunk_buf[hunk_n] = $0
        if ($0 ~ /^-/)       old_count++
        else if ($0 ~ /^\+/) new_count++
        else                  { old_count++; new_count++ }
        next
    }

    { print }

    END { flush_hunk() }
    ' "$patch_file" > "$patch_file.tmp" && mv "$patch_file.tmp" "$patch_file"
}

recalc_hunk_headers "$GKI_PATCH"
echo "[+] Recalculated GKI patch hunk headers"


# =============================================================================
# Phase B: Source file modifications (AFTER sources copied to kernel tree)
# =============================================================================

# --- P2 (Phase B, part a): Add AS_FLAGS_SUS_PATH_PARENT to susfs_def.h ---

if [ -f "$SUSFS_DEF_H" ]; then
    if ! grep -q 'AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_DEF_H"; then
        echo "[+] P2a: Adding AS_FLAGS_SUS_PATH_PARENT to susfs_def.h"
        sed -i '/^#define AS_FLAGS_SUS_MAP/a #define AS_FLAGS_SUS_PATH_PARENT 41' "$SUSFS_DEF_H"
        ((fix_count++)) || true
    else
        echo "[=] P2a: AS_FLAGS_SUS_PATH_PARENT already defined"
    fi
    # inject-susfs-features.sh runs before fix-perf.sh, so its conditional
    # BUILD_BUG_ON for SUS_PATH_PARENT misses. Add it here.
    if [ -f "$SUSFS_C" ] && ! grep -q 'BUILD_BUG_ON.*AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_C"; then
        echo "[+] P2a: Adding BUILD_BUG_ON for AS_FLAGS_SUS_PATH_PARENT"
        sed -i '/BUILD_BUG_ON(AS_FLAGS_OPEN_REDIRECT_ALL >= BITS_PER_LONG);/a \\tBUILD_BUG_ON(AS_FLAGS_SUS_PATH_PARENT >= BITS_PER_LONG);' "$SUSFS_C"
    fi
else
    echo "[!] P2a: susfs_def.h not found at $SUSFS_DEF_H — skipping"
fi


# --- P2 (Phase B, part b): Set parent directory flag in susfs.c ---
# In susfs_add_sus_path() and susfs_run_sus_path_loop(), after set_bit(AS_FLAGS_SUS_PATH, ...),
# also set AS_FLAGS_SUS_PATH_PARENT on the parent directory inode.

if [ -f "$SUSFS_C" ]; then
    if ! grep -q 'AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_C"; then
        echo "[+] P2b: Adding parent directory flag to susfs_add_sus_path and susfs_run_sus_path_loop"
        awk '
        # Match set_bit for inode->i_mapping (non-FUSE path) in writer functions.
        # Preserve indentation from the matched line.
        /set_bit\(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags\);/ {
            print
            # Extract leading whitespace for proper indentation
            match($0, /^[\t ]+/)
            ind = substr($0, RSTART, RLENGTH)
            print ind "{"
            print ind "\tstruct dentry *parent_dentry = dget_parent(path.dentry);"
            print ind "\tif (parent_dentry && parent_dentry->d_inode &&"
            print ind "\t    parent_dentry->d_inode->i_mapping) {"
            print ind "\t\tset_bit(AS_FLAGS_SUS_PATH_PARENT,"
            print ind "\t\t\t&parent_dentry->d_inode->i_mapping->flags);"
            print ind "\t}"
            print ind "\tdput(parent_dentry);"
            print ind "}"
            next
        }
        # Match set_bit for fi->inode.i_mapping (FUSE path) in writer functions.
        /set_bit\(AS_FLAGS_SUS_PATH, &fi->inode\.i_mapping->flags\);/ {
            print
            match($0, /^[\t ]+/)
            ind = substr($0, RSTART, RLENGTH)
            print ind "{"
            print ind "\tstruct dentry *parent_dentry = dget_parent(path.dentry);"
            print ind "\tif (parent_dentry) {"
            print ind "\t\tset_bit(AS_FLAGS_SUS_PATH_PARENT,"
            print ind "\t\t\t&d_inode(parent_dentry)->i_mapping->flags);"
            print ind "\t}"
            print ind "\tdput(parent_dentry);"
            print ind "}"
            next
        }
        { print }
        ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
        ((fix_count++)) || true
    else
        echo "[=] P2b: parent directory flag already present"
    fi
else
    echo "[!] P2b: susfs.c not found at $SUSFS_C — skipping"
fi


# --- M2 (Phase B, part a): Add #include <linux/hashtable.h> to susfs.c ---
# Required for DEFINE_HASHTABLE, hash_add_rcu, hash_for_each_possible_rcu

if [ -f "$SUSFS_C" ]; then
    if ! grep -q '#include <linux/hashtable.h>' "$SUSFS_C"; then
        echo "[+] M2a: Adding hashtable.h include to susfs.c"
        sed -i '/#include <linux\/spinlock.h>/a #include <linux/hashtable.h>' "$SUSFS_C"
        ((fix_count++)) || true
    else
        echo "[=] M2a: hashtable.h already included"
    fi
else
    echo "[!] M2a: susfs.c not found at $SUSFS_C — skipping"
fi


# --- M2 (Phase B, part b): Hidden-ino hash table + lookup function ---
# Inject per-superblock hidden-ino hash table and susfs_is_hidden_ino()
# right after the existing spinlock/list_head declarations in the SUS_PATH section.
# This replaces ilookup() in filldir hooks with an O(1) RCU hash lookup
# that is cache-independent (D1 fix).

if [ -f "$SUSFS_C" ]; then
    if ! grep -q 'susfs_hidden_inos' "$SUSFS_C"; then
        echo "[+] M2b: Injecting hidden-ino hash table and lookup function"
        # Anchor: right after the LIST_HEAD(LH_SUS_PATH_LOOP) line
        awk '
        /^static LIST_HEAD\(LH_SUS_PATH_LOOP\);/ {
            print
            print ""
            print "struct susfs_hidden_ino_entry {"
            print "\tunsigned long ino;"
            print "\tstruct super_block *sb;"
            print "\tstruct hlist_node node;"
            print "\tstruct rcu_head rcu;"
            print "};"
            print ""
            print "static DEFINE_HASHTABLE(susfs_hidden_inos, 10);"
            print "static DEFINE_SPINLOCK(susfs_hidden_inos_lock);"
            print ""
            print "bool susfs_is_hidden_ino(struct super_block *sb, unsigned long ino)"
            print "{"
            print "\tstruct susfs_hidden_ino_entry *entry;"
            print "\tu32 key = hash_long(ino ^ (unsigned long)sb, 10);"
            print ""
            print "\trcu_read_lock();"
            print "\thash_for_each_possible_rcu(susfs_hidden_inos, entry, node, key) {"
            print "\t\tif (entry->ino == ino && entry->sb == sb) {"
            print "\t\t\trcu_read_unlock();"
            print "\t\t\treturn true;"
            print "\t\t}"
            print "\t}"
            print "\trcu_read_unlock();"
            print "\treturn false;"
            print "}"
            print "EXPORT_SYMBOL(susfs_is_hidden_ino);"
            next
        }
        { print }
        ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
        ((fix_count++)) || true
    else
        echo "[=] M2b: hidden-ino hash table already present"
    fi
else
    echo "[!] M2b: susfs.c not found at $SUSFS_C — skipping"
fi


# --- M2 (Phase B, part c): Register hidden inos in sus_path writers ---
# After P2b adds the parent_dentry block, M2c adds hash table registration.
# Handles both non-FUSE (inode->i_mapping) and FUSE (fi->inode.i_mapping) paths.
# Also covers susfs_run_sus_path_loop() since both have the same patterns.

if [ -f "$SUSFS_C" ]; then
    if ! grep -q 'susfs_hidden_ino_entry \*new_entry' "$SUSFS_C"; then
        echo "[+] M2c: Adding hidden-ino registration to sus_path writers"
        awk '
        # Non-FUSE path: set_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags);
        /set_bit\(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags\);/ {
            print
            match($0, /^[\t ]+/)
            ind = substr($0, RSTART, RLENGTH)
            print ind "{"
            print ind "\tstruct susfs_hidden_ino_entry *new_entry;"
            print ind "\tstruct susfs_hidden_ino_entry *existing;"
            print ind "\tu32 key = hash_long(inode->i_ino ^ (unsigned long)inode->i_sb, 10);"
            print ind "\tbool found = false;"
            print ind ""
            print ind "\trcu_read_lock();"
            print ind "\thash_for_each_possible_rcu(susfs_hidden_inos, existing, node, key) {"
            print ind "\t\tif (existing->ino == inode->i_ino && existing->sb == inode->i_sb) {"
            print ind "\t\t\tfound = true;"
            print ind "\t\t\tbreak;"
            print ind "\t\t}"
            print ind "\t}"
            print ind "\trcu_read_unlock();"
            print ind ""
            print ind "\tif (!found) {"
            print ind "\t\tnew_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);"
            print ind "\t\tif (new_entry) {"
            print ind "\t\t\tnew_entry->ino = inode->i_ino;"
            print ind "\t\t\tnew_entry->sb = inode->i_sb;"
            print ind "\t\t\tspin_lock(&susfs_hidden_inos_lock);"
            print ind "\t\t\thash_add_rcu(susfs_hidden_inos, &new_entry->node, key);"
            print ind "\t\t\tspin_unlock(&susfs_hidden_inos_lock);"
            print ind "\t\t}"
            print ind "\t}"
            print ind "}"
            next
        }
        # FUSE path: set_bit(AS_FLAGS_SUS_PATH, &fi->inode.i_mapping->flags);
        /set_bit\(AS_FLAGS_SUS_PATH, &fi->inode\.i_mapping->flags\);/ {
            print
            match($0, /^[\t ]+/)
            ind = substr($0, RSTART, RLENGTH)
            print ind "{"
            print ind "\tstruct susfs_hidden_ino_entry *new_entry;"
            print ind "\tstruct susfs_hidden_ino_entry *existing;"
            print ind "\tu32 key = hash_long(fi->inode.i_ino ^ (unsigned long)fi->inode.i_sb, 10);"
            print ind "\tbool found = false;"
            print ind ""
            print ind "\trcu_read_lock();"
            print ind "\thash_for_each_possible_rcu(susfs_hidden_inos, existing, node, key) {"
            print ind "\t\tif (existing->ino == fi->inode.i_ino && existing->sb == fi->inode.i_sb) {"
            print ind "\t\t\tfound = true;"
            print ind "\t\t\tbreak;"
            print ind "\t\t}"
            print ind "\t}"
            print ind "\trcu_read_unlock();"
            print ind ""
            print ind "\tif (!found) {"
            print ind "\t\tnew_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);"
            print ind "\t\tif (new_entry) {"
            print ind "\t\t\tnew_entry->ino = fi->inode.i_ino;"
            print ind "\t\t\tnew_entry->sb = fi->inode.i_sb;"
            print ind "\t\t\tspin_lock(&susfs_hidden_inos_lock);"
            print ind "\t\t\thash_add_rcu(susfs_hidden_inos, &new_entry->node, key);"
            print ind "\t\t\tspin_unlock(&susfs_hidden_inos_lock);"
            print ind "\t\t}"
            print ind "\t}"
            print ind "}"
            next
        }
        { print }
        ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
        ((fix_count++)) || true
    else
        echo "[=] M2c: hidden-ino registration already present"
    fi
else
    echo "[!] M2c: susfs.c not found at $SUSFS_C — skipping"
fi


echo "=== Done: $fix_count fixes applied ==="
