#!/bin/bash
# VFS performance patches for SUSFS.
#
# Phase A: GKI patch file (before patch is applied to kernel tree)
#   P1 - Inline fast-path for link_path_walk SUS_PATH check
#   P5 - Remove RCU retry from OPEN_REDIRECT redirect path
#   P2/F6 - Two-level readdir guard with unified susfs_should_hide_dirent()
#   M4 - Extend kallsyms filter to hide zeromount symbols
#
# Phase B: susfs_def.h and susfs.c (after sources copied to kernel tree)
#   P2 - AS_FLAGS_SUS_PATH_PARENT definition and parent flag setting
#   M2 - Hidden-ino hash table replacing ilookup in filldir
#
# 5.10 readdir.c has 5 filldir variants (vs 3 in 5.15):
#   fillonedir, filldir, filldir64, compat_fillonedir, compat_filldir
#
# Usage: ./fix-susfs-perf.sh <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>

set -euo pipefail

KERNEL_DIR="${1:?Usage: $0 <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>}"
SUSFS_DIR="${2:?Usage: $0 <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>}"
GKI_PATCH="${3:?Usage: $0 <KERNEL_SRC_DIR> <SUSFS_SRC_DIR> <GKI_PATCH_PATH>}"

[ -f "$GKI_PATCH" ] || { echo "FATAL: GKI patch not found: $GKI_PATCH"; exit 1; }

SUSFS_DEF_H="$SUSFS_DIR/include/linux/susfs_def.h"
SUSFS_C="$SUSFS_DIR/fs/susfs.c"

echo "=== fix-susfs-perf ==="
fix_count=0

# Phase A: GKI patch file modifications (BEFORE patch is applied)

# -- P1: Inline fast-path for link_path_walk SUS_PATH check --
if grep -A1 'dentry = nd->path.dentry;' "$GKI_PATCH" 2>/dev/null | grep -q 'susfs_is_inode_sus_path(dentry->d_inode)'; then
    echo "[+] P1: Inlining fast-path for link_path_walk SUS_PATH check"
    awk '
    /^\+[\t]+if \(dentry->d_inode && susfs_is_inode_sus_path\(dentry->d_inode\)\)/ {
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
fi

# -- P5: Remove RCU retry from OPEN_REDIRECT redirect path --
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
        print "+\t\t\tfilp = path_openat(&nd, op, flags);"
        next
    }
    in_redirect && /^\+\t\t\tif \(unlikely\(filp == ERR_PTR\(-ECHILD\)\)\)/ { next }
    in_redirect && /^\+\t\t\t\tfilp = path_openat\(&nd, op, flags\);/ { next }
    in_redirect && /^\+\t\t\tif \(unlikely\(filp == ERR_PTR\(-ESTALE\)\)\)/ { next }
    in_redirect && /^\+\t\t\t\tfilp = path_openat\(&nd, op, flags \| LOOKUP_REVAL\);/ { next }
    in_redirect && /^\+\t\t\trestore_nameidata\(\);/ {
        in_redirect = 0
        print
        next
    }
    { print }
    ' "$GKI_PATCH" > "$GKI_PATCH.tmp" && mv "$GKI_PATCH.tmp" "$GKI_PATCH"
    ((fix_count++)) || true
fi

# -- P2/F6: Full readdir rewrite with two-level guard + unified function --
if grep -q 'ilookup(buf->sb, ino)' "$GKI_PATCH" 2>/dev/null; then
    echo "[+] P2/F6: Rewriting readdir hooks with two-level guard + unified function"
    awk '
    BEGIN { injected_shared_fn = 0; in_readdir = 0 }

    /^diff --git a\/fs\/readdir\.c/ { in_readdir = 1 }
    in_readdir && /^diff --git/ && !/readdir\.c/ { in_readdir = 0 }

    # Inject extern + susfs_should_hide_dirent() once in readdir.c section
    in_readdir && !injected_shared_fn && /^\+extern bool susfs_is_inode_sus_path\(struct inode \*inode\);/ {
        print
        print "+extern bool susfs_is_hidden_ino(struct super_block *sb, unsigned long ino);"
        print "+extern bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid);"
        print "+static inline bool susfs_should_hide_dirent(struct super_block *sb,"
        print "+\t\t\t\t\t\tunsigned long ino,"
        print "+\t\t\t\t\t\tconst char *name,"
        print "+\t\t\t\t\t\tint namlen)"
        print "+"
        print "+{"
        print "+\tuid_t uid = current_uid().val;"
        print "+\tif (uid < 10000)"
        print "+\t\treturn false;"
        print "+\tif (!susfs_is_current_proc_umounted()) {"
        print "+\t\tprintk_ratelimited(KERN_INFO \"susfs_debug: SKIP not_umounted uid=%u name='%.*s'\\n\", uid, namlen, name);"
        print "+\t\treturn false;"
        print "+\t}"
        print "+\tprintk_ratelimited(KERN_INFO \"susfs_debug: ENTER hide_dirent uid=%u name='%.*s' ino=%lu\\n\", uid, namlen, name, ino);"
        print "+\tif (susfs_is_hidden_ino(sb, ino)) {"
        print "+\t\tprintk(KERN_INFO \"susfs_debug: HIDE via ino_hit ino=%lu uid=%u name='%.*s'\\n\", ino, uid, namlen, name);"
        print "+\t\treturn true;"
        print "+\t}"
        print "+\t{"
        print "+\t\tbool r = susfs_is_hidden_name(name, namlen, uid);"
        print "+\t\tprintk(KERN_INFO \"susfs_debug: name_check '%.*s' uid=%u result=%s\\n\", namlen, name, uid, r ? \"HIDE\" : \"SHOW\");"
        print "+\t\treturn r;"
        print "+\t}"
        print "+}"
        injected_shared_fn = 1
        next
    }

    # Replace each ilookup block with unified function call
    /^\+\tinode = ilookup\(buf->sb, ino\);/ {
        consumed = 0
        while (consumed < 9) {
            if (getline > 0) {
                consumed++
                if ($0 ~ /^\+orig_flow:/) break
            } else break
        }
        print "+\tif (susfs_should_hide_dirent(buf->sb, ino, name, namlen))"
        print "+\t\treturn 0;"
        next
    }

    # Remove per-filldir "struct inode *inode;" declaration (now unused)
    /^\+\tstruct inode \*inode;$/ { next }

    { print }
    ' "$GKI_PATCH" > "$GKI_PATCH.tmp" && mv "$GKI_PATCH.tmp" "$GKI_PATCH"
    ((fix_count++)) || true
fi

# -- M4: Extend kallsyms filter to hide zeromount symbols --
if grep -q 'susfs_starts_with(iter->name, "is_zygote")' "$GKI_PATCH" 2>/dev/null && \
   ! grep -q 'susfs_starts_with(iter->name, "zeromount")' "$GKI_PATCH" 2>/dev/null; then
    echo "[+] M4: Extending kallsyms filter for zeromount symbols"
    sed -i 's/susfs_starts_with(iter->name, "is_zygote"))/susfs_starts_with(iter->name, "is_zygote") ||\n+\t\t\tsusfs_starts_with(iter->name, "zeromount"))/' "$GKI_PATCH"
    ((fix_count++)) || true
fi

# -- Recalculate @@ hunk headers after line-count mutations --
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


# Phase B: Source file modifications (AFTER sources copied to kernel tree)

# -- P2a: Add AS_FLAGS_SUS_PATH_PARENT to susfs_def.h --
if [ -f "$SUSFS_DEF_H" ]; then
    if ! grep -q 'AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_DEF_H"; then
        echo "[+] P2a: Adding AS_FLAGS_SUS_PATH_PARENT to susfs_def.h"
        sed -i '/^#define AS_FLAGS_SUS_MAP/a #define AS_FLAGS_SUS_PATH_PARENT 41' "$SUSFS_DEF_H"
        ((fix_count++)) || true
    fi
    if [ -f "$SUSFS_C" ] && ! grep -q 'BUILD_BUG_ON.*AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_C"; then
        echo "[+] P2a: Adding BUILD_BUG_ON for AS_FLAGS_SUS_PATH_PARENT"
        sed -i '/BUILD_BUG_ON(AS_FLAGS_OPEN_REDIRECT_ALL >= BITS_PER_LONG);/a \\tBUILD_BUG_ON(AS_FLAGS_SUS_PATH_PARENT >= BITS_PER_LONG);' "$SUSFS_C"
    fi
fi

# -- P2b: Set parent directory flag in susfs_add_sus_path and sus_path_loop --
if [ -f "$SUSFS_C" ] && ! grep -q 'AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_C"; then
    echo "[+] P2b: Adding parent directory flag to sus_path writers"
    awk '
    /set_bit\(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags\);/ {
        print
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
fi

# -- M2a: Add #include <linux/hashtable.h> to susfs.c --
if [ -f "$SUSFS_C" ] && ! grep -q '#include <linux/hashtable.h>' "$SUSFS_C"; then
    echo "[+] M2a: Adding hashtable.h include to susfs.c"
    sed -i '/#include <linux\/spinlock.h>/a #include <linux/hashtable.h>' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- M2b: Hidden-ino hash table + lookup function --
if [ -f "$SUSFS_C" ] && ! grep -q 'susfs_hidden_inos' "$SUSFS_C"; then
    echo "[+] M2b: Injecting hidden-ino hash table and lookup function"
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
fi

# -- M2c: Register hidden inos in sus_path writers --
if [ -f "$SUSFS_C" ] && ! grep -q 'susfs_hidden_ino_entry \*new_entry' "$SUSFS_C"; then
    echo "[+] M2c: Adding hidden-ino registration to sus_path writers"
    awk '
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
fi

# -- N1: Hidden-name hash table for FUSE-safe readdir fallback --
# FUSE evicts/recreates inodes, losing AS_FLAGS_SUS_PATH. Name-based
# matching survives inode recycling since we compare the dirent name
# against basenames extracted from android_data sus_paths.
if [ -f "$SUSFS_C" ] && ! grep -q 'susfs_hidden_names' "$SUSFS_C"; then
    echo "[+] N1: Injecting hidden-name hash table for FUSE readdir fallback"
    awk '
    /^static DEFINE_HASHTABLE\(susfs_hidden_inos, 10\);/ {
        print
        print ""
        print "struct susfs_hidden_name_entry {"
        print "\tchar name[SUSFS_MAX_LEN_PATHNAME];"
        print "\tint namlen;"
        print "\tuid_t owner_uid;"
        print "\tstruct hlist_node node;"
        print "\tstruct rcu_head rcu;"
        print "};"
        print ""
        print "static DEFINE_HASHTABLE(susfs_hidden_names, 8);"
        print "static DEFINE_SPINLOCK(susfs_hidden_names_lock);"
        print ""
        print "static u32 susfs_name_hash(const char *name, int namlen)"
        print "{"
        print "\tu32 hash = 0;"
        print "\tint i;"
        print "\tfor (i = 0; i < namlen; i++)"
        print "\t\thash = hash * 31 + (unsigned char)name[i];"
        print "\treturn hash;"
        print "}"
        print ""
        print "bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid)"
        print "{"
        print "\tstruct susfs_hidden_name_entry *entry;"
        print "\tu32 key = susfs_name_hash(name, namlen);"
        print ""
        print "\trcu_read_lock();"
        print "\thash_for_each_possible_rcu(susfs_hidden_names, entry, node, key) {"
        print "\t\tif (entry->namlen == namlen &&"
        print "\t\t    !memcmp(entry->name, name, namlen)) {"
        print "\t\t\tif (entry->owner_uid && caller_uid == entry->owner_uid) {"
        print "\t\t\t\tprintk_ratelimited(KERN_INFO \"susfs_debug: hidden_name SELF_EXEMPT '"'"'%.*s'"'"' caller=%u owner=%u\\n\", namlen, name, caller_uid, entry->owner_uid);"
        print "\t\t\t\trcu_read_unlock();"
        print "\t\t\t\treturn false;"
        print "\t\t\t}"
        print "\t\t\tprintk_ratelimited(KERN_INFO \"susfs_debug: hidden_name HIDE '"'"'%.*s'"'"' caller=%u owner=%u\\n\", namlen, name, caller_uid, entry->owner_uid);"
        print "\t\t\trcu_read_unlock();"
        print "\t\t\treturn true;"
        print "\t\t}"
        print "\t}"
        print "\trcu_read_unlock();"
        print "\tprintk_ratelimited(KERN_INFO \"susfs_debug: hidden_name MISS '"'"'%.*s'"'"' (no entry in table)\\n\", namlen, name);"
        print "\treturn false;"
        print "}"
        print "EXPORT_SYMBOL(susfs_is_hidden_name);"
        print ""
        print "static void susfs_add_hidden_name(const char *name, int namlen, uid_t owner_uid)"
        print "{"
        print "\tstruct susfs_hidden_name_entry *entry;"
        print "\tu32 key = susfs_name_hash(name, namlen);"
        print ""
        print "\trcu_read_lock();"
        print "\thash_for_each_possible_rcu(susfs_hidden_names, entry, node, key) {"
        print "\t\tif (entry->namlen == namlen &&"
        print "\t\t    !memcmp(entry->name, name, namlen)) {"
        print "\t\t\trcu_read_unlock();"
        print "\t\t\treturn;"
        print "\t\t}"
        print "\t}"
        print "\trcu_read_unlock();"
        print ""
        print "\tentry = kmalloc(sizeof(*entry), GFP_KERNEL);"
        print "\tif (!entry)"
        print "\t\treturn;"
        print "\tmemcpy(entry->name, name, namlen);"
        print "\tentry->name[namlen] = '"'"'\\0'"'"';"
        print "\tentry->namlen = namlen;"
        print "\tentry->owner_uid = owner_uid;"
        print "\tspin_lock(&susfs_hidden_names_lock);"
        print "\thash_add_rcu(susfs_hidden_names, &entry->node, key);"
        print "\tspin_unlock(&susfs_hidden_names_lock);"
        print "}"
        print ""
        print "static void susfs_try_register_hidden_name(const char *pathname)"
        print "{"
        print "\tconst char *prefix;"
        print "\tconst char *basename;"
        print "\tint namlen;"
        print "\tuid_t owner_uid = 0;"
        print "\tstruct path data_path;"
        print "\tchar lookup_buf[256];"
        print ""
        print "\tprintk(KERN_INFO \"susfs_debug: try_register pathname='%s'\\n\", pathname);"
        print "\tprefix = strstr(pathname, \"/Android/data/\");"
        print "\tif (prefix) {"
        print "\t\tbasename = prefix + 14;"
        print "\t} else {"
        print "\t\tprefix = strstr(pathname, \"/Android/obb/\");"
        print "\t\tif (!prefix) {"
        print "\t\t\tprintk(KERN_INFO \"susfs_debug: try_register SKIP no /Android/data/ or /obb/ prefix\\n\");"
        print "\t\t\treturn;"
        print "\t\t}"
        print "\t\tbasename = prefix + 13;"
        print "\t}"
        print "\tif (!*basename)"
        print "\t\treturn;"
        print "\tnamlen = 0;"
        print "\twhile (basename[namlen] && basename[namlen] != '"'"'/'"'"')"
        print "\t\tnamlen++;"
        print "\tif (namlen <= 0 || namlen >= 240)"
        print "\t\treturn;"
        print "\tsnprintf(lookup_buf, sizeof(lookup_buf), \"/data/data/%.*s\", namlen, basename);"
        print "\tif (!kern_path(lookup_buf, LOOKUP_FOLLOW, &data_path)) {"
        print "\t\tstruct inode *di = d_backing_inode(data_path.dentry);"
        print "\t\tif (di)"
        print "\t\t\towner_uid = di->i_uid.val;"
        print "\t\tpath_put(&data_path);"
        print "\t}"
        print "\tsusfs_add_hidden_name(basename, namlen, owner_uid);"
        print "\tprintk(KERN_INFO \"susfs_debug: registered hidden_name '%.*s' owner_uid=%u\\n\", namlen, basename, owner_uid);"
        print "}"
        print ""
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- N2: Register hidden names when add_sus_path succeeds --
if [ -f "$SUSFS_C" ] && ! grep -q 'susfs_try_register_hidden_name(info\.target_pathname)' "$SUSFS_C"; then
    echo "[+] N2: Wiring name registration into add_sus_path"
    sed -i '/SUSFS_LOGI("CMD_SUSFS_ADD_SUS_PATH -> ret: %d/i\\tif (!info.err)\n\t\tsusfs_try_register_hidden_name(info.target_pathname);' "$SUSFS_C"
    ((fix_count++)) || true
fi

echo "=== fix-susfs-perf done ($fix_count fixes) ==="
