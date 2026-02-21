#!/bin/bash
# fix-susfs-safety.sh
# Applies security and correctness fixes to upstream SUSFS source:
# - strncpy null-termination (10+ locations)
# - RCU transition for kstat/open_redirect hash tables (M1)
#   readers: rcu_read_lock + hash_for_each_possible_rcu (lockless)
#   writers: spinlock + hash_add_rcu/hash_del_rcu + kfree_rcu
# - Sleep-under-spinlock fixes (C5 open_redirect, C1 sus_path RCU)
# - Lock ordering rewrite for susfs_update_sus_kstat (C6/C7)
# - NULL deref in cmdline_or_bootconfig and enabled_features
# - Racy lockless read in susfs_spoof_uname (L1)
# - Struct field dedup in st_susfs_sus_path_list (L6)
#
# Usage: ./fix-susfs-safety.sh <SUSFS_KERNEL_PATCHES_DIR>

set -e

SUSFS_DIR="$1"

if [ -z "$SUSFS_DIR" ]; then
    echo "Usage: $0 <SUSFS_KERNEL_PATCHES_DIR>"
    exit 1
fi

SUSFS_C="$SUSFS_DIR/fs/susfs.c"
SUSFS_H="$SUSFS_DIR/include/linux/susfs.h"

if [ ! -f "$SUSFS_C" ]; then
    echo "FATAL: missing $SUSFS_C"
    exit 1
fi

echo "=== fix-susfs-safety ==="
fix_count=0

# --- 1. (removed: fsnotify_backend.h is required for sdcard monitor) ---

# --- 2. Fix trailing whitespace in disabled log macros ---
if grep -q 'SUSFS_LOGI(fmt, \.\.\.) $' "$SUSFS_C"; then
    echo "[+] Fixing trailing whitespace in disabled log macros"
    sed -i 's/#define SUSFS_LOGI(fmt, \.\.\.) $/#define SUSFS_LOGI(fmt, ...)/' "$SUSFS_C"
    sed -i 's/#define SUSFS_LOGE(fmt, \.\.\.) $/#define SUSFS_LOGE(fmt, ...)/' "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] Log macros already clean"
fi

# --- 3. strncpy null-termination fixes ---
# After every strncpy, ensure the buffer is null-terminated.
# Pattern: strncpy(dst, src, SIZE - 1); -> add dst[SIZE-1] = '\0';
# We target specific anchor patterns rather than blind replacement.

echo "[+] Applying strncpy null-termination fixes"

# 3a. android_data_path.target_pathname
if ! grep -A1 'android_data_path.target_pathname' "$SUSFS_C" | grep -q '\[SUSFS_MAX_LEN_PATHNAME-1\].*\\0'; then
    sed -i '/strncpy(android_data_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);/a \\t\tandroid_data_path.target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3b. sdcard_path.target_pathname
if ! grep -A1 'sdcard_path.target_pathname' "$SUSFS_C" | grep -q '\[SUSFS_MAX_LEN_PATHNAME-1\].*\\0'; then
    sed -i '/strncpy(sdcard_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);/a \\t\tsdcard_path.target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3c-d. sus_path: new_list->info.target_pathname + new_list->target_pathname (3 code blocks)
# ADD blocks use 2-tab indent, sus_path_loop uses 1-tab — detect from strncpy line itself
# State-based: after seeing strncpy, insert null-term before the NEXT line (handles adjacent pairs)
if grep -q 'strncpy(new_list->.*target_pathname,.*SUSFS_MAX_LEN_PATHNAME' "$SUSFS_C" && \
   ! awk '/strncpy\(new_list->(info\.)?target_pathname,.*SUSFS_MAX_LEN_PATHNAME *- *1\);/{found=1;next} found{if($0 !~ /target_pathname\[SUSFS_MAX_LEN_PATHNAME *- *1\]/){exit 1}; found=0}' "$SUSFS_C" 2>/dev/null; then
    awk '
    {
        if (pending_field != "") {
            if ($0 !~ /target_pathname\[SUSFS_MAX_LEN_PATHNAME *- *1\]/) {
                print pending_indent "new_list->" pending_field "[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';"
            }
            pending_field = ""
        }
        print
        if ($0 ~ /strncpy\(new_list->(info\.)?target_pathname,.*SUSFS_MAX_LEN_PATHNAME *- *1\);/) {
            match($0, /^[\t]+/)
            pending_indent = substr($0, RSTART, RLENGTH)
            pending_field = ($0 ~ /strncpy\(new_list->info\./) ? "info.target_pathname" : "target_pathname"
        }
    }
    END {
        if (pending_field != "") {
            print pending_indent "new_list->" pending_field "[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';"
        }
    }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "  [=] Section 3c-d: null-terminators already present"
fi

# 3e. uname release/version null-termination (L10)
# Insert null-term for BOTH branches (info.release AND utsname()->release) by
# placing it once before spin_unlock in susfs_set_uname(), covering all paths.
if ! grep -q 'my_uname.release\[__NEW_UTS_LEN\].*\\0' "$SUSFS_C"; then
    sed -i '/^void susfs_set_uname/,/^}/ {
        /spin_unlock(&susfs_spin_lock_set_uname);/i \\tmy_uname.release[__NEW_UTS_LEN] = '"'"'\\0'"'"';\n\tmy_uname.version[__NEW_UTS_LEN] = '"'"'\\0'"'"';
    }' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3f. spoof_uname tmp->release/version null-termination
if ! grep -A1 'strncpy(tmp->release' "$SUSFS_C" | grep -q 'tmp->release\[__NEW_UTS_LEN\]'; then
    sed -i '/strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);/a \\ttmp->release[__NEW_UTS_LEN] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

if ! grep -A1 'strncpy(tmp->version' "$SUSFS_C" | grep -q 'tmp->version\[__NEW_UTS_LEN\]'; then
    sed -i '/strncpy(tmp->version, my_uname.version, __NEW_UTS_LEN);/a \\ttmp->version[__NEW_UTS_LEN] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3g. susfs_show_variant null-termination
if ! grep -A1 'strncpy(info.susfs_variant' "$SUSFS_C" | grep -q 'susfs_variant\[SUSFS_MAX_VARIANT_BUFSIZE-1\]'; then
    sed -i '/strncpy(info.susfs_variant, SUSFS_VARIANT, SUSFS_MAX_VARIANT_BUFSIZE-1);/a \\tinfo.susfs_variant[SUSFS_MAX_VARIANT_BUFSIZE-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3h. susfs_show_version null-termination
if ! grep -A1 'strncpy(info.susfs_version' "$SUSFS_C" | grep -q 'susfs_version\[SUSFS_MAX_VERSION_BUFSIZE-1\]'; then
    sed -i '/strncpy(info.susfs_version, SUSFS_VERSION, SUSFS_MAX_VERSION_BUFSIZE-1);/a \\tinfo.susfs_version[SUSFS_MAX_VERSION_BUFSIZE-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# 3i. open_redirect: new_entry->target_pathname and new_entry->redirected_pathname
# These appear in susfs_add_open_redirect() — the per-UID variant
# State-based: track pending null-term without consuming lines via getline
if grep -q 'strncpy(new_entry->.*pathname, info\..*pathname, SUSFS_MAX_LEN_PATHNAME' "$SUSFS_C" && \
   ! awk '/strncpy\(new_entry->(target|redirected)_pathname, info\..*, SUSFS_MAX_LEN_PATHNAME-1\);/{found=1;next} found{if($0 !~ /\[SUSFS_MAX_LEN_PATHNAME-1\]/){exit 1}; found=0}' "$SUSFS_C" 2>/dev/null; then
    awk '
    {
        if (pending_field != "") {
            if ($0 !~ /\[SUSFS_MAX_LEN_PATHNAME-1\]/) {
                print pending_indent "new_entry->" pending_field "[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';"
            }
            pending_field = ""
        }
        print
        if ($0 ~ /strncpy\(new_entry->target_pathname, info\.target_pathname, SUSFS_MAX_LEN_PATHNAME-1\);/) {
            match($0, /^[\t]+/)
            pending_indent = substr($0, RSTART, RLENGTH)
            pending_field = "target_pathname"
        } else if ($0 ~ /strncpy\(new_entry->redirected_pathname, info\.redirected_pathname, SUSFS_MAX_LEN_PATHNAME-1\);/) {
            match($0, /^[\t]+/)
            pending_indent = substr($0, RSTART, RLENGTH)
            pending_field = "redirected_pathname"
        }
    }
    END {
        if (pending_field != "") {
            print pending_indent "new_entry->" pending_field "[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';"
        }
    }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "  [=] Section 3i: null-terminators already present"
fi

# --- 4. RCU transition for kstat/open_redirect hash tables (M1) ---
# Readers vastly outnumber writers for both SUS_KSTAT_HLIST and OPEN_REDIRECT_HLIST.
# Transition from spinlock-based protection to RCU: lockless reads, spinlock only
# for writer mutual exclusion with RCU-safe deletion and deferred freeing.

# 4-pre-a. Add struct rcu_head to st_susfs_sus_kstat_hlist for kfree_rcu
if [ -f "$SUSFS_H" ] && ! grep -A5 'struct st_susfs_sus_kstat_hlist' "$SUSFS_H" | grep -q 'struct rcu_head'; then
    echo "[+] Adding rcu_head to st_susfs_sus_kstat_hlist (M1)"
    sed -i '/struct st_susfs_sus_kstat_hlist {/,/};/ {
        /struct hlist_node.*node;/a \\tstruct rcu_head\t\t\t\trcu;
    }' "$SUSFS_H"
    ((fix_count++)) || true
else
    echo "[=] st_susfs_sus_kstat_hlist rcu_head already present"
fi

# 4-pre-b. Add struct rcu_head to st_susfs_open_redirect_hlist for kfree_rcu
if [ -f "$SUSFS_H" ] && ! grep -A5 'struct st_susfs_open_redirect_hlist' "$SUSFS_H" | grep -q 'struct rcu_head'; then
    echo "[+] Adding rcu_head to st_susfs_open_redirect_hlist (M1)"
    sed -i '/struct st_susfs_open_redirect_hlist {/,/};/ {
        /struct hlist_node.*node;/a \\tstruct rcu_head\t\t\t\trcu;
    }' "$SUSFS_H"
    ((fix_count++)) || true
else
    echo "[=] st_susfs_open_redirect_hlist rcu_head already present"
fi

# 4-pre-c. Convert hash_add to hash_add_rcu in susfs_add_sus_kstat
if grep -q 'hash_add(SUS_KSTAT_HLIST' "$SUSFS_C"; then
    echo "[+] Converting hash_add to hash_add_rcu for SUS_KSTAT_HLIST"
    sed -i 's/hash_add(SUS_KSTAT_HLIST,/hash_add_rcu(SUS_KSTAT_HLIST,/g' "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] SUS_KSTAT_HLIST already uses hash_add_rcu"
fi

# 4-pre-d. Convert hash_add to hash_add_rcu in susfs_add_open_redirect
if grep -q 'hash_add(OPEN_REDIRECT_HLIST' "$SUSFS_C"; then
    echo "[+] Converting hash_add to hash_add_rcu for OPEN_REDIRECT_HLIST"
    sed -i 's/hash_add(OPEN_REDIRECT_HLIST,/hash_add_rcu(OPEN_REDIRECT_HLIST,/g' "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] OPEN_REDIRECT_HLIST already uses hash_add_rcu"
fi

# 4a. susfs_update_sus_kstat: complete rewrite with two-phase locking (C6/C7)
# Upstream holds no lock during hash iteration and does hash_del/kfree unlocked.
# Rewrite: Phase 1 (find under lock, copy pathname), Phase 2 (sleeping ops outside
# lock), Phase 3 (re-find under lock, swap with RCU-safe del/add, deferred free).
if ! grep -q 'match_pathname\[SUSFS_MAX_LEN_PATHNAME\]' "$SUSFS_C"; then
    echo "[+] Rewriting susfs_update_sus_kstat lock ordering (C6/C7 + M1 RCU)"
    awk '
    /^void susfs_update_sus_kstat\(void __user \*\*user_info\)/ {
        print "void susfs_update_sus_kstat(void __user **user_info) {"
        print "\tstruct st_susfs_sus_kstat info = {0};"
        print "\tstruct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;"
        print "\tstruct hlist_node *tmp_node;"
        print "\tint bkt;"
        print "\tchar match_pathname[SUSFS_MAX_LEN_PATHNAME];"
        print "\tbool found = false;"
        print ""
        print "\tif (copy_from_user(&info, (struct st_susfs_sus_kstat __user*)*user_info, sizeof(info))) {"
        print "\t\tinfo.err = -EFAULT;"
        print "\t\tgoto out_copy_to_user;"
        print "\t}"
        print ""
        print "\t/* Phase 1: find matching entry under lock, copy pathname */"
        print "\tspin_lock(&susfs_spin_lock_sus_kstat);"
        print "\thash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_node, tmp_entry, node) {"
        print "\t\tif (!strcmp(tmp_entry->info.target_pathname, info.target_pathname)) {"
        print "\t\t\tstrncpy(match_pathname, tmp_entry->info.target_pathname,"
        print "\t\t\t\tSUSFS_MAX_LEN_PATHNAME - 1);"
        print "\t\t\tmatch_pathname[SUSFS_MAX_LEN_PATHNAME - 1] = '"'"'\\0'"'"';"
        print "\t\t\tfound = true;"
        print "\t\t\tbreak;"
        print "\t\t}"
        print "\t}"
        print "\tspin_unlock(&susfs_spin_lock_sus_kstat);"
        print ""
        print "\tif (!found)"
        print "\t\tgoto out_copy_to_user;"
        print ""
        print "\t/* Phase 2: sleeping ops outside any lock */"
        print "\tinfo.err = susfs_update_sus_kstat_inode(match_pathname);"
        print "\tif (info.err)"
        print "\t\tgoto out_copy_to_user;"
        print ""
        print "\tnew_entry = kmalloc(sizeof(struct st_susfs_sus_kstat_hlist), GFP_KERNEL);"
        print "\tif (!new_entry) {"
        print "\t\tinfo.err = -ENOMEM;"
        print "\t\tgoto out_copy_to_user;"
        print "\t}"
        print ""
        print "\t/* Phase 3: re-acquire lock, find entry again, swap (RCU-safe) */"
        print "\tspin_lock(&susfs_spin_lock_sus_kstat);"
        print "\thash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_node, tmp_entry, node) {"
        print "\t\tif (!strcmp(tmp_entry->info.target_pathname, info.target_pathname)) {"
        print "\t\t\tmemcpy(&new_entry->info, &tmp_entry->info, sizeof(tmp_entry->info));"
        print "\t\t\tSUSFS_LOGI(\"updating target_ino from '"'"'%lu'"'"' to '"'"'%lu'"'"' for pathname: '"'"'%s'"'"' in SUS_KSTAT_HLIST\\n\","
        print "\t\t\t\t\t\tnew_entry->info.target_ino, info.target_ino, info.target_pathname);"
        print "\t\t\tnew_entry->target_ino = info.target_ino;"
        print "\t\t\tnew_entry->info.target_ino = info.target_ino;"
        print "\t\t\tif (info.spoofed_size > 0)"
        print "\t\t\t\tnew_entry->info.spoofed_size = info.spoofed_size;"
        print "\t\t\tif (info.spoofed_blocks > 0)"
        print "\t\t\t\tnew_entry->info.spoofed_blocks = info.spoofed_blocks;"
        print "\t\t\thash_del_rcu(&tmp_entry->node);"
        print "\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);"
        print "\t\t\tspin_unlock(&susfs_spin_lock_sus_kstat);"
        print "\t\t\tkfree_rcu(tmp_entry, rcu);"
        print "\t\t\tinfo.err = 0;"
        print "\t\t\tgoto out_copy_to_user;"
        print "\t\t}"
        print "\t}"
        print "\tspin_unlock(&susfs_spin_lock_sus_kstat);"
        print "\tkfree(new_entry);"
        print ""
        print "out_copy_to_user:"
        print "\tif (copy_to_user(&((struct st_susfs_sus_kstat __user*)*user_info)->err, &info.err, sizeof(info.err))) {"
        print "\t\tinfo.err = -EFAULT;"
        print "\t}"
        print "\tSUSFS_LOGI(\"CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\\n\", info.err);"
        print "}"
        # consume original function
        brace = 0
        while ((getline) > 0) {
            if ($0 ~ /\{/) brace++
            if ($0 ~ /\}/) brace--
            if ($0 ~ /^\}/ && brace <= 0) break
        }
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# 4b. susfs_sus_ino_for_generic_fillattr: RCU read-side protection (M1)
# Replaces spinlock-based reader with lockless RCU iteration.
if ! grep -A10 'void susfs_sus_ino_for_generic_fillattr' "$SUSFS_C" | grep -q 'rcu_read_lock\|spin_lock_irqsave'; then
    echo "[+] Adding RCU read protection to susfs_sus_ino_for_generic_fillattr (M1)"
    awk '
    /^void susfs_sus_ino_for_generic_fillattr\(unsigned long ino, struct kstat \*stat\)/ {
        print "void susfs_sus_ino_for_generic_fillattr(unsigned long ino, struct kstat *stat) {"
        print "\tstruct st_susfs_sus_kstat_hlist *entry;"
        print ""
        print "\trcu_read_lock();"
        print "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, ino) {"
        print "\t\tif (entry->target_ino == ino) {"
        print "\t\t\tstat->dev = entry->info.spoofed_dev;"
        print "\t\t\tstat->ino = entry->info.spoofed_ino;"
        print "\t\t\tstat->nlink = entry->info.spoofed_nlink;"
        print "\t\t\tstat->size = entry->info.spoofed_size;"
        print "\t\t\tstat->atime.tv_sec = entry->info.spoofed_atime_tv_sec;"
        print "\t\t\tstat->atime.tv_nsec = entry->info.spoofed_atime_tv_nsec;"
        print "\t\t\tstat->mtime.tv_sec = entry->info.spoofed_mtime_tv_sec;"
        print "\t\t\tstat->mtime.tv_nsec = entry->info.spoofed_mtime_tv_nsec;"
        print "\t\t\tstat->ctime.tv_sec = entry->info.spoofed_ctime_tv_sec;"
        print "\t\t\tstat->ctime.tv_nsec = entry->info.spoofed_ctime_tv_nsec;"
        print "\t\t\tstat->blocks = entry->info.spoofed_blocks;"
        print "\t\t\tstat->blksize = entry->info.spoofed_blksize;"
        print "\t\t\trcu_read_unlock();"
        print "\t\t\treturn;"
        print "\t\t}"
        print "\t}"
        print "\trcu_read_unlock();"
        print "}"
        # consume original function
        brace = 0
        while ((getline) > 0) {
            if ($0 ~ /\{/) brace++
            if ($0 ~ /\}/) brace--
            if ($0 ~ /^\}/ && brace <= 0) break
        }
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# 4c. susfs_sus_ino_for_show_map_vma: RCU read-side protection (M1)
if ! grep -A10 'void susfs_sus_ino_for_show_map_vma' "$SUSFS_C" | grep -q 'rcu_read_lock\|spin_lock_irqsave'; then
    echo "[+] Adding RCU read protection to susfs_sus_ino_for_show_map_vma (M1)"
    awk '
    /^void susfs_sus_ino_for_show_map_vma\(unsigned long ino, dev_t \*out_dev, unsigned long \*out_ino\)/ {
        print "void susfs_sus_ino_for_show_map_vma(unsigned long ino, dev_t *out_dev, unsigned long *out_ino) {"
        print "\tstruct st_susfs_sus_kstat_hlist *entry;"
        print ""
        print "\trcu_read_lock();"
        print "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, ino) {"
        print "\t\tif (entry->target_ino == ino) {"
        print "\t\t\t*out_dev = entry->info.spoofed_dev;"
        print "\t\t\t*out_ino = entry->info.spoofed_ino;"
        print "\t\t\trcu_read_unlock();"
        print "\t\t\treturn;"
        print "\t\t}"
        print "\t}"
        print "\trcu_read_unlock();"
        print "}"
        # consume original function
        brace = 0
        while ((getline) > 0) {
            if ($0 ~ /\{/) brace++
            if ($0 ~ /\}/) brace--
            if ($0 ~ /^\}/ && brace <= 0) break
        }
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# 4d. susfs_get_redirected_path: RCU read + copy-to-stack (C5 + M1)
# getname_kernel() sleeps (GFP_KERNEL alloc), cannot be called under any lock.
# Copy pathname under RCU read-side, call getname_kernel after rcu_read_unlock.
if ! grep -A5 'susfs_get_redirected_path(unsigned long ino)' "$SUSFS_C" | grep -q 'tmp_path\[SUSFS_MAX_LEN_PATHNAME\]'; then
    echo "[+] Fixing susfs_get_redirected_path with RCU read-side (C5 + M1)"
    awk '
    /^struct filename\* susfs_get_redirected_path\(unsigned long ino\)/ {
        print "struct filename* susfs_get_redirected_path(unsigned long ino) {"
        print "\tstruct st_susfs_open_redirect_hlist *entry;"
        print "\tchar tmp_path[SUSFS_MAX_LEN_PATHNAME];"
        print "\tbool found = false;"
        print ""
        print "\trcu_read_lock();"
        print "\thash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node, ino) {"
        print "\t\tif (entry->target_ino == ino) {"
        print "\t\t\tSUSFS_LOGI(\"Redirect for ino: %lu\\n\", ino);"
        print "\t\t\tstrncpy(tmp_path, entry->redirected_pathname, SUSFS_MAX_LEN_PATHNAME - 1);"
        print "\t\t\ttmp_path[SUSFS_MAX_LEN_PATHNAME - 1] = '"'"'\\0'"'"';"
        print "\t\t\tfound = true;"
        print "\t\t\tbreak;"
        print "\t\t}"
        print "\t}"
        print "\trcu_read_unlock();"
        print ""
        print "\tif (found)"
        print "\t\treturn getname_kernel(tmp_path);"
        print "\treturn ERR_PTR(-ENOENT);"
        print "}"
        # consume original function
        in_func = 1
        brace_depth = 0
        next
    }
    in_func {
        if ($0 ~ /\{/) brace_depth++
        if ($0 ~ /\}/) brace_depth--
        if (brace_depth < 0 || ($0 ~ /^\}/ && brace_depth == 0)) {
            in_func = 0
        }
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# --- 5. NULL deref fixes ---
# 5a/5b: kzalloc returns NULL → code dereferences info->err.
# Only replace the block inside if (!info) { ... }, not subsequent error paths.
# Pattern: if (!info) { info->err = -ENOMEM; goto out_copy_to_user; }
# We match the 3-line sequence and replace with SUSFS_LOGE + return.
if grep -q 'if (!info)' "$SUSFS_C" && grep -A1 'if (!info)' "$SUSFS_C" | grep -q 'info->err = -ENOMEM'; then
    echo "[+] Fixing NULL deref in kzalloc error paths"
    awk '
    /if \(!info\) \{/ {
        if (getline l1 > 0 && l1 ~ /info->err = -ENOMEM/) {
            if (getline l2 > 0 && l2 ~ /goto out_copy_to_user/) {
                if (getline l3 > 0 && l3 ~ /\}/) {
                    print "\tif (!info) {"
                    print "\t\tSUSFS_LOGE(\"Failed to allocate memory\\n\");"
                    print "\t\treturn;"
                    print "\t}"
                    next
                }
            }
        }
        print
        if (l1 != "") print l1
        if (l2 != "") print l2
        if (l3 != "") print l3
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] kzalloc NULL deref already fixed"
fi

# --- 6. sus_mount default: keep upstream false (L2) ---
# Upstream defaults to false so zygisk can inspect sus mounts during
# post-fs-data. ZeroMount toggles this via supercall at runtime (brene.rs S06).
echo "[=] sus_mount default: keeping upstream false (toggled at runtime)"

# --- 7. Fix trailing whitespace before kzalloc in cmdline_or_bootconfig ---
sed -i '/void susfs_set_cmdline_or_bootconfig/,/^}/ {
    s/	$/	/
}' "$SUSFS_C"

# --- 8. Fix format specifier: spoofed_size is loff_t (long long), not unsigned int ---
# Upstream uses '%u' for spoofed_size in the #else (non-STAT64) SUSFS_LOGI paths
if grep -q "spoofed_size: '%u'" "$SUSFS_C"; then
    echo "[+] Fixing spoofed_size format specifier (%u -> %llu)"
    sed -i "s/spoofed_size: '%u'/spoofed_size: '%llu'/g" "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] spoofed_size format specifier already correct"
fi

# --- 9. Null guards for susfs_is_base_dentry_* (prevents kernel panic on null base) ---
if grep -q 'return (base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR)' "$SUSFS_C"; then
    echo "[+] Adding null guards to susfs_is_base_dentry functions"
    sed -i 's/return (base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR);/return (base \&\& !IS_ERR(base) \&\& base->d_inode \&\& (base->d_inode->i_mapping->flags \& BIT_ANDROID_DATA_ROOT_DIR));/' "$SUSFS_C"
    sed -i 's/return (base->d_inode->i_mapping->flags & BIT_ANDROID_SDCARD_ROOT_DIR);/return (base \&\& !IS_ERR(base) \&\& base->d_inode \&\& (base->d_inode->i_mapping->flags \& BIT_ANDROID_SDCARD_ROOT_DIR));/' "$SUSFS_C"
    ((fix_count++)) || true
else
    echo "[=] susfs_is_base_dentry null guards already present"
fi

# --- 10. Remove EACCES permission leak from SUS_PATH in GKI patch ---
# Older upstream versions return ERR_PTR(-EACCES) on create/excl lookups,
# which leaks SUSFS presence to detector apps. Replace with blank lines
# to preserve patch hunk line counts.
for patch_file in "$SUSFS_DIR"/50_add_susfs_in_gki-*.patch; do
    [ -f "$patch_file" ] || continue
    if grep -q 'ERR_PTR(-EACCES)' "$patch_file"; then
        echo "[+] Removing EACCES permission leak from $(basename "$patch_file")"
        awk '
        # 5.10: if (flags & (LOOKUP_CREATE | LOOKUP_EXCL)) { return ERR_PTR(-EACCES); }
        /^\+[[:space:]]*if \(flags & \(LOOKUP_CREATE \| LOOKUP_EXCL\)\) \{/ {
            print "+"; getline; print "+"; getline; print "+"
            next
        }
        # 6.6: if (create_flags) { dentry = ERR_PTR(-EACCES); goto unlock; }
        /^\+[[:space:]]*if \(create_flags\) \{/ {
            saved = $0
            if (getline > 0 && $0 ~ /ERR_PTR\(-EACCES\)/) {
                print "+"; print "+"
                getline; print "+"; getline; print "+"
                next
            }
            print saved
        }
        { print }
        ' "$patch_file" > "$patch_file.tmp" && mv "$patch_file.tmp" "$patch_file"
        ((fix_count++)) || true
    else
        echo "[=] No EACCES permission leak in $(basename "$patch_file")"
    fi
done

# --- 11. susfs_run_sus_path_loop: move kern_path() outside RCU (C1) ---
# kern_path() sleeps (dcache mutex, GFP_KERNEL alloc). Calling it inside
# rcu_read_lock() blocks RCU grace periods and causes softlockup on 2GB devices.
# Three-phase fix: count under RCU, kmalloc outside, copy under RCU, resolve outside.
if ! grep -q 'kmalloc_array.*SUSFS_MAX_LEN_PATHNAME' "$SUSFS_C"; then
    echo "[+] Fixing kern_path inside RCU in susfs_run_sus_path_loop (C1)"
    awk '
    /^void susfs_run_sus_path_loop\(uid_t uid\)/ {
        print "void susfs_run_sus_path_loop(uid_t uid) {"
        print "\tstruct st_susfs_sus_path_list *cursor = NULL;"
        print "\tstruct path path;"
        print "\tstruct inode *inode;"
        print "\tstruct fuse_inode *fi = NULL;"
        print "\tchar (*pathnames)[SUSFS_MAX_LEN_PATHNAME] = NULL;"
        print "\tint count = 0, i, max_count = 0;"
        print ""
        print "\trcu_read_lock();"
        print "\tlist_for_each_entry_rcu(cursor, &LH_SUS_PATH_LOOP, list) {"
        print "\t\tmax_count++;"
        print "\t}"
        print "\trcu_read_unlock();"
        print ""
        print "\tif (max_count == 0)"
        print "\t\treturn;"
        print ""
        print "\tpathnames = kmalloc_array(max_count, SUSFS_MAX_LEN_PATHNAME, GFP_KERNEL);"
        print "\tif (!pathnames) {"
        print "\t\tSUSFS_LOGE(\"failed to allocate pathname array for sus_path_loop\\n\");"
        print "\t\treturn;"
        print "\t}"
        print ""
        print "\trcu_read_lock();"
        print "\tlist_for_each_entry_rcu(cursor, &LH_SUS_PATH_LOOP, list) {"
        print "\t\tif (count >= max_count)"
        print "\t\t\tbreak;"
        print "\t\tstrncpy(pathnames[count], cursor->info.target_pathname,"
        print "\t\t\tSUSFS_MAX_LEN_PATHNAME - 1);"
        print "\t\tpathnames[count][SUSFS_MAX_LEN_PATHNAME - 1] = '"'"'\\0'"'"';"
        print "\t\tcount++;"
        print "\t}"
        print "\trcu_read_unlock();"
        print ""
        print "\tfor (i = 0; i < count; i++) {"
        print "\t\tif (!kern_path(pathnames[i], 0, &path)) {"
        print "\t\t\tinode = d_backing_inode(path.dentry);"
        print "\t\t\tif (!inode || !inode->i_mapping) {"
        print "\t\t\t\tpath_put(&path);"
        print "\t\t\t\tcontinue;"
        print "\t\t\t}"
        print "\t\t\tif (inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {"
        print "\t\t\t\tfi = get_fuse_inode(inode);"
        print "\t\t\t\tif (!fi) {"
        print "\t\t\t\t\tSUSFS_LOGE(\"fi is NULL\\n\");"
        print "\t\t\t\t\tpath_put(&path);"
        print "\t\t\t\t\tcontinue;"
        print "\t\t\t\t}"
        print "\t\t\t\tset_bit(AS_FLAGS_SUS_PATH, &fi->inode.i_mapping->flags);"
        print "\t\t\t} else {"
        print "\t\t\t\tset_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags);"
        print "\t\t\t}"
        print "\t\t\tpath_put(&path);"
        print "\t\t\tSUSFS_LOGI(\"re-flag AS_FLAGS_SUS_PATH on path '"'"'%s'"'"' for uid: %u\\n\","
        print "\t\t\t\tpathnames[i], uid);"
        print "\t\t}"
        print "\t}"
        print "\tkfree(pathnames);"
        print "}"
        # consume original function
        brace = 0
        while ((getline) > 0) {
            if ($0 ~ /\{/) brace++
            if ($0 ~ /\}/) brace--
            if ($0 ~ /^\}/ && brace <= 0) break
        }
        next
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    ((fix_count++)) || true
fi

# --- 12. susfs_spoof_uname: replace spin_is_locked with proper locking (L1) ---
# spin_is_locked() is a debug/diagnostic function, not a synchronization
# primitive. Returns false on UP kernels. Replace with spin_lock/spin_unlock.
if grep -q 'spin_is_locked(&susfs_spin_lock_set_uname)' "$SUSFS_C"; then
    echo "[+] Fixing racy lockless read in susfs_spoof_uname (L1)"
    # Remove the spin_is_locked condition from the early-return check
    sed -i 's/if (unlikely(my_uname.release\[0\] == '"'"'\\0'"'"' || spin_is_locked(\&susfs_spin_lock_set_uname)))/if (unlikely(my_uname.release[0] == '"'"'\\0'"'"'))/' "$SUSFS_C"
    # Add spin_lock before the first strncpy and spin_unlock after the second
    sed -i '/^void susfs_spoof_uname/,/^}/ {
        /strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);/i \\tspin_lock(\&susfs_spin_lock_set_uname);
    }' "$SUSFS_C"
    # Find the last strncpy in the function (tmp->version) and add unlock after it
    # Account for possible null-term line added by 3f
    sed -i '/^void susfs_spoof_uname/,/^}/ {
        /^}/ i\\tspin_unlock(\&susfs_spin_lock_set_uname);
    }' "$SUSFS_C"
    ((fix_count++)) || true
fi

# --- 13. Remove redundant target_pathname field from st_susfs_sus_path_list (L6) ---
# The struct has both info.target_pathname[256] and a standalone target_pathname[256].
# Both are populated identically. Remove the redundant field and redirect all references.
if [ -f "$SUSFS_H" ] && grep -q 'target_pathname\[SUSFS_MAX_LEN_PATHNAME\]' "$SUSFS_H"; then
    # Only apply if the redundant field exists in the list struct
    if sed -n '/struct st_susfs_sus_path_list/,/};/p' "$SUSFS_H" | grep -q '^\s*char.*target_pathname\[SUSFS_MAX_LEN_PATHNAME\]'; then
        echo "[+] Removing redundant target_pathname from st_susfs_sus_path_list (L6)"
        # Remove the standalone target_pathname field from the struct in susfs.h
        sed -i '/struct st_susfs_sus_path_list/,/};/ {
            /^[[:space:]]*char[[:space:]]*target_pathname\[SUSFS_MAX_LEN_PATHNAME\];/d
        }' "$SUSFS_H"
        # Remove the redundant strncpy and its null-term in susfs.c
        sed -i '/strncpy(new_list->target_pathname, info.target_pathname/d' "$SUSFS_C"
        # Remove null-term lines for the standalone field (before rename)
        sed -i '/^[[:space:]]*new_list->target_pathname\[SUSFS_MAX_LEN_PATHNAME-1\]/d' "$SUSFS_C"
        # Redirect remaining ->target_pathname to ->info.target_pathname
        sed -i 's/new_list->target_pathname/new_list->info.target_pathname/g' "$SUSFS_C"
        sed -i 's/cursor->target_pathname/cursor->info.target_pathname/g' "$SUSFS_C"
        ((fix_count++)) || true
    else
        echo "[=] st_susfs_sus_path_list redundant field already removed"
    fi
else
    echo "[=] susfs.h not found or field already removed"
fi

echo "=== Done: $fix_count fixes applied ==="
