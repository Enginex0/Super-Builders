#!/bin/bash
# Applies safety, correctness, and KSU integration fixes to upstream SUSFS.
#
# Phase 1: SUSFS source (susfs.c, susfs.h) — strncpy null-term, RCU
#   transitions, NULL deref, lock ordering, format specifiers, etc.
# Phase 2: KSU source (setuid_hook.c, ksud.c, sucompat.c) — off-by-one,
#   early-boot guard, dead code, WRITE_ONCE barriers.
#
# Usage: ./fix-safety.sh <SUSFS_DIR> <KSU_DIR> [KSU_VARIANT]

set -euo pipefail

SUSFS_DIR="${1:?Usage: $0 <SUSFS_DIR> <KSU_DIR> [KSU_VARIANT]}"
KSU_DIR="${2:?Usage: $0 <SUSFS_DIR> <KSU_DIR> [KSU_VARIANT]}"
KSU_VARIANT="${3:-}"

SUSFS_C="$SUSFS_DIR/fs/susfs.c"
SUSFS_H="$SUSFS_DIR/include/linux/susfs.h"

for f in "$SUSFS_C" "$SUSFS_H"; do
    [ -f "$f" ] || { echo "FATAL: missing $f"; exit 1; }
done

# Upstream has been observed with literal \x00 in susfs_get_redirected_path
python3 - "$SUSFS_C" <<'PYEOF'
import sys
p = sys.argv[1]
data = open(p, 'rb').read()
if b'\x00' in data:
    print('[+] Scrubbing null bytes from susfs.c')
    open(p, 'wb').write(data.replace(b'\x00', b'0'))
PYEOF

echo "=== fix-susfs: safety ==="
fix_count=0

# -- Trailing whitespace in disabled log macros --
if grep -q 'SUSFS_LOGI(fmt, \.\.\.) $' "$SUSFS_C"; then
    echo "[+] Fixing trailing whitespace in disabled log macros"
    sed -i 's/#define SUSFS_LOGI(fmt, \.\.\.) $/#define SUSFS_LOGI(fmt, ...)/' "$SUSFS_C"
    sed -i 's/#define SUSFS_LOGE(fmt, \.\.\.) $/#define SUSFS_LOGE(fmt, ...)/' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- strncpy null-termination fixes --
echo "[+] Applying strncpy null-termination fixes"

# android_data_path.target_pathname
if ! grep -A1 'android_data_path.target_pathname' "$SUSFS_C" | grep -q '\[SUSFS_MAX_LEN_PATHNAME-1\].*\\0'; then
    sed -i '/strncpy(android_data_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);/a \\t\tandroid_data_path.target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# sdcard_path.target_pathname
if ! grep -A1 'sdcard_path.target_pathname' "$SUSFS_C" | grep -q '\[SUSFS_MAX_LEN_PATHNAME-1\].*\\0'; then
    sed -i '/strncpy(sdcard_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);/a \\t\tsdcard_path.target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# sus_path: new_list->info.target_pathname + new_list->target_pathname
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
fi

# uname release/version null-termination (L10)
if ! grep -q 'my_uname.release\[__NEW_UTS_LEN\].*\\0' "$SUSFS_C"; then
    sed -i '/^void susfs_set_uname/,/^}/ {
        /spin_unlock(&susfs_spin_lock_set_uname);/i \\tmy_uname.release[__NEW_UTS_LEN] = '"'"'\\0'"'"';\n\tmy_uname.version[__NEW_UTS_LEN] = '"'"'\\0'"'"';
    }' "$SUSFS_C"
    ((fix_count++)) || true
fi

# spoof_uname tmp->release/version null-termination
if ! grep -A1 'strncpy(tmp->release' "$SUSFS_C" | grep -q 'tmp->release\[__NEW_UTS_LEN\]'; then
    sed -i '/strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);/a \\ttmp->release[__NEW_UTS_LEN] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

if ! grep -A1 'strncpy(tmp->version' "$SUSFS_C" | grep -q 'tmp->version\[__NEW_UTS_LEN\]'; then
    sed -i '/strncpy(tmp->version, my_uname.version, __NEW_UTS_LEN);/a \\ttmp->version[__NEW_UTS_LEN] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# susfs_show_variant null-termination
if ! grep -A1 'strncpy(info.susfs_variant' "$SUSFS_C" | grep -q 'susfs_variant\[SUSFS_MAX_VARIANT_BUFSIZE-1\]'; then
    sed -i '/strncpy(info.susfs_variant, SUSFS_VARIANT, SUSFS_MAX_VARIANT_BUFSIZE-1);/a \\tinfo.susfs_variant[SUSFS_MAX_VARIANT_BUFSIZE-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# susfs_show_version null-termination
if ! grep -A1 'strncpy(info.susfs_version' "$SUSFS_C" | grep -q 'susfs_version\[SUSFS_MAX_VERSION_BUFSIZE-1\]'; then
    sed -i '/strncpy(info.susfs_version, SUSFS_VERSION, SUSFS_MAX_VERSION_BUFSIZE-1);/a \\tinfo.susfs_version[SUSFS_MAX_VERSION_BUFSIZE-1] = '"'"'\\0'"'"';' "$SUSFS_C"
    ((fix_count++)) || true
fi

# open_redirect: new_entry->target_pathname and new_entry->redirected_pathname
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
fi

# -- RCU transition for kstat/open_redirect hash tables (M1) --

# rcu_head in st_susfs_sus_kstat_hlist
if ! grep -A5 'struct st_susfs_sus_kstat_hlist' "$SUSFS_H" | grep -q 'struct rcu_head'; then
    echo "[+] Adding rcu_head to st_susfs_sus_kstat_hlist"
    sed -i '/struct st_susfs_sus_kstat_hlist {/,/};/ {
        /struct hlist_node.*node;/a \\tstruct rcu_head\t\t\t\trcu;
    }' "$SUSFS_H"
    ((fix_count++)) || true
fi

# rcu_head in st_susfs_open_redirect_hlist
if ! grep -A5 'struct st_susfs_open_redirect_hlist' "$SUSFS_H" | grep -q 'struct rcu_head'; then
    echo "[+] Adding rcu_head to st_susfs_open_redirect_hlist"
    sed -i '/struct st_susfs_open_redirect_hlist {/,/};/ {
        /struct hlist_node.*node;/a \\tstruct rcu_head\t\t\t\trcu;
    }' "$SUSFS_H"
    ((fix_count++)) || true
fi

# hash_add -> hash_add_rcu for SUS_KSTAT_HLIST
if grep -q 'hash_add(SUS_KSTAT_HLIST' "$SUSFS_C"; then
    sed -i 's/hash_add(SUS_KSTAT_HLIST,/hash_add_rcu(SUS_KSTAT_HLIST,/g' "$SUSFS_C"
    ((fix_count++)) || true
fi

# hash_add -> hash_add_rcu for OPEN_REDIRECT_HLIST
if grep -q 'hash_add(OPEN_REDIRECT_HLIST' "$SUSFS_C"; then
    sed -i 's/hash_add(OPEN_REDIRECT_HLIST,/hash_add_rcu(OPEN_REDIRECT_HLIST,/g' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- susfs_update_sus_kstat: two-phase locking rewrite (C6/C7 + M1 RCU) --
if ! grep -q 'match_pathname\[SUSFS_MAX_LEN_PATHNAME\]' "$SUSFS_C"; then
    echo "[+] Rewriting susfs_update_sus_kstat lock ordering (C6/C7 + M1)"
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

# -- RCU read-side for susfs_sus_ino_for_generic_fillattr (M1) --
if ! grep -A10 'void susfs_sus_ino_for_generic_fillattr' "$SUSFS_C" | grep -q 'rcu_read_lock\|spin_lock_irqsave'; then
    echo "[+] Adding RCU read protection to susfs_sus_ino_for_generic_fillattr"
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

# -- RCU read-side for susfs_sus_ino_for_show_map_vma (M1) --
if ! grep -A10 'void susfs_sus_ino_for_show_map_vma' "$SUSFS_C" | grep -q 'rcu_read_lock\|spin_lock_irqsave'; then
    echo "[+] Adding RCU read protection to susfs_sus_ino_for_show_map_vma"
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

# -- susfs_get_redirected_path: RCU read + copy-to-stack (C5 + M1) --
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

# -- NULL deref in kzalloc error paths --
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
fi

# -- Trailing whitespace before kzalloc in cmdline_or_bootconfig --
sed -i '/void susfs_set_cmdline_or_bootconfig/,/^}/ {
    s/	$/	/
}' "$SUSFS_C"

# -- Format specifier: spoofed_size is loff_t, not unsigned int --
if grep -q "spoofed_size: '%u'" "$SUSFS_C"; then
    echo "[+] Fixing spoofed_size format specifier (%u -> %llu)"
    sed -i "s/spoofed_size: '%u'/spoofed_size: '%llu'/g" "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- Null guards for susfs_is_base_dentry_* --
if grep -q 'return (base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR)' "$SUSFS_C"; then
    echo "[+] Adding null guards to susfs_is_base_dentry functions"
    sed -i 's/return (base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR);/return (base \&\& !IS_ERR(base) \&\& base->d_inode \&\& (base->d_inode->i_mapping->flags \& BIT_ANDROID_DATA_ROOT_DIR));/' "$SUSFS_C"
    sed -i 's/return (base->d_inode->i_mapping->flags & BIT_ANDROID_SDCARD_ROOT_DIR);/return (base \&\& !IS_ERR(base) \&\& base->d_inode \&\& (base->d_inode->i_mapping->flags \& BIT_ANDROID_SDCARD_ROOT_DIR));/' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- Remove EACCES permission leak from SUS_PATH in GKI patch --
for patch_file in "$SUSFS_DIR"/50_add_susfs_in_gki-*.patch; do
    [ -f "$patch_file" ] || continue
    if grep -q 'ERR_PTR(-EACCES)' "$patch_file"; then
        echo "[+] Removing EACCES permission leak from $(basename "$patch_file")"
        awk '
        /^\+[[:space:]]*if \(flags & \(LOOKUP_CREATE \| LOOKUP_EXCL\)\) \{/ {
            print "+"; getline; print "+"; getline; print "+"
            next
        }
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
    fi
done

# -- Extend kallsyms filter to hide zeromount symbols (M4) --
for patch_file in "$SUSFS_DIR"/50_add_susfs_in_gki-*.patch; do
    [ -f "$patch_file" ] || continue
    if grep -q 'susfs_starts_with(iter->name, "is_zygote")' "$patch_file" && \
       ! grep -q 'susfs_starts_with(iter->name, "zeromount")' "$patch_file"; then
        echo "[+] Extending kallsyms filter for zeromount symbols in $(basename "$patch_file")"
        sed -i 's/susfs_starts_with(iter->name, "is_zygote"))/susfs_starts_with(iter->name, "is_zygote") ||\n+\t\t\tsusfs_starts_with(iter->name, "zeromount"))/' "$patch_file"
        ((fix_count++)) || true
    fi
done

# -- fsnotify: defer cleanup outside SRCU context to prevent deadlock --
if grep -q 'msleep(5000)' "$SUSFS_C" && grep -q 'susfs_handle_sdcard_inode_event' "$SUSFS_C"; then
    echo "[+] Fixing fsnotify handler SRCU deadlock (deferred cleanup via delayed_work)"

    # workqueue.h for queue_delayed_work
    if ! grep -q '#include <linux/workqueue.h>' "$SUSFS_C"; then
        sed -i '/#include <linux\/delay.h>/a #include <linux/workqueue.h>' "$SUSFS_C"
    fi

    # static vars + cleanup function before the handler
    awk '
    /^static int susfs_handle_sdcard_inode_event/ {
        print "static unsigned long sdcard_cleanup_scheduled;"
        print "static struct delayed_work sdcard_cleanup_dwork;"
        print ""
        print "static void susfs_sdcard_cleanup_fn(struct work_struct *work)"
        print "{"
        print "\tstruct fsnotify_group *grp;"
        print "\tstruct inode *inode;"
        print ""
        print "\tSUSFS_LOGI(\"set susfs_is_sdcard_android_data_decrypted to true\\n\");"
        print "\tWRITE_ONCE(susfs_is_sdcard_android_data_decrypted, true);"
        print ""
        print "\tSUSFS_LOGI(\"cleaning up fsnotify sdcard watch\\n\");"
        print ""
        print "\tgrp = xchg(&g, NULL);"
        print "\tif (grp)"
        print "\t\tfsnotify_destroy_group(grp);"
        print ""
        print "\tinode = xchg(&g_watch.inode, NULL);"
        print "\tif (inode)"
        print "\t\tiput(inode);"
        print ""
        print "\tif (g_watch.kpath.mnt) {"
        print "\t\tpath_put(&g_watch.kpath);"
        print "\t\tmemset(&g_watch.kpath, 0, sizeof(g_watch.kpath));"
        print "\t}"
        print "}"
        print ""
    }
    { print }
    ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"

    # rewrite the handler itself
    awk '
    /^static int susfs_handle_sdcard_inode_event/ {
        print "static int susfs_handle_sdcard_inode_event(struct fsnotify_mark *mark, u32 mask,"
        print "\t\t\t\t\t\t\t\t\t\t\tstruct inode *inode, struct inode *dir,"
        print "\t\t\t\t\t\t\t\t\t\t\tconst struct qstr *file_name, u32 cookie)"
        print "{"
        print "\tif (!file_name || file_name->len != 7 ||"
        print "\t    memcmp(file_name->name, \"Android\", 7))"
        print "\t\treturn 0;"
        print ""
        print "\tif (test_and_set_bit(0, &sdcard_cleanup_scheduled))"
        print "\t\treturn 0;"
        print ""
        print "\tSUSFS_LOGI(\"'"'"'Android'"'"' detected, mask: 0x%x\\n\", mask);"
        print "\tSUSFS_LOGI(\"deferring cleanup for 5 seconds\\n\");"
        print "\tqueue_delayed_work(system_unbound_wq, &sdcard_cleanup_dwork, 5 * HZ);"
        print "\treturn 0;"
        print "}"
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

    # INIT_DELAYED_WORK before the #if/fsnotify_alloc_group block
    if ! grep -q 'INIT_DELAYED_WORK' "$SUSFS_C"; then
        awk '
        /LINUX_VERSION_CODE.*KERNEL_VERSION/ && !init_done {
            if (getline next_line > 0) {
                if (next_line ~ /fsnotify_alloc_group/) {
                    print "\tINIT_DELAYED_WORK(&sdcard_cleanup_dwork, susfs_sdcard_cleanup_fn);"
                    print ""
                    init_done = 1
                }
                print $0
                print next_line
                next
            }
        }
        { print }
        ' "$SUSFS_C" > "$SUSFS_C.tmp" && mv "$SUSFS_C.tmp" "$SUSFS_C"
    fi

    ((fix_count++)) || true
fi

# -- FUSE include for C1 two-pass kern_path (5.10 has no public FUSE_SUPER_MAGIC) --
if ! grep -q 'fuse/fuse_i\.h' "$SUSFS_C"; then
    echo "[+] Adding fuse/fuse_i.h include for FUSE_SUPER_MAGIC"
    sed -i '/#include <linux\/susfs\.h>/a\
#include "fuse/fuse_i.h"\
\
#ifndef FUSE_SUPER_MAGIC\
#define FUSE_SUPER_MAGIC 0x65735546\
#endif' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- sus_path_loop: move kern_path() outside RCU (C1) --
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

# -- susfs_spoof_uname: replace spin_is_locked with proper locking (L1) --
if grep -q 'spin_is_locked(&susfs_spin_lock_set_uname)' "$SUSFS_C"; then
    echo "[+] Fixing racy lockless read in susfs_spoof_uname (L1)"
    sed -i 's/if (unlikely(my_uname.release\[0\] == '"'"'\\0'"'"' || spin_is_locked(\&susfs_spin_lock_set_uname)))/if (unlikely(my_uname.release[0] == '"'"'\\0'"'"'))/' "$SUSFS_C"
    sed -i '/^void susfs_spoof_uname/,/^}/ {
        /strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);/i \\tspin_lock(\&susfs_spin_lock_set_uname);
    }' "$SUSFS_C"
    sed -i '/^void susfs_spoof_uname/,/^}/ {
        /^}/ i\\tspin_unlock(\&susfs_spin_lock_set_uname);
    }' "$SUSFS_C"
    ((fix_count++)) || true
fi

# -- Remove redundant target_pathname from st_susfs_sus_path_list (L6) --
if [ -f "$SUSFS_H" ] && grep -q 'target_pathname\[SUSFS_MAX_LEN_PATHNAME\]' "$SUSFS_H"; then
    if sed -n '/struct st_susfs_sus_path_list/,/};/p' "$SUSFS_H" | grep -q '^\s*char.*target_pathname\[SUSFS_MAX_LEN_PATHNAME\]'; then
        echo "[+] Removing redundant target_pathname from st_susfs_sus_path_list (L6)"
        sed -i '/struct st_susfs_sus_path_list/,/};/ {
            /^[[:space:]]*char[[:space:]]*target_pathname\[SUSFS_MAX_LEN_PATHNAME\];/d
        }' "$SUSFS_H"
        sed -i '/strncpy(new_list->target_pathname, info.target_pathname/d' "$SUSFS_C"
        sed -i '/^[[:space:]]*new_list->target_pathname\[SUSFS_MAX_LEN_PATHNAME-1\]/d' "$SUSFS_C"
        sed -i 's/new_list->target_pathname/new_list->info.target_pathname/g' "$SUSFS_C"
        sed -i 's/cursor->target_pathname/cursor->info.target_pathname/g' "$SUSFS_C"
        ((fix_count++)) || true
    fi
fi

echo "=== fix-susfs: safety done ($fix_count fixes) ==="


# Phase 2: KSU integration fixes

SETUID_HOOK="$KSU_DIR/kernel/setuid_hook.c"
KSUD="$KSU_DIR/kernel/ksud.c"
SUCOMPAT="$KSU_DIR/kernel/sucompat.c"

for f in "$SETUID_HOOK" "$KSUD" "$SUCOMPAT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f"; exit 1; }
done

echo "=== fix-susfs: ksu-integration ==="
ksu_count=0

# -- Off-by-one in is_zygote_normal_app_uid (L3) --
if grep -q 'uid >= 10000 && uid < 19999' "$SETUID_HOOK"; then
    echo "[+] Fixing off-by-one in is_zygote_normal_app_uid (uid < 19999 -> < 20000)"
    sed -i 's/uid >= 10000 && uid < 19999/uid >= 10000 \&\& uid < 20000/' "$SETUID_HOOK"
    ((ksu_count++)) || true
fi

# -- susfs_zygote_sid == 0 early-boot guard (L7) --
if ! grep -q 'susfs_zygote_sid == 0' "$SETUID_HOOK"; then
    echo "[+] Adding susfs_zygote_sid == 0 early-boot guard"
    sed -i '/if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))/i \
\tif (susfs_zygote_sid == 0) {\
\t\treturn 0;\
\t}\
' "$SETUID_HOOK"
    ((ksu_count++)) || true
fi

# -- Remove redundant ksu_handle_execveat_init call (L4) --
if grep -q '(void)ksu_handle_execveat_init(filename)' "$KSUD"; then
    echo "[+] Removing redundant ksu_handle_execveat_init call from ksud.c"
    sed -i '/#ifdef CONFIG_KSU_SUSFS/{
        N
        /We need to run ksu_handle_execveat_init/{
            N
            /(void)ksu_handle_execveat_init(filename);/{
                N
                /#endif/d
            }
        }
    }' "$KSUD"
    ((ksu_count++)) || true
fi

# -- Remove orphaned extern ksu_handle_execveat_init declaration (L4) --
if grep -q 'extern int ksu_handle_execveat_init' "$KSUD"; then
    echo "[+] Removing orphaned extern ksu_handle_execveat_init declaration"
    sed -i '/#ifdef CONFIG_KSU_SUSFS/{
        N
        /extern int ksu_handle_execveat_init/{
            N
            /#endif/d
        }
    }' "$KSUD"
    ((ksu_count++)) || true
fi

# -- Dead return 0 in ksu_handle_faccessat (L8) --
# ReSukiSU/SukiSU rewrote faccessat — awk guard false-positives on their non-dead returns
if [[ "$KSU_VARIANT" == "ReSukiSU" || "$KSU_VARIANT" == "SukiSU" ]]; then
    echo "[-] Skipping faccessat dead-return fix (not applicable for $KSU_VARIANT)"
elif awk '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
       if (/return 0;/) { count++ }
       if (/^}/ && count >= 2) { found=1; exit 0 }
   } END { exit !found }' "$SUCOMPAT"; then
    echo "[+] Removing dead return 0 in ksu_handle_faccessat"
    sed -i '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
        /[[:space:]]*return 0;$/{
            N
            /\n$/{
                N
                /\n[[:space:]]*return 0;$/{ s/\n\n[[:space:]]*return 0;// }
            }
        }
    }' "$SUCOMPAT"
    ((ksu_count++)) || true
fi

# -- WRITE_ONCE/READ_ONCE for hook flags (L9) --
if grep -q 'ksu_init_rc_hook = false;' "$KSUD"; then
    echo "[+] Wrapping hook flag writers with WRITE_ONCE"
    sed -i 's/ksu_init_rc_hook = false;/WRITE_ONCE(ksu_init_rc_hook, false);/' "$KSUD"
    sed -i 's/ksu_execveat_hook = false;/WRITE_ONCE(ksu_execveat_hook, false);/' "$KSUD"
    sed -i 's/ksu_input_hook = false;/WRITE_ONCE(ksu_input_hook, false);/' "$KSUD"
    ((ksu_count++)) || true
fi

if grep -q 'if (!ksu_input_hook)' "$KSUD"; then
    echo "[+] Wrapping hook flag reader with READ_ONCE"
    sed -i 's/if (!ksu_input_hook)/if (!READ_ONCE(ksu_input_hook))/' "$KSUD"
    ((ksu_count++)) || true
fi

echo "=== fix-susfs: ksu-integration done ($ksu_count fixes) ==="
echo "=== fix-susfs: total $(( fix_count + ksu_count )) fixes ==="
