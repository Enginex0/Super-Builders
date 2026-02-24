#!/bin/bash
# Patches kernel C sources: supercall handlers, zeromount mount display,
# VFS open redirect (all UIDs), and unicode filter.
# Usage: ./patch-kernel-sources.sh KERNEL_DIR SUPERCALLS_PATH SUSFS_SOURCE
set -e

KERNEL_DIR="${1:?KERNEL_COMMON_DIR required}"
SUPERCALLS="${2:?SUPERCALLS path required}"
SUSFS_SOURCE="${3:?SUSFS_SOURCE path required}"

HANDLERS=(
    "susfs_add_sus_kstat_redirect|CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT|CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY|CONFIG_KSU_SUSFS_SUS_KSTAT|susfs_add_sus_kstat_redirect(arg)"
    "susfs_add_open_redirect_all|CMD_SUSFS_ADD_OPEN_REDIRECT_ALL|CMD_SUSFS_ADD_OPEN_REDIRECT|CONFIG_KSU_SUSFS_OPEN_REDIRECT|susfs_add_open_redirect_all(arg)"
)

inject_supercall_handlers() {
    [ -f "$SUPERCALLS" ] || { echo "[-] supercalls.c not found, skipping handler injection"; return 0; }

    local count=0
    for entry in "${HANDLERS[@]}"; do
        IFS='|' read -r func cmd anchor_cmd anchor_endif handler_call <<< "$entry"

        grep -q "$func" "$SUSFS_SOURCE" 2>/dev/null || {
            echo "[-] $func not in source, skipping"
            continue
        }

        grep -q "$cmd" "$SUPERCALLS" && {
            echo "[=] $cmd already present"
            continue
        }

        echo "[+] Injecting $cmd"
        sed -i "/$anchor_cmd/,/#endif.*$anchor_endif/ {
            /#endif.*$anchor_endif/ i\\
        if (cmd == $cmd) {\\
            $handler_call;\\
            return 0;\\
        }
        }" "$SUPERCALLS"
        ((count++)) || true
    done

    echo "[+] $count supercall handlers injected"
}

inject_zeromount_mount_display() {
    local proc_ns="$KERNEL_DIR/fs/proc_namespace.c"
    [ -f "$proc_ns" ] || { echo "FATAL: $proc_ns not found"; exit 1; }

    local count=0

    if grep -q 'susfs_is_uid_zeromount_excluded' "$proc_ns"; then
        echo "[=] zeromount extern already present"
    else
        echo "[+] Injecting zeromount extern declarations"
        sed -i '/^extern bool susfs_is_current_ksu_domain(void);/a #ifdef CONFIG_ZEROMOUNT\nextern bool susfs_is_uid_zeromount_excluded(uid_t uid);\n#endif' "$proc_ns"
        ((count++)) || true
    fi

    local inline_count
    inline_count=$(grep -c '!susfs_is_uid_zeromount_excluded' "$proc_ns" || true)
    if [ "$inline_count" -ge 3 ]; then
        echo "[=] zeromount inline checks already present ($inline_count found)"
    else
        echo "[+] Injecting zeromount checks into show_* functions"
        awk '
        /^\t\t!susfs_is_current_ksu_domain\(\)\)$/ {
            print "\t\t!susfs_is_current_ksu_domain()"
            print "#ifdef CONFIG_ZEROMOUNT"
            print "\t\t&& !susfs_is_uid_zeromount_excluded(current_uid().val)"
            print "#endif"
            print "\t\t)"
            next
        }
        { print }
        ' "$proc_ns" > "$proc_ns.tmp" && mv "$proc_ns.tmp" "$proc_ns"
        ((count++)) || true
    fi

    local ref_count
    ref_count=$(grep -c 'susfs_is_uid_zeromount_excluded' "$proc_ns" || true)
    [ "$ref_count" -ge 4 ] || { echo "FATAL: expected at least 4 zeromount references, found $ref_count"; exit 1; }

    echo "[+] Mount display: $count injections applied"
}

inject_vfs_open_redirect_all() {
    local namei="$KERNEL_DIR/fs/namei.c"
    [ -f "$namei" ] || { echo "FATAL: $namei not found"; exit 1; }

    local count=0

    if grep -q 'susfs_get_redirected_path_all' "$namei"; then
        echo "[=] susfs_get_redirected_path_all extern already present"
    else
        echo "[+] Injecting susfs_get_redirected_path_all extern"
        sed -i '/^extern struct filename\* susfs_get_redirected_path(unsigned long ino);/a extern struct filename* susfs_get_redirected_path_all(unsigned long ino);' "$namei"
        ((count++)) || true
    fi

    if grep -q 'AS_FLAGS_OPEN_REDIRECT_ALL' "$namei"; then
        echo "[=] AS_FLAGS_OPEN_REDIRECT_ALL check already present"
    else
        echo "[+] Replacing do_filp_open redirect block with two-branch check"
        awk '
        /^#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT/ {
            block = $0 "\n"
            is_redirect_block = 0
            while ((getline line) > 0) {
                block = block line "\n"
                if (line ~ /AS_FLAGS_OPEN_REDIRECT|BIT_OPEN_REDIRECT/) is_redirect_block = 1
                if (line ~ /^#endif/) break
            }
            if (is_redirect_block && !already_replaced) {
                already_replaced = 1
                print "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT"
                print "\tif (!IS_ERR(filp)) {"
                print "\t\tif (unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT_ALL, &filp->f_inode->i_mapping->flags))) {"
                print "\t\t\tfake_pathname = susfs_get_redirected_path_all(filp->f_inode->i_ino);"
                print "\t\t\tif (!IS_ERR(fake_pathname)) {"
                print "\t\t\t\trestore_nameidata();"
                print "\t\t\t\tfilp_close(filp, NULL);"
                print "\t\t\t\tset_nameidata(&nd, dfd, fake_pathname);"
                print "\t\t\t\tfilp = path_openat(&nd, op, flags | LOOKUP_RCU);"
                print "\t\t\t\tif (unlikely(filp == ERR_PTR(-ECHILD)))"
                print "\t\t\t\t\tfilp = path_openat(&nd, op, flags);"
                print "\t\t\t\tif (unlikely(filp == ERR_PTR(-ESTALE)))"
                print "\t\t\t\t\tfilp = path_openat(&nd, op, flags | LOOKUP_REVAL);"
                print "\t\t\t\trestore_nameidata();"
                print "\t\t\t\tputname(fake_pathname);"
                print "\t\t\t\treturn filp;"
                print "\t\t\t}"
                print "\t\t} else if (unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &filp->f_inode->i_mapping->flags) &&"
                print "\t\t\tcurrent_uid().val < 2000))"
                print "\t\t{"
                print "\t\t\tfake_pathname = susfs_get_redirected_path(filp->f_inode->i_ino);"
                print "\t\t\tif (!IS_ERR(fake_pathname)) {"
                print "\t\t\t\trestore_nameidata();"
                print "\t\t\t\tfilp_close(filp, NULL);"
                print "\t\t\t\tset_nameidata(&nd, dfd, fake_pathname);"
                print "\t\t\t\tfilp = path_openat(&nd, op, flags | LOOKUP_RCU);"
                print "\t\t\t\tif (unlikely(filp == ERR_PTR(-ECHILD)))"
                print "\t\t\t\t\tfilp = path_openat(&nd, op, flags);"
                print "\t\t\t\tif (unlikely(filp == ERR_PTR(-ESTALE)))"
                print "\t\t\t\t\tfilp = path_openat(&nd, op, flags | LOOKUP_REVAL);"
                print "\t\t\t\trestore_nameidata();"
                print "\t\t\t\tputname(fake_pathname);"
                print "\t\t\t\treturn filp;"
                print "\t\t\t}"
                print "\t\t}"
                print "\t}"
                print "#endif"
            } else {
                printf "%s", block
            }
            next
        }
        { print }
        ' "$namei" > "$namei.tmp" && mv "$namei.tmp" "$namei"
        ((count++)) || true
    fi

    grep -q 'susfs_get_redirected_path_all' "$namei" || { echo "FATAL: susfs_get_redirected_path_all not found after injection"; exit 1; }
    grep -q 'AS_FLAGS_OPEN_REDIRECT_ALL' "$namei" || { echo "FATAL: AS_FLAGS_OPEN_REDIRECT_ALL not found after injection"; exit 1; }

    echo "[+] VFS open redirect: $count injections applied"
}

inject_susfs_include() {
    sed -i "/$1/a\\
#ifdef CONFIG_KSU_SUSFS\\
#include <linux/susfs.h>\\
#endif" "$2"
}

patch_unicode_namei() {
    local f="$KERNEL_DIR/fs/namei.c"
    [ -f "$f" ] && grep -q "CONFIG_KSU_SUSFS_UNICODE_FILTER" "$f" && return

    echo "[+] $f"
    inject_susfs_include '#include <linux\/uaccess.h>' "$f"

    # do_mkdirat
    sed -i '/unsigned int lookup_flags = LOOKUP_DIRECTORY;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(pathname)) {\
\t\treturn -ENOENT;\
\t}\
#endif' "$f"

    # unlinkat
    sed -i '/if ((flag & ~AT_REMOVEDIR) != 0)/,/return -EINVAL;/{
        /return -EINVAL;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(pathname)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"

    # do_symlinkat
    sed -i '/^static long do_symlinkat/,/unsigned int lookup_flags = 0;/{
        /unsigned int lookup_flags = 0;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(newname)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"

    # do_linkat
    sed -i '/^static int do_linkat/,/int error;/{
        /int error;$/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(newname)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"

    # do_renameat2
    sed -i '/^int do_renameat2/,/int error = -EINVAL;/{
        /int error = -EINVAL;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(from->uptr) ||\
\t    susfs_check_unicode_bypass(to->uptr)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"
}

patch_unicode_open() {
    local f="$KERNEL_DIR/fs/open.c"
    [ -f "$f" ] && grep -q "CONFIG_KSU_SUSFS_UNICODE_FILTER" "$f" && return

    echo "[+] $f"
    inject_susfs_include '#include <linux\/compat.h>' "$f"

    sed -i '/^static long do_sys_openat2/,/struct filename \*tmp;/{
        /struct filename \*tmp;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(filename)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"
}

patch_unicode_stat() {
    local f="$KERNEL_DIR/fs/stat.c"
    [ -f "$f" ] && grep -q "CONFIG_KSU_SUSFS_UNICODE_FILTER" "$f" && return

    echo "[+] $f"
    inject_susfs_include '#include <linux\/compat.h>' "$f"

    # vfs_statx
    sed -i '/^static int vfs_statx/,/int error;/{
        /int error;$/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(filename)) {\
\t\treturn -ENOENT;\
\t}\
#endif
    }' "$f"

    # do_readlinkat
    sed -i '/unsigned int lookup_flags = LOOKUP_EMPTY;/a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\tif (susfs_check_unicode_bypass(pathname)) {\
\t\treturn -ENOENT;\
\t}\
#endif' "$f"
}

inject_stat_hide() {
    local f="$KERNEL_DIR/fs/stat.c"
    [ -f "$f" ] && grep -q "CONFIG_KSU_SUSFS" "$f" && grep -q "susfs_is_hidden_name" "$f" && return

    echo "[+] $f"

    sed -i '/#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT/{
        N
        /extern void susfs_sus_ino_for_generic_fillattr/a\
extern bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid);
    }' "$f"

    awk '
    /error = vfs_getattr\(&path, stat,/ && !stat_hide_done {
        print "\tif (current_uid().val >= 10000 &&"
        print "\t    susfs_is_current_proc_umounted()) {"
        print "\t\tstruct dentry *_d = path.dentry;"
        print "\t\tstruct dentry *_par = _d->d_parent;"
        print "\t\tif (_par && _par != _d && _par->d_parent) {"
        print "\t\t\tint _plen = _par->d_name.len;"
        print "\t\t\tif ((_plen == 4 && !memcmp(_par->d_name.name, \"data\", 4)) ||"
        print "\t\t\t    (_plen == 3 && !memcmp(_par->d_name.name, \"obb\", 3))) {"
        print "\t\t\t\tstruct dentry *_gp = _par->d_parent;"
        print "\t\t\t\tif (_gp->d_name.len == 7 &&"
        print "\t\t\t\t    !memcmp(_gp->d_name.name, \"Android\", 7) &&"
        print "\t\t\t\t    susfs_is_hidden_name(_d->d_name.name,"
        print "\t\t\t\t        _d->d_name.len, current_uid().val)) {"
        print "\t\t\t\t\tprintk_ratelimited(KERN_INFO"
        print "\t\t\t\t\t\t\"susfs_debug: HIDE stat uid=%u name='"'"'%.*s'"'"'\\n\","
        print "\t\t\t\t\t\tcurrent_uid().val, _d->d_name.len, _d->d_name.name);"
        print "\t\t\t\t\tpath_put(&path);"
        print "\t\t\t\t\terror = -ENOENT;"
        print "\t\t\t\t\tgoto out;"
        print "\t\t\t\t}"
        print "\t\t\t}"
        print "\t\t}"
        print "\t}"
        print ""
        stat_hide_done = 1
    }
    { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

inject_access_hide() {
    local f="$KERNEL_DIR/fs/open.c"
    [ -f "$f" ] && grep -q "CONFIG_KSU_SUSFS" "$f" && grep -q "susfs_is_hidden_name" "$f" && return

    echo "[+] $f"

    # ksu_handle_faccessat spans two lines — consume both before appending
    sed -i '/extern int ksu_handle_faccessat/{
        N
        a\
extern bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid);
    }' "$f"

    awk '
    BEGIN { in_faccessat = 0 }
    /^static long do_faccessat\(/ { in_faccessat = 1 }
    in_faccessat && /inode = d_backing_inode\(path\.dentry\)/ && !access_hide_done {
        print "\tif (current_uid().val >= 10000 &&"
        print "\t    susfs_is_current_proc_umounted()) {"
        print "\t\tstruct dentry *_d = path.dentry;"
        print "\t\tstruct dentry *_par = _d->d_parent;"
        print "\t\tif (_par && _par != _d && _par->d_parent) {"
        print "\t\t\tint _plen = _par->d_name.len;"
        print "\t\t\tif ((_plen == 4 && !memcmp(_par->d_name.name, \"data\", 4)) ||"
        print "\t\t\t    (_plen == 3 && !memcmp(_par->d_name.name, \"obb\", 3))) {"
        print "\t\t\t\tstruct dentry *_gp = _par->d_parent;"
        print "\t\t\t\tif (_gp->d_name.len == 7 &&"
        print "\t\t\t\t    !memcmp(_gp->d_name.name, \"Android\", 7) &&"
        print "\t\t\t\t    susfs_is_hidden_name(_d->d_name.name,"
        print "\t\t\t\t        _d->d_name.len, current_uid().val)) {"
        print "\t\t\t\t\tprintk_ratelimited(KERN_INFO"
        print "\t\t\t\t\t\t\"susfs_debug: HIDE access uid=%u name='"'"'%.*s'"'"'\\n\","
        print "\t\t\t\t\t\tcurrent_uid().val, _d->d_name.len, _d->d_name.name);"
        print "\t\t\t\t\tres = -ENOENT;"
        print "\t\t\t\t\tgoto out_path_release;"
        print "\t\t\t\t}"
        print "\t\t\t}"
        print "\t\t}"
        print "\t}"
        print ""
        access_hide_done = 1
        in_faccessat = 0
    }
    { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

inject_supercall_handlers
inject_zeromount_mount_display
inject_vfs_open_redirect_all
patch_unicode_namei
patch_unicode_open
patch_unicode_stat
inject_stat_hide
inject_access_hide

echo "[+] All kernel source patches applied"
