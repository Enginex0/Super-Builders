#!/bin/bash
set -euo pipefail

HELPERS_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION_DIR="$(cd "$HELPERS_DIR/.." && pwd)"
BASELINE="$VERSION_DIR/samsung-e3q-zzhl-dlkm-crc-baseline.tsv"
AUDITOR="$HELPERS_DIR/verify-samsung-dlkm-crcs.sh"
COMPARATOR="$HELPERS_DIR/compare-kmi-variants.sh"
COLLECTOR="$HELPERS_DIR/collect-kmi-symtypes.sh"
CLEAN_FLAGS="$HELPERS_DIR/clean-build-flags.sh"
KASAN_STUB_HELPER="$HELPERS_DIR/apply-kasan-kmi-stub.sh"
XHCI_HOOK_HELPER="$HELPERS_DIR/apply-s928b-dzg1-xhci-hooks.sh"
SAMSUNG_SOURCE_HELPER="$HELPERS_DIR/apply-s928b-zzhl-source-port.sh"
SAMSUNG_SOURCE_PROFILE="$VERSION_DIR/samsung-s928bxxu6zzhl-source.env"
SAMSUNG_TARGET_PROFILE="$VERSION_DIR/samsung-s928bxxu6zzhl-target.env"
SAMSUNG_SOURCE_OVERLAY="$VERSION_DIR/samsung-sm-s928b-17-zzhl-common-port.tar.xz"
SAMSUNG_DEFCONFIG_NORMALIZER="$HELPERS_DIR/normalize-s928b-kleaf-defconfig.sh"
SAMSUNG_SUSFS_NAMESPACE_REPAIR="$HELPERS_DIR/repair-s928b-dzg1-susfs-namespace.sh"
DAILY_AUDIT="$HELPERS_DIR/audit-s928b-daily-config.sh"
BUILD_WORKFLOW="$VERSION_DIR/../.github/workflows/build-resukisu.yml"
SUSFS_ACTION="$VERSION_DIR/../.github/actions/susfs-v2.2/action.yml"
KERNEL_PATCH_HELPER="$VERSION_DIR/../android12-5.10/build-helpers/apply-kernel-patches.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

KERNEL_ROOT="$TMP_DIR/kernel"
SYMVERS_DIR="$KERNEL_ROOT/bazel-bin/common/kernel_aarch64"
VERSION_SOURCE="$KERNEL_ROOT/common/kernel/module/version.c"
mkdir -p "$SYMVERS_DIR" "$(dirname "$VERSION_SOURCE")"

awk '!/^#/ && NF >= 3 {
  print $3 "\t" $1 "\tvmlinux\tEXPORT_SYMBOL"
}' "$BASELINE" > "$SYMVERS_DIR/Module.symvers"

write_loader_policy() {
  local value="$1"
  cat > "$VERSION_SOURCE" <<EOF
static int check_version(void)
{
bad_version:
  pr_warn("disagrees about version of symbol");
  return $value;
}
EOF
}

write_loader_policy 0
mkdir -p "$SYMVERS_DIR/symtypes/kernel/module"
cat > "$SYMVERS_DIR/.config" <<'EOF'
CONFIG_ARM64=y
CONFIG_MODVERSIONS=y
EOF
cat > "$SYMVERS_DIR/symtypes/kernel/module/version.symtypes" <<'EOF'
check_version int check_version ( void )
EOF
git -C "$KERNEL_ROOT/common" init --quiet
git -C "$KERNEL_ROOT/common" config user.name test
git -C "$KERNEL_ROOT/common" config user.email test@example.invalid
git -C "$KERNEL_ROOT/common" add .
git -C "$KERNEL_ROOT/common" commit --quiet -m fixture

"$AUDITOR" "$KERNEL_ROOT" "$BASELINE" "$TMP_DIR/symtypes" symtypes full
grep -qx 'EXACT_COUNT=1681' "$TMP_DIR/symtypes/summary.env"
grep -qx 'REFERENCE_COUNT=795' "$TMP_DIR/symtypes/summary.env"
grep -qx 'VARIANT_COUNT=0' "$TMP_DIR/symtypes/summary.env"
grep -qx 'MISSING_COUNT=0' "$TMP_DIR/symtypes/summary.env"
"$COLLECTOR" "$KERNEL_ROOT" "$TMP_DIR/symtypes" full symtypes
grep -qx 'SYMTYPES_COUNT=1' "$TMP_DIR/symtypes/summary.env"
tar -tzf "$TMP_DIR/symtypes/symtypes.tar.gz" | grep -qx \
  'bazel-bin/common/kernel_aarch64/symtypes/kernel/module/version.symtypes'

if "$AUDITOR" "$KERNEL_ROOT" "$BASELINE" "$TMP_DIR/strict" strict full-strict; then
  echo "Strict audit unexpectedly accepted 795 CRC differences" >&2
  exit 1
fi

write_loader_policy 1
"$AUDITOR" "$KERNEL_ROOT" "$BASELINE" "$TMP_DIR/runtime" runtime-compat full

awk 'BEGIN { changed=0 }
  !changed && $2 == "___pskb_trim" { $1="0xdeadbeef"; changed=1 }
  { print }
' OFS='\t' "$SYMVERS_DIR/Module.symvers" > "$SYMVERS_DIR/Module.symvers.new"
mv "$SYMVERS_DIR/Module.symvers.new" "$SYMVERS_DIR/Module.symvers"

write_loader_policy 0
"$AUDITOR" "$KERNEL_ROOT" "$BASELINE" "$TMP_DIR/variant" symtypes gki-control
grep -qx 'VARIANT_COUNT=1' "$TMP_DIR/variant/summary.env"

if "$AUDITOR" "$KERNEL_ROOT" "$BASELINE" "$TMP_DIR/runtime-mutated" runtime-compat full; then
  echo "Runtime audit unexpectedly accepted an unpinned build CRC" >&2
  exit 1
fi

mkdir -p "$TMP_DIR/artifacts/gki" "$TMP_DIR/artifacts/full"
cp "$TMP_DIR/variant/summary.env" "$TMP_DIR/variant/Module.symvers" "$TMP_DIR/artifacts/gki/"
cp "$TMP_DIR/symtypes/summary.env" "$TMP_DIR/symtypes/Module.symvers" "$TMP_DIR/artifacts/full/"
"$COMPARATOR" "$BASELINE" "$TMP_DIR/artifacts" "$TMP_DIR/comparison"
grep -q $'^gki-control\t1681\t794\t1\t0\tno\t' "$TMP_DIR/comparison/variant-summary.tsv"
grep -q $'^full\t1681\t795\t0\t0\tno\t' "$TMP_DIR/comparison/variant-summary.tsv"

test_strict_daily_config() {
  local config="$TMP_DIR/strict-daily.config"

  awk '
    /^REQUIRED=\(/ { in_required=1; next }
    in_required && /^\)/ { in_required=0; next }
    in_required {
      for (field=1; field<=NF; field++) {
        if ($field ~ /^CONFIG_[A-Z0-9_]+$/) print $field "=y"
      }
    }
  ' "$DAILY_AUDIT" > "$config"
  cat >> "$config" <<'EOF'
# CONFIG_CGROUP_PIDS is not set
# CONFIG_LRU_GEN_STATS is not set
CONFIG_LOG_BUF_SHIFT=22
CONFIG_IP6_NF_NAT=y
# CONFIG_KFENCE is not set
# CONFIG_KASAN is not set
# CONFIG_UBSAN is not set
EOF

  "$DAILY_AUDIT" "$config" false false strict
  if "$DAILY_AUDIT" "$config" false false runtime-compat; then
    echo "Runtime-compatible audit unexpectedly accepted strict-disabled features" >&2
    exit 1
  fi
}

test_strict_daily_config

test_kleaf_kmi_flags() {
  grep -qF 'BAZEL_FLAGS+=(--nokmi_symbol_list_strict_mode --nokmi_symbol_list_violations_check)' \
    "$BUILD_WORKFLOW"
  if grep -qF 'BAZEL_FLAGS+=(--kmi_symbol_list_strict_mode' "$BUILD_WORKFLOW"; then
    echo "Strict workflow uses a positive Kleaf flag unsupported by the pinned wrapper" >&2
    exit 1
  fi
  grep -qF '"$CONFIG_TOOL" --file "$DEFCONFIG_FRAGMENT" --enable "$SYMBOL"' "$BUILD_WORKFLOW"
  grep -qF '"$CONFIG_TOOL" --file "$DEFCONFIG" --undefine "$SYMBOL"' "$BUILD_WORKFLOW"
  grep -qF 'grep -qx "CONFIG_${SYMBOL}=y" "$DEFCONFIG_FRAGMENT"' "$BUILD_WORKFLOW"
  grep -qF '"$NORMALIZER" "$KERNEL_ROOT/common" "$DEFCONFIG"' "$BUILD_WORKFLOW"
  grep -qF 'DEVICE_CODENAME" == "e3q" && "$KMI_MODE" == "strict"' "$BUILD_WORKFLOW"
  grep -qF '"$NAMESPACE_REPAIR" "$KERNEL_COMMON"' "$SUSFS_ACTION"
  grep -qF 'KSU_INCOMPATIBLE=(UH KDP RKP)' "$HELPERS_DIR/enforce-s928b-daily-config.sh"
  grep -qF 'REQUIRED_MODULE_COMPAT=(MODULE_ALLOW_BTF_MISMATCH)' \
    "$HELPERS_DIR/enforce-s928b-daily-config.sh"
}

test_kleaf_kmi_flags

test_samsung_defconfig_normalizer() {
  local fixture="$TMP_DIR/samsung-defconfig-normalizer"
  local common="$fixture/common"
  local defconfig="$common/arch/arm64/configs/gki_defconfig"
  local clang="$fixture/prebuilts/clang/host/linux-x86/clang-test/bin/clang"
  local make_bin="$fixture/bin/make"
  mkdir -p "$(dirname "$defconfig")" "$(dirname "$clang")" "$(dirname "$make_bin")"

  cat > "$defconfig" <<'EOF'
CONFIG_ZETA=y
CONFIG_ARM64=y
CONFIG_ALPHA=y
EOF
  cat > "$make_bin" <<'EOF'
#!/bin/bash
set -euo pipefail
source_dir=
out_dir=
target=
while (( $# )); do
  case "$1" in
    -C) shift; source_dir="$1" ;;
    O=*) out_dir="${1#O=}" ;;
    gki_defconfig|savedefconfig) target="$1" ;;
  esac
  shift
done
mkdir -p "$out_dir"
case "$target" in
  gki_defconfig) cp "$source_dir/arch/arm64/configs/gki_defconfig" "$out_dir/.config" ;;
  savedefconfig) LC_ALL=C sort -u "$out_dir/.config" > "$out_dir/defconfig" ;;
  *) exit 64 ;;
esac
EOF
  cat > "$clang" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$clang" "$make_bin"

  PATH="$fixture/bin:$PATH" RUNNER_TEMP="$fixture/tmp" \
    bash "$SAMSUNG_DEFCONFIG_NORMALIZER" "$common" "$defconfig"
  cat > "$fixture/expected" <<'EOF'
CONFIG_ALPHA=y
CONFIG_ARM64=y
CONFIG_ZETA=y
EOF
  cmp -s "$fixture/expected" "$defconfig"
}

test_samsung_defconfig_normalizer

test_samsung_susfs_namespace_repair() {
  local fixture="$TMP_DIR/samsung-susfs-namespace"
  local source="$fixture/fs/namespace.c"
  mkdir -p "$(dirname "$source")"
  cat > "$source" <<'EOF'
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#include <linux/susfs_def.h>
#endif
extern bool susfs_is_current_ksu_domain(void);
extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;
#define CL_COPY_MNT_NS BIT(25)
static unsigned int sysctl_mount_max;

static void mnt_free_id(struct mount *mnt)
{
	if (mnt->mnt.mnt_flags & VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT)
		return;
	ida_free(&mnt_id_ida, mnt->mnt_id);
}

static int mnt_alloc_group_id(struct mount *mnt)
{
	if (susfs_is_current_ksu_domain())
		res = ida_alloc_min(&mnt_group_ida, DEFAULT_KSU_MNT_GROUP_ID, GFP_KERNEL);
bypass_orig_flow:
	if (res < 0)
		return res;
}

void mnt_release_group_id(struct mount *mnt) { }

int mnt_get_count(struct mount *mnt) { return 1; }
static struct mount *susfs_alloc_unshare_ksu_vfsmnt(const char *name, int old_mnt_id)
{
	return NULL;
}
static struct mount *susfs_alloc_non_unshare_ksu_vfsmnt(const char *name)
{
	return NULL;
}
static struct mount *alloc_vfsmnt(const char *name) { return NULL; }

struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	if (susfs_is_current_proc_umounted_for_zygote_next())
		hlist_for_each_entry_rcu(p, head, mnt_hash)
		if (p->mnt_id < DEFAULT_KSU_MNT_ID)
			return p;
	return NULL;
	hlist_for_each_entry_rcu(p, head, mnt_hash) { }
	return NULL;
}

struct vfsmount *lookup_mnt(const struct path *path) { return NULL; }

struct vfsmount *vfs_create_mount(struct fs_context *fc)
{
	if (susfs_is_sdcard_android_data_not_decrypted)
		mnt = susfs_alloc_non_unshare_ksu_vfsmnt(fc->source ?: "none");
bypass_orig_flow:
	if (!mnt)
		return NULL;
}
EXPORT_SYMBOL(vfs_create_mount);

static struct mount *clone_mnt(struct mount *old, struct dentry *root,
		int flag)
{
	bool is_mnt_ksu_unshared = false;
	mnt = susfs_alloc_unshare_ksu_vfsmnt(old->mnt_devname, old->mnt_id);
	mnt = susfs_alloc_non_unshare_ksu_vfsmnt(old->mnt_devname);
bypass_orig_flow:
	mnt->mnt.mnt_flags |= VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT;
	return mnt;
}

static void cleanup_mnt(struct mount *mnt) { }

static void *copy_mount_options(const void __user *data)
{
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	copy_flags |= CL_COPY_MNT_NS;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	return NULL;
}

struct mnt_namespace *copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct user_namespace *user_ns, struct fs_struct *new_fs)
{
	struct mount *old;
	struct mount *new;
	int copy_flags;

	copy_flags = CL_COPY_UNBINDABLE | CL_EXPIRE;
	if (user_ns != ns->user_ns)
		copy_flags |= CL_SHARED_TO_SLAVE;
#ifdef CONFIG_KDP_NS
	new = copy_tree(old, ((struct kdp_mount *)old)->mnt->mnt_root, copy_flags);
#else
	new = copy_tree(old, old->mnt.mnt_root, copy_flags);
#endif
	return ERR_CAST(new);
}

struct dentry *mount_subtree(struct vfsmount *m, const char *name)
{
	return NULL;
}

#endif /* CONFIG_SYSCTL */
int susfs_get_non_sus_mnt_id_from_mnt(struct mount *orig_mnt) { return 0; }
struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt)
{
	return vfsmnt;
}
EOF

  bash "$SAMSUNG_SUSFS_NAMESPACE_REPAIR" "$fixture"
  test "$(grep -cF 'copy_flags |= CL_COPY_MNT_NS;' "$source")" = 1
  awk '
    /^struct mnt_namespace \*copy_mnt_ns/ { in_function=1 }
    in_function && /copy_flags \|= CL_COPY_MNT_NS;/ { found=1 }
    in_function && /^}/ { exit(found ? 0 : 1) }
    END { if (!found) exit 1 }
  ' "$source"
  ! sed -n '/copy_mount_options/,/^}/p' "$source" | grep -qF 'CL_COPY_MNT_NS'
}

test_samsung_susfs_namespace_repair

test_strict_anykernel_gate() {
  grep -qF 'package_strict_anykernel:' "$BUILD_WORKFLOW"
  grep -qF 'Strict AnyKernel packaging requires kmi_mode=strict' "$BUILD_WORKFLOW"
  grep -qF 'Strict AnyKernel packaging is restricted to kmi_profile=full-strict' "$BUILD_WORKFLOW"
  grep -qF 'Strict AnyKernel packaging is restricted to device_codename=e3q' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_DLKM_EXACT_COUNT" = "2469"' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_DLKM_COMPATIBLE_COUNT" = "0"' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_DLKM_UNEXPECTED_COUNT" = "0"' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_DLKM_MISSING_COUNT" = "0"' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_DLKM_RUNTIME_FALLBACK" = "strict-rejection"' "$BUILD_WORKFLOW"
  grep -qF 'Packaged strict Image lacks Samsung XHCI KMI symbol' "$BUILD_WORKFLOW"
  grep -qF '__tracepoint_android_vh_xhci_suspend' "$BUILD_WORKFLOW"
  grep -qF '__tracepoint_android_vh_xhci_resume' "$BUILD_WORKFLOW"
  grep -qF 'test "$SAMSUNG_SOURCE_BASE_APPLIED" = "true"' "$BUILD_WORKFLOW"
  grep -qF 'Samsung source: ${SAMSUNG_OSS_PACKAGE} (${SAMSUNG_OSS_SHA256})' "$BUILD_WORKFLOW"
  grep -qF 'CONFIG_EROFS_FS_ZIP_LZMA=y' "$BUILD_WORKFLOW"
  grep -qF 'CONFIG_XZ_DEC_MICROLZMA=y' "$BUILD_WORKFLOW"
  grep -qF 'Upload exact flashable Strict KMI ZIP' "$BUILD_WORKFLOW"
}

test_strict_anykernel_gate

test_s928b_dzg1_xhci_hooks() {
  local fixture="$TMP_DIR/s928b-dzg1-xhci"
  mkdir -p \
    "$fixture/include/trace/hooks" \
    "$fixture/drivers/android" \
    "$fixture/drivers/usb/host" \
    "$fixture/android"

  cat > "$fixture/drivers/android/vendor_hooks.c" <<'EOF'
#define CREATE_TRACE_POINTS
#include <trace/hooks/usb.h>
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_usb_dev_resume);
EOF
  cat > "$fixture/drivers/usb/host/xhci-plat.c" <<'EOF'
#include "xhci.h"

static int __maybe_unused xhci_plat_runtime_suspend(struct device *dev)
{
	struct usb_hcd  *hcd = dev_get_drvdata(dev);
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	int ret;

	ret = xhci_priv_suspend_quirk(hcd);
	if (ret)
		return ret;

	return xhci_suspend(xhci, true);
}

static int __maybe_unused xhci_plat_runtime_resume(struct device *dev)
{
	struct usb_hcd  *hcd = dev_get_drvdata(dev);
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);

	return xhci_resume(xhci, 0);
}
EOF
  cat > "$fixture/android/abi_gki_aarch64_galaxy" <<'EOF'
[abi_symbol_list]
  __traceiter_android_vh_wq_lockup_pool
  __traceiter_block_rq_insert
  __tracepoint_android_vh_wq_lockup_pool
  __tracepoint_block_rq_insert
EOF

  bash "$XHCI_HOOK_HELPER" "$fixture"
  bash "$XHCI_HOOK_HELPER" "$fixture"

  [[ "$(grep -cF '#include <linux/tracepoint.h>' \
      "$fixture/include/trace/hooks/xhci.h")" -eq 1 ]]
  grep -qxF '  __traceiter_android_rvh_nf_conn_alloc' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __traceiter_android_rvh_nf_conn_free' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __tracepoint_android_rvh_nf_conn_alloc' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __tracepoint_android_rvh_nf_conn_free' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __traceiter_android_vh_xhci_resume' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __traceiter_android_vh_xhci_suspend' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __tracepoint_android_vh_xhci_resume' "$fixture/android/abi_gki_aarch64_galaxy"
  grep -qxF '  __tracepoint_android_vh_xhci_suspend' "$fixture/android/abi_gki_aarch64_galaxy"
  [[ "$(grep -cF 'trace_android_vh_xhci_suspend(dev, &bypass);' \
      "$fixture/drivers/usb/host/xhci-plat.c")" -eq 1 ]]
  [[ "$(grep -cF 'trace_android_vh_xhci_resume(dev, &bypass);' \
      "$fixture/drivers/usb/host/xhci-plat.c")" -eq 1 ]]
}

test_s928b_dzg1_xhci_hooks

test_s928b_zzhl_source_port() {
  local listing="$TMP_DIR/samsung-overlay-listing.txt"
  local manifest="$TMP_DIR/samsung-overlay-manifest.tsv"
  local deletes="$TMP_DIR/samsung-overlay-delete.txt"
  local extracted="$TMP_DIR/samsung-overlay-extracted"

  # shellcheck disable=SC1090
  source "$SAMSUNG_SOURCE_PROFILE"
  [[ "$SAMSUNG_BUILD_TARGET" == "e3q_eur_openx" ]]
  [[ "$SAMSUNG_CHIPSET" == "pineapple" ]]
  [[ "$SAMSUNG_OSS_SHA256" == "512c0a0b74646ddbb64ac8adea7c396c90458c2c12cf7f437e9d20282a33fa3c" ]]
  [[ "$AOSP_COMMON_COMMIT" == "4bd1b41bff8bb87bed8c3621fa2bb5b2e96f5d8c" ]]
  [[ "$SAMSUNG_COMMON_OVERLAY_SHA256" == "a9538364b3539754fcc4be676a02fff81694af61504a0afdcc0212a803042346" ]]
  echo "$SAMSUNG_COMMON_OVERLAY_SHA256  $SAMSUNG_SOURCE_OVERLAY" | sha256sum -c -

  tar -tJf "$SAMSUNG_SOURCE_OVERLAY" > "$listing"
  [[ "$(wc -l < "$listing")" -eq 826 ]]
  tar -xOJf "$SAMSUNG_SOURCE_OVERLAY" manifest.tsv > "$manifest"
  tar -xOJf "$SAMSUNG_SOURCE_OVERLAY" delete.txt > "$deletes"
  [[ "$(awk -F '\t' '$1 == "changed" { count++ } END { print count+0 }' "$manifest")" -eq 402 ]]
  [[ "$(awk -F '\t' '$1 == "ported-only" { count++ } END { print count+0 }' "$manifest")" -eq 421 ]]
  [[ "$(grep -c . "$deletes")" -eq 308 ]]

  mkdir -p "$extracted"
  tar -xJf "$SAMSUNG_SOURCE_OVERLAY" -C "$extracted" \
    files/arch/arm64/configs/gki_defconfig \
    files/arch/arm64/include/asm/cputype.h \
    files/include/trace/hooks/xhci.h \
    files/include/trace/hooks/net.h \
    files/drivers/android/vendor_hooks.c \
    files/drivers/usb/host/xhci-plat.c \
    files/fs/f2fs/f2fs.h \
    files/fs/f2fs/super.c \
    files/kernel/module/main.c \
    files/net/netfilter/nf_conntrack_core.c
  echo "$SAMSUNG_GKI_DEFCONFIG_SHA256  $extracted/files/arch/arm64/configs/gki_defconfig" | sha256sum -c -
  echo "$SAMSUNG_CPUTYPE_SHA256  $extracted/files/arch/arm64/include/asm/cputype.h" | sha256sum -c -
  echo "$SAMSUNG_XHCI_HEADER_SHA256  $extracted/files/include/trace/hooks/xhci.h" | sha256sum -c -
  echo "$SAMSUNG_NET_HOOKS_SHA256  $extracted/files/include/trace/hooks/net.h" | sha256sum -c -
  echo "$SAMSUNG_VENDOR_HOOKS_SHA256  $extracted/files/drivers/android/vendor_hooks.c" | sha256sum -c -
  echo "$SAMSUNG_XHCI_PLAT_SHA256  $extracted/files/drivers/usb/host/xhci-plat.c" | sha256sum -c -
  echo "$SAMSUNG_F2FS_HEADER_SHA256  $extracted/files/fs/f2fs/f2fs.h" | sha256sum -c -
  echo "$SAMSUNG_F2FS_SUPER_SHA256  $extracted/files/fs/f2fs/super.c" | sha256sum -c -
  echo "$SAMSUNG_MODULE_MAIN_SHA256  $extracted/files/kernel/module/main.c" | sha256sum -c -
  echo "$SAMSUNG_NF_CONNTRACK_CORE_SHA256  $extracted/files/net/netfilter/nf_conntrack_core.c" | sha256sum -c -
  if grep -rIl $'\r' \
      "$extracted/files/arch/arm64/configs/gki_defconfig" \
      "$extracted/files/drivers/android/vendor_hooks.c" \
      "$extracted/files/fs/f2fs/f2fs.h" \
      "$extracted/files/fs/f2fs/super.c" \
      "$extracted/files/include/trace/hooks/net.h" \
      "$extracted/files/kernel/module/main.c" \
      "$extracted/files/net/netfilter/nf_conntrack_core.c"; then
    echo "Audited Samsung patch target still contains CR line endings" >&2
    return 1
  fi

  grep -qF 'Apply SM-S928B Samsung source port for ZZHL / 6.1.162' "$BUILD_WORKFLOW"
  grep -qF 'apply-s928b-zzhl-source-port.sh' "$BUILD_WORKFLOW"
  grep -qF 'status_counts != {"changed": 402, "ported-only": 421}' "$SAMSUNG_SOURCE_HELPER"
  grep -qF 'MIDR_ALL_VERSIONS(MIDR_NEOVERSE_V3AE)' "$SAMSUNG_SOURCE_HELPER"
  grep -qF 'Stale F2FS checkpoint merge fragment remains' "$SAMSUNG_SOURCE_HELPER"
  grep -qF 'Samsung source port calls undeclared Android vendor hooks' "$SAMSUNG_SOURCE_HELPER"
  grep -qF 'hook.endswith("_enabled") and hook[:-8] in declared_hooks' "$SAMSUNG_SOURCE_HELPER"
  grep -qF 'EXPORT_TRACEPOINT_SYMBOL_GPL(android_rvh_nf_conn_alloc);' \
    "$extracted/files/drivers/android/vendor_hooks.c"
  grep -qF '#include <trace/hooks/net.h>' \
    "$extracted/files/net/netfilter/nf_conntrack_core.c"
}

test_s928b_zzhl_source_port

test_s928b_zzhl_full_odin_identity() {
  # shellcheck disable=SC1090
  source "$SAMSUNG_TARGET_PROFILE"
  [[ "$SAMSUNG_TARGET_PACKAGE" == "AP_S928BXXU6ZZHL_S928BXXU6ZZHL_MQB114051673_REV00_user_low_ship_MULTI_CERT_meta_OS17.tar.md5" ]]
  [[ "$SAMSUNG_TARGET_AP_TAR_MD5" == "37edc3573e04577e4f0d44176f7733a5" ]]
  [[ "$SAMSUNG_TARGET_AP_ARCHIVE_SHA256" == "605f5f8a9f15dd83cdbc34e1bad52df07720a8a7b6f3864cf2c94c9b5389d441" ]]
  [[ "$SAMSUNG_TARGET_CP_PACKAGE" == "CP_S928BXXU6EZHK_CP36088022_MQB114028509_REV00_user_low_ship_MULTI_CERT.tar.md5" ]]
  [[ "$SAMSUNG_TARGET_CP_TAR_MD5" == "b14852527539694ab53b4d82a9115a3d" ]]
  [[ "$SAMSUNG_TARGET_CP_ARCHIVE_SHA256" == "64fe7c3e3480e46a604357cbcd5392962c8cb9bcbc7a7a8190005d41c3ee3641" ]]
  [[ "$SAMSUNG_TARGET_CSC_PACKAGE" == "CSC_OXM_S928BOXM6ZZHL_MQB114051673_REV00_user_low_ship_MULTI_CERT.tar.md5" ]]
  [[ "$SAMSUNG_TARGET_CSC_TAR_MD5" == "63a7ab94c3b148cb5d6abb511026d885" ]]
  [[ "$SAMSUNG_TARGET_CSC_ARCHIVE_SHA256" == "9c353270143b7804e25b357d96fca3f08a7dfff1f63e5ef7eca48e65ad692912" ]]
  [[ "$SAMSUNG_TARGET_HOME_CSC_PACKAGE" == "HOME_CSC_OXM_S928BOXM6ZZHL_MQB114051673_REV00_user_low_ship_MULTI_CERT.tar.md5" ]]
  [[ "$SAMSUNG_TARGET_HOME_CSC_TAR_MD5" == "fb40e1b3f22a58444a7ee7e4aacd3a1c" ]]
  [[ "$SAMSUNG_TARGET_HOME_CSC_ARCHIVE_SHA256" == "6ed22fcc99b42341b88d93e891e4dfacc638ec23f7684661d2a5831293121c42" ]]
  [[ "$SAMSUNG_TARGET_INIT_BOOT_IMAGE_SHA256" == "d48469e0937636843d0c5533dcaa850f4213cbdb3d07998320b3a899b8391e7f" ]]
  [[ "$SAMSUNG_TARGET_APNHLOS_IMAGE_SHA256" == "74ea46406663ebdf64c6d7c0e0fd08bca147d92713093857107d8ac1eae64dcd" ]]
  [[ "$SAMSUNG_TARGET_MODEM_IMAGE_SHA256" == "fd4bed7db314670d2a5443c8af8805456c59c4337d97bdaa69596666b221ff94" ]]
  [[ "$SAMSUNG_KEEP_BL_PACKAGE" == "BL_S928BXXU6ZZHL_KEEP_OEM_UNLOCK.tar.md5" ]]
  [[ "$SAMSUNG_KEEP_BL_TAR_MD5" == "ab2ee0f0e4f171c87d353706135c25e1" ]]
  [[ "$SAMSUNG_KEEP_BL_ARCHIVE_SHA256" == "2eaff7a27e10b7898246d200f8ebb2bd315ee3c7eec0e6669b74371bf2be16dd" ]]
  [[ "$SAMSUNG_KEEP_BL_VBMETA_SHA256" == "67b8d114c5c1af81c473fb649f5b47cca340a5744baed548db9660e5907a4535" ]]
  [[ "$SAMSUNG_KEEP_BL_VBMETA_FLAGS" == "3" ]]
  [[ "$SAMSUNG_KEEP_BL_COMPATIBILITY" == "avb-flags-3-intentional-keep-oem-unlock" ]]
}

test_s928b_zzhl_full_odin_identity

test_s928b_dzg1_susfs_patch_context() {
  grep -qF 'SAMSUNG_SOURCE_BASE_APPLIED:-false' "$SUSFS_ACTION"
  grep -qF 'PATCH_FUZZ=3' "$SUSFS_ACTION"
  grep -qF 'patch -p1 -F"$PATCH_FUZZ" --forward --batch --dry-run' "$SUSFS_ACTION"
  grep -qF 'patch -p1 -F"$PATCH_FUZZ" --forward --batch --no-backup-if-mismatch' "$SUSFS_ACTION"
  grep -qF '#define CL_COPY_MNT_NS BIT(25)' "$SUSFS_ACTION"
  grep -qF 'susfs_open_redirect_spoof_do_sys_openat(inode)' "$SUSFS_ACTION"
  grep -qF "require_exact_susfs_marker fs/proc/base.c '#include <linux/susfs_def.h>'" "$SUSFS_ACTION"
  grep -qF 'Samsung SUSFS integration left patch rejects' "$SUSFS_ACTION"
}

test_s928b_dzg1_susfs_patch_context

test_s928b_dzg1_wakeup_patch() {
  grep -qF 'SAMSUNG_SOURCE_BASE_APPLIED:-false' "$KERNEL_PATCH_HELPER"
  grep -qF 'avoid_extra_s2idle_wake_attempts_oneui8.5.patch' "$KERNEL_PATCH_HELPER"
  grep -qF "grep -cF 'if (atomic_inc_return_relaxed(&pm_abort_suspend) == 1) {'" "$KERNEL_PATCH_HELPER"
  grep -qF '[[ ! -f drivers/base/power/wakeup.c.rej ]]' "$KERNEL_PATCH_HELPER"
}

test_s928b_dzg1_wakeup_patch

test_s928b_zzhl_patch_ports() {
  grep -qF 'Samsung F2FS congestion patch port applied' "$KERNEL_PATCH_HELPER"
  grep -qF "grep -cF 'msecs_to_jiffies(20)'" "$KERNEL_PATCH_HELPER"
  grep -qF "grep -cF 'msecs_to_jiffies(6)'" "$KERNEL_PATCH_HELPER"
  grep -qF 'patch -p1 -F3 --forward --batch --dry-run --no-backup-if-mismatch' "$BUILD_WORKFLOW"
  grep -qF "grep -qF 'static char *custom_module_blacklist[] = {' kernel/module/main.c" "$BUILD_WORKFLOW"
  grep -qF "grep -qF 'custom_blacklist:' kernel/module/main.c" "$BUILD_WORKFLOW"
}

test_s928b_zzhl_patch_ports

test_kasan_kmi_layout() {
  local fixture="$TMP_DIR/kasan-kmi-layout"
  mkdir -p "$fixture/mm/kasan" "$fixture/include/linux"

  cat > "$fixture/mm/Makefile" <<'EOF'
obj-$(CONFIG_KASAN) += kasan/
EOF
  cat > "$fixture/mm/kasan/hw_tags.c" <<'EOF'
DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
EXPORT_SYMBOL(kasan_flag_enabled);
EOF
  cat > "$fixture/include/linux/kasan.h" <<'EOF'
#ifdef CONFIG_KASAN
struct kasan_cache {
	bool is_kmalloc;
};
#else /* CONFIG_KASAN */

static inline void kasan_unpoison_range(const void *address, size_t size) {}
#endif /* CONFIG_KASAN */
EOF
  cat > "$fixture/include/linux/slub_def.h" <<'EOF'
struct kmem_cache {
#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif
	unsigned int useroffset;
};
EOF

  "$KASAN_STUB_HELPER" "$fixture"
  "$KASAN_STUB_HELPER" "$fixture"
  grep -qxF 'obj-y += kasan_kmi_compat.o' "$fixture/mm/Makefile"
  [[ "$(grep -cF 'Samsung KMI: retain the HW-tags kasan_cache layout with KASAN off.' \
      "$fixture/include/linux/kasan.h")" -eq 1 ]]
  [[ "$(grep -cF 'Samsung KMI: layout only; KASAN instrumentation remains disabled.' \
      "$fixture/include/linux/slub_def.h")" -eq 1 ]]
  [[ "$(grep -c $'^\tstruct kasan_cache kasan_info;$' \
      "$fixture/include/linux/slub_def.h")" -eq 1 ]]
}

test_kasan_kmi_layout

test_clean_flags_mode() {
  local mode="$1"
  local expected_return="$2"
  local fixture="$TMP_DIR/clean-$mode"
  mkdir -p \
    "$fixture/common/scripts" \
    "$fixture/common/kernel/module" \
    "$fixture/common/arch/arm64/configs" \
    "$fixture/build/kernel/kleaf/impl"

  cat > "$fixture/common/scripts/setlocalversion" <<'EOF'
#!/bin/sh
res=test
echo "$res"
EOF
  cat > "$fixture/build/kernel/kleaf/impl/stamp.bzl" <<'EOF'
stable_scmversion_cmd = "-maybe-dirty"
EOF
  cat > "$fixture/common/BUILD.bazel" <<'EOF'
kernel_build(
    name = "kernel_aarch64",
    "protected_exports_list": "android/abi_gki_protected_exports_aarch64",
)
EOF
  cat > "$fixture/common/kernel/module/version.c" <<'EOF'
static int check_version(void)
{
bad_version:
  pr_warn("disagrees about version of symbol");
  return 0;
}
EOF
  cat > "$fixture/common/kernel/module/main.c" <<'EOF'
if (blacklisted(info->name)) {
  err = -EPERM;
  goto free_copy;
}
EOF
  cat > "$fixture/common/arch/arm64/configs/sukisu_gki.fragment" <<'EOF'
CONFIG_KSU=y
EOF

  git -C "$fixture/common" init --quiet
  git -C "$fixture/common" config user.name test
  git -C "$fixture/common" config user.email test@example.invalid
  git -C "$fixture/common" add .
  git -C "$fixture/common" commit --quiet -m fixture

  GITHUB_WORKSPACE="$fixture/audit" "$CLEAN_FLAGS" "$fixture" 6.1 ReSukiSU "$mode"
  awk -v expected="$expected_return" '
    /bad_version:/ { active=1; next }
    active && /return[[:space:]]+[01];/ {
      exit($0 ~ ("return[[:space:]]+" expected ";") ? 0 : 1)
    }
    END { if (!active) exit 1 }
  ' "$fixture/common/kernel/module/version.c"
  ! grep -q 'protected_exports_list' "$fixture/common/BUILD.bazel"
}

test_clean_flags_mode symtypes 0
test_clean_flags_mode strict 0
test_clean_flags_mode runtime-compat 1

echo "KMI diagnostics self-test passed."
