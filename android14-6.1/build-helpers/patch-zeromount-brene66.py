#!/usr/bin/env python3
from pathlib import Path
import json
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"anchor mismatch in {rel}: count={count}: {old[:120]!r}")
    write(rel, text.replace(old, new, 1))


# This helper is applied after patch-zeromount-guard-whitelist.py.
replace_once(
    "Cargo.toml",
    'version = "2.0.216-dev.guard1"',
    'version = "2.0.216-dev.guard2.brene66"',
)

# ---------------------------------------------------------------------------
# BreneConfig: add the safe BRENE v0.0.66 functionality that ZeroMount did not
# yet model. New potentially invasive features default OFF; one-shot cleanup is
# safe and defaults ON. custom_kernel_umounts is explicit-only.
# ---------------------------------------------------------------------------
replace_once(
    "src/core/config.rs",
    '''    #[serde(default = "default_true")]
    pub auto_hide_tmp: bool,
    #[serde(default = "default_true")]
    pub avc_log_spoofing: bool,''',
    '''    #[serde(default = "default_true")]
    pub auto_hide_tmp: bool,
    /// Remove SUSFS' writable-storage redirect marker once after boot.
    #[serde(default = "default_true")]
    pub cleanup_sus_marker: bool,
    /// Hide non-standard direct children of /storage/emulated/0/Android.
    /// Disabled by default on vendor ROMs to avoid hiding OEM-owned folders.
    #[serde(default)]
    pub hide_nonstandard_android: bool,
    /// Persistently enable ReSukiSU/KernelSU su_compat at boot-completed.
    #[serde(default)]
    pub sync_su_compat: bool,
    /// Persistently enable ReSukiSU/KernelSU selinux_hide at boot-completed.
    #[serde(default)]
    pub sync_selinux_hide: bool,
    #[serde(default = "default_true")]
    pub avc_log_spoofing: bool,''',
)
replace_once(
    "src/core/config.rs",
    '''    #[serde(default)]
    pub custom_sus_path_loops: Vec<String>,
    #[serde(default = "default_vbmeta_size")]''',
    '''    #[serde(default)]
    pub custom_sus_path_loops: Vec<String>,
    /// Explicit KernelSU kernel-umount targets (BRENE custom_kernel_umount.txt equivalent).
    #[serde(default)]
    pub custom_kernel_umounts: Vec<String>,
    #[serde(default = "default_vbmeta_size")]''',
)
replace_once(
    "src/core/config.rs",
    '''            auto_hide_recovery: true,
            auto_hide_tmp: true,
            avc_log_spoofing: true,''',
    '''            auto_hide_recovery: true,
            auto_hide_tmp: true,
            cleanup_sus_marker: true,
            hide_nonstandard_android: false,
            sync_su_compat: false,
            sync_selinux_hide: false,
            avc_log_spoofing: true,''',
)
replace_once(
    "src/core/config.rs",
    '''            custom_sus_paths: Vec::new(),
            custom_sus_maps: Vec::new(),
            custom_sus_path_loops: Vec::new(),
            vbmeta_size: default_vbmeta_size(),''',
    '''            custom_sus_paths: Vec::new(),
            custom_sus_maps: Vec::new(),
            custom_sus_path_loops: Vec::new(),
            custom_kernel_umounts: Vec::new(),
            vbmeta_size: default_vbmeta_size(),''',
)
replace_once(
    "src/core/config.rs",
    '''        for path in self.custom_sus_paths.iter().chain(&self.custom_sus_maps).chain(&self.custom_sus_path_loops) {
            if !path.starts_with('/') || path.contains('\\0') {
                anyhow::bail!("invalid sus path: {path:?} (must be absolute, no NUL)");
            }
        }''',
    '''        for path in self
            .custom_sus_paths
            .iter()
            .chain(&self.custom_sus_maps)
            .chain(&self.custom_sus_path_loops)
            .chain(&self.custom_kernel_umounts)
        {
            if !path.starts_with('/') || path.contains('\\0') {
                anyhow::bail!("invalid BRENE path: {path:?} (must be absolute, no NUL)");
            }
        }''',
)
replace_once(
    "src/core/config.rs",
    '''            "brene.auto_hide_tmp" => Some(self.brene.auto_hide_tmp.to_string()),
            "brene.avc_log_spoofing" => Some(self.brene.avc_log_spoofing.to_string()),''',
    '''            "brene.auto_hide_tmp" => Some(self.brene.auto_hide_tmp.to_string()),
            "brene.cleanup_sus_marker" => Some(self.brene.cleanup_sus_marker.to_string()),
            "brene.hide_nonstandard_android" => Some(self.brene.hide_nonstandard_android.to_string()),
            "brene.sync_su_compat" => Some(self.brene.sync_su_compat.to_string()),
            "brene.sync_selinux_hide" => Some(self.brene.sync_selinux_hide.to_string()),
            "brene.avc_log_spoofing" => Some(self.brene.avc_log_spoofing.to_string()),''',
)
replace_once(
    "src/core/config.rs",
    '''            "brene.custom_sus_path_loops" => Some(self.brene.custom_sus_path_loops.join(",")),
            "brene.vbmeta_size" => Some(self.brene.vbmeta_size.to_string()),''',
    '''            "brene.custom_sus_path_loops" => Some(self.brene.custom_sus_path_loops.join(",")),
            "brene.custom_kernel_umounts" => Some(self.brene.custom_kernel_umounts.join(",")),
            "brene.vbmeta_size" => Some(self.brene.vbmeta_size.to_string()),''',
)
replace_once(
    "src/core/config.rs",
    '''            "brene.auto_hide_tmp" => self.brene.auto_hide_tmp = value.parse()?,
            "brene.avc_log_spoofing" => self.brene.avc_log_spoofing = value.parse()?,''',
    '''            "brene.auto_hide_tmp" => self.brene.auto_hide_tmp = value.parse()?,
            "brene.cleanup_sus_marker" => self.brene.cleanup_sus_marker = value.parse()?,
            "brene.hide_nonstandard_android" => self.brene.hide_nonstandard_android = value.parse()?,
            "brene.sync_su_compat" => self.brene.sync_su_compat = value.parse()?,
            "brene.sync_selinux_hide" => self.brene.sync_selinux_hide = value.parse()?,
            "brene.avc_log_spoofing" => self.brene.avc_log_spoofing = value.parse()?,''',
)
replace_once(
    "src/core/config.rs",
    '''            "brene.custom_sus_path_loops" => self.brene.custom_sus_path_loops = parse_csv(value),
            "brene.vbmeta_size" => self.brene.vbmeta_size = value.parse()?,''',
    '''            "brene.custom_sus_path_loops" => self.brene.custom_sus_path_loops = parse_csv(value),
            "brene.custom_kernel_umounts" => self.brene.custom_kernel_umounts = parse_csv(value),
            "brene.vbmeta_size" => self.brene.vbmeta_size = value.parse()?,''',
)

# ---------------------------------------------------------------------------
# Native BRENE runtime additions.
# ---------------------------------------------------------------------------
replace_once(
    "src/susfs/brene.rs",
    '''const RECOVERY_PATHS: &[&str] = &[
    "/cache/recovery",
    "/data/cache/recovery",
];''',
    '''const RECOVERY_PATHS: &[&str] = &[
    "/cache/recovery",
    "/data/cache/recovery",
];

// BRENE v0.0.66 uses add_sus_path_loop for these frequently recreated paths.
const RECOVERY_LOOP_PATHS: &[&str] = &[
    "/storage/emulated/0/Fox",
    "/storage/emulated/0/TWRP",
    "/data/recovery",
    "/vendor/bin/install-recovery.sh",
    "/system/bin/install-recovery.sh",
];

const SUS_MARKER_PATHS: &[&str] = &[
    "/storage/emulated/0/..5.u.S",
    "/storage/emulated/0/Android/data/..5.u.S",
    "/storage/emulated/0/Android/media/..5.u.S",
    "/storage/emulated/0/Android/obb/..5.u.S",
];

const ANDROID_STORAGE_DIR: &str = "/storage/emulated/0/Android";
const STANDARD_ANDROID_CHILDREN: &[&str] = &["data", "media", "obb"];''',
)
replace_once(
    "src/susfs/brene.rs",
    '''        if brene.auto_hide_recovery && has_path {
            let count = paths::hide_paths(client, RECOVERY_PATHS).unwrap_or(0);
            result.paths_hidden += count;
            info!("BRENE: recovery paths hidden ({count})");
        }

        if brene.auto_hide_tmp && has_path {''',
    '''        if brene.auto_hide_recovery && has_path {
            let normal = paths::hide_paths(client, RECOVERY_PATHS).unwrap_or(0);
            let looped = paths::hide_paths_loop(client, RECOVERY_LOOP_PATHS).unwrap_or(0);
            let count = normal + looped;
            result.paths_hidden += count;
            info!("BRENE: recovery paths hidden ({count}; looped={looped})");
        }

        if brene.cleanup_sus_marker {
            let count = cleanup_sus_markers();
            info!("BRENE: SUS marker cleanup removed {count} paths");
        }

        if brene.hide_nonstandard_android && has_path {
            let count = hide_nonstandard_android_children(client);
            result.paths_hidden += count;
            info!("BRENE: non-standard Android storage children hidden ({count})");
        }

        if brene.auto_hide_tmp && has_path {''',
)
replace_once(
    "src/susfs/brene.rs",
    '''        if run_complement && brene.force_hide_lsposed {
            apply_force_hide_lsposed();
        }
    }

    // Supercalls: boot time only (kernel state toggles, not path-specific)''',
    '''        if run_complement && brene.force_hide_lsposed {
            apply_force_hide_lsposed();
        }

        // BRENE v0.0.66 persists KernelSU feature switches at boot-completed.
        // New switches remain opt-in in ZeroMount; kernel_umount follows the
        // existing ZeroMount toggle.
        sync_ksu_features(config);

        if brene.kernel_umount && !brene.custom_kernel_umounts.is_empty() {
            let count = apply_custom_kernel_umounts(&brene.custom_kernel_umounts);
            info!("BRENE: custom kernel umount targets registered ({count}/{})", brene.custom_kernel_umounts.len());
        }
    }

    // Supercalls: boot time only (kernel state toggles, not path-specific)''',
)
replace_once(
    "src/susfs/brene.rs",
    '''fn find_ksud() -> &'static str {
    if Path::new("/data/adb/ksu/bin/ksud").exists() {
        "/data/adb/ksu/bin/ksud"
    } else if Path::new("/data/adb/ap/bin/ksud").exists() {
        "/data/adb/ap/bin/ksud"
    } else {
        "ksud"
    }
}''',
    '''fn find_ksud() -> &'static str {
    // ReSukiSU/BRENE v0.0.66 uses the standalone path first.
    if Path::new("/data/adb/ksud").exists() {
        "/data/adb/ksud"
    } else if Path::new("/data/adb/ksu/bin/ksud").exists() {
        "/data/adb/ksu/bin/ksud"
    } else if Path::new("/data/adb/ap/bin/ksud").exists() {
        "/data/adb/ap/bin/ksud"
    } else {
        "ksud"
    }
}

fn cleanup_sus_markers() -> u32 {
    let mut removed = 0u32;
    for path in SUS_MARKER_PATHS {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        let result = if p.is_dir() {
            fs::remove_dir_all(p)
        } else {
            fs::remove_file(p)
        };
        match result {
            Ok(()) => removed += 1,
            Err(e) => debug!("SUS marker cleanup failed for {path}: {e}"),
        }
    }
    removed
}

fn hide_nonstandard_android_children(client: &SusfsClient) -> u32 {
    let dir = Path::new(ANDROID_STORAGE_DIR);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("cannot scan {ANDROID_STORAGE_DIR}: {e}");
            return 0;
        }
    };

    let mut count = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(v) => v,
            None => continue,
        };
        if STANDARD_ANDROID_CHILDREN.contains(&name) || name == "..5.u.S" {
            continue;
        }
        let path = entry.path().to_string_lossy().to_string();
        match client.add_sus_path_loop(&path) {
            Ok(()) => count += 1,
            Err(e) => debug!("hide non-standard Android child failed for {path}: {e}"),
        }
    }
    count
}

fn sync_ksu_features(config: &ZeroMountConfig) {
    let brene = &config.brene;
    let mut requested = Vec::new();
    if brene.sync_su_compat {
        requested.push("su_compat");
    }
    if brene.sync_selinux_hide {
        requested.push("selinux_hide");
    }
    if brene.kernel_umount {
        requested.push("kernel_umount");
    }
    if requested.is_empty() {
        return;
    }

    let ksud = find_ksud();
    let mut changed = 0u32;
    for feature in requested {
        match run_command_with_timeout(
            Command::new(ksud).args(["feature", "set", feature, "1"]),
            CMD_TIMEOUT,
        ) {
            Ok(o) if o.status.success() => changed += 1,
            Ok(o) => warn!("BRENE: ksud feature set {feature} failed (exit {})", o.status.code().unwrap_or(-1)),
            Err(e) => warn!("BRENE: ksud feature set {feature} failed: {e}"),
        }
    }

    if changed > 0 {
        match run_command_with_timeout(Command::new(ksud).args(["feature", "save"]), CMD_TIMEOUT) {
            Ok(o) if o.status.success() => info!("BRENE: persisted {changed} KernelSU feature switches"),
            Ok(o) => warn!("BRENE: ksud feature save failed (exit {})", o.status.code().unwrap_or(-1)),
            Err(e) => warn!("BRENE: ksud feature save failed: {e}"),
        }
    }
}

fn apply_custom_kernel_umounts(paths: &[String]) -> u32 {
    let ksud = find_ksud();
    let _ = run_command_with_timeout(
        Command::new(ksud).args(["kernel", "notify-module-mounted"]),
        CMD_TIMEOUT,
    );

    let mut count = 0u32;
    for path in paths {
        if crate::utils::signal::shutdown_requested() {
            break;
        }
        match run_command_with_timeout(
            Command::new(ksud).args(["kernel", "umount", "add", path, "--flags", "2"]),
            CMD_TIMEOUT,
        ) {
            Ok(o) if o.status.success() => count += 1,
            Ok(o) => debug!("custom kernel umount failed for {path} (exit {})", o.status.code().unwrap_or(-1)),
            Err(e) => debug!("custom kernel umount failed for {path}: {e}"),
        }
    }
    count
}''',
)

# ---------------------------------------------------------------------------
# BRENE v0.0.66 bridge. The old ZeroMount bridge used obsolete key names and
# rewrote config.sh from scratch, silently dropping new BRENE settings. This
# version updates only keys ZeroMount owns and preserves comments/unknown keys.
# ---------------------------------------------------------------------------
write(
    "src/bridge/brene.rs",
    r'''use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::BufRead;
use std::path::Path;

use anyhow::{Context, Result};

use crate::core::config::{UnameMode, ZeroMountConfig};

use super::translate;

pub(super) const BASE_DIR: &str = "/data/adb/brene";
pub(super) const CONFIG_FILE: &str = "config.sh";

pub(super) const TXT_FILES: &[&str] = &[
    "custom_sus_path.txt",
    "custom_sus_map.txt",
    "custom_sus_path_loop.txt",
    "custom_kernel_umount.txt",
];

const CONFIG_PREFIX: &str = "config_";

pub(super) fn read_config(dir: &Path) -> Result<HashMap<String, String>> {
    let path = dir.join(CONFIG_FILE);
    let file = fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let mut map = HashMap::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((raw_key, value)) = trimmed.split_once('=') {
            let key = raw_key.strip_prefix(CONFIG_PREFIX).unwrap_or(raw_key);
            map.insert(key.to_string(), value.to_string());
        }
    }
    tracing::debug!(keys = map.len(), "read BRENE v0.0.66 config.sh");
    Ok(map)
}

fn write_preserving(dir: &Path, config: &ZeroMountConfig) -> Result<()> {
    let path = dir.join(CONFIG_FILE);
    let ours = config_to_keys(config);
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut output = Vec::new();
    let mut seen = HashSet::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output.push(line.to_string());
            continue;
        }
        if let Some((raw_key, _)) = trimmed.split_once('=') {
            let key = raw_key.strip_prefix(CONFIG_PREFIX).unwrap_or(raw_key);
            if let Some(value) = ours.get(key) {
                output.push(format!("{CONFIG_PREFIX}{key}={value}"));
                seen.insert(key.to_string());
                continue;
            }
        }
        // Critical v0.0.66 compatibility rule: never discard settings that
        // ZeroMount does not understand yet.
        output.push(line.to_string());
    }

    for &key in BRIDGED_KEY_ORDER {
        if !seen.contains(key) {
            if let Some(value) = ours.get(key) {
                output.push(format!("{CONFIG_PREFIX}{key}={value}"));
            }
        }
    }
    output.push(String::new());
    fs::write(&path, output.join("\n")).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub(super) fn write_config(dir: &Path, config: &ZeroMountConfig) -> Result<()> {
    write_preserving(dir, config)
}

pub(super) fn merge_config(
    dir: &Path,
    config: &ZeroMountConfig,
    _existing: &HashMap<String, String>,
) -> Result<()> {
    write_preserving(dir, config)
}

pub(super) fn ensure_txt_files(dir: &Path) -> Result<()> {
    for name in TXT_FILES {
        let path = dir.join(name);
        if !path.exists() {
            fs::write(&path, "").with_context(|| format!("creating {}", path.display()))?;
            tracing::debug!(file = name, "created empty BRENE txt file");
        }
    }
    Ok(())
}

fn config_to_keys(config: &ZeroMountConfig) -> HashMap<String, String> {
    let mut m = HashMap::with_capacity(24);
    let b = &config.brene;

    // Current BRENE v0.0.66 keys.
    m.insert("enable_avc_log_spoofing".into(), translate::bool_to_int(b.avc_log_spoofing).to_string());
    m.insert("hide_custom_recovery".into(), translate::bool_to_int(b.auto_hide_recovery).to_string());
    m.insert("paths_hiding__data_local_tmp".into(), translate::bool_to_int(b.auto_hide_tmp).to_string());
    m.insert("paths_hiding__non_standard_sdcard_android".into(), translate::bool_to_int(b.hide_nonstandard_android).to_string());
    m.insert("hide_sus_mnts_for_non_su_procs".into(), translate::bool_to_int(b.hide_sus_mounts).to_string());
    m.insert("kernel_umount".into(), translate::bool_to_int(b.kernel_umount).to_string());
    m.insert("su_compat".into(), translate::bool_to_int(b.sync_su_compat).to_string());
    m.insert("selinux_hide".into(), translate::bool_to_int(b.sync_selinux_hide).to_string());
    m.insert("hide_injections".into(), translate::bool_to_int(b.auto_hide_injections || b.auto_hide_zygisk).to_string());
    m.insert("usb_debugging".into(), translate::bool_to_int(config.adb.usb_debugging).to_string());
    m.insert("developer_options".into(), translate::bool_to_int(config.adb.developer_options).to_string());
    m.insert("enable_log".into(), translate::bool_to_int(b.susfs_log).to_string());
    m.insert("hide_modules_img".into(), translate::bool_to_int(b.hide_ksu_loops).to_string());
    m.insert("spoof_system_properties".into(), translate::bool_to_int(b.prop_spoofing).to_string());
    m.insert("spoof_cmdline_or_bootconfig".into(), translate::bool_to_int(b.spoof_cmdline).to_string());

    let custom_uname = matches!(config.uname.mode, UnameMode::Static)
        && (!config.uname.release.is_empty() || !config.uname.version.is_empty());
    m.insert("spoof_uname".into(), translate::bool_to_int(!matches!(config.uname.mode, UnameMode::Disabled)).to_string());
    m.insert("custom_spoof_uname".into(), translate::bool_to_int(custom_uname).to_string());
    m.insert("custom_uname_kernel_release".into(), translate::string_to_external(&config.uname.release));
    m.insert("custom_uname_kernel_version".into(), translate::string_to_external(&config.uname.version));

    m
}

fn first<'a>(keys: &'a HashMap<String, String>, names: &[&str]) -> Option<&'a String> {
    names.iter().find_map(|name| keys.get(*name))
}

pub(super) fn apply_keys_to_config(keys: &HashMap<String, String>, config: &mut ZeroMountConfig) -> bool {
    let mut changed = false;

    macro_rules! bool_key {
        ($field:expr, [$($name:expr),+ $(,)?]) => {
            if let Some(v) = first(keys, &[$($name),+]) {
                let val = translate::int_to_bool(v.parse().unwrap_or(0));
                if $field != val {
                    $field = val;
                    changed = true;
                }
            }
        };
    }

    bool_key!(config.brene.avc_log_spoofing, ["enable_avc_log_spoofing"]);
    bool_key!(config.brene.auto_hide_recovery, ["hide_custom_recovery", "hide_custom_recovery_folders"]);
    bool_key!(config.brene.auto_hide_tmp, ["paths_hiding__data_local_tmp", "hide_data_local_tmp"]);
    bool_key!(config.brene.hide_nonstandard_android, ["paths_hiding__non_standard_sdcard_android"]);
    bool_key!(config.brene.hide_sus_mounts, ["hide_sus_mnts_for_non_su_procs"]);
    bool_key!(config.brene.kernel_umount, ["kernel_umount"]);
    bool_key!(config.brene.sync_su_compat, ["su_compat"]);
    bool_key!(config.brene.sync_selinux_hide, ["selinux_hide"]);
    bool_key!(config.brene.auto_hide_injections, ["hide_injections"]);
    bool_key!(config.adb.usb_debugging, ["usb_debugging"]);
    bool_key!(config.adb.developer_options, ["developer_options"]);
    bool_key!(config.brene.susfs_log, ["enable_log"]);
    bool_key!(config.brene.hide_ksu_loops, ["hide_modules_img"]);
    bool_key!(config.brene.prop_spoofing, ["spoof_system_properties"]);
    bool_key!(config.brene.spoof_cmdline, ["spoof_cmdline_or_bootconfig"]);

    let spoof_uname = first(keys, &["spoof_uname", "uname_spoofing"])
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0) != 0;
    let custom_uname = first(keys, &["custom_spoof_uname", "custom_uname_spoofing"])
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0) != 0;
    if keys.contains_key("spoof_uname")
        || keys.contains_key("uname_spoofing")
        || keys.contains_key("custom_spoof_uname")
        || keys.contains_key("custom_uname_spoofing")
    {
        let mode = if custom_uname {
            UnameMode::Static
        } else if spoof_uname {
            UnameMode::Dynamic
        } else {
            UnameMode::Disabled
        };
        if config.uname.mode != mode {
            config.uname.mode = mode;
            changed = true;
        }
    }

    if let Some(v) = keys.get("custom_uname_kernel_release") {
        let val = translate::normalize_string_value(v);
        if config.uname.release != val {
            config.uname.release = val;
            changed = true;
        }
    }
    if let Some(v) = keys.get("custom_uname_kernel_version") {
        let val = translate::normalize_string_value(v);
        if config.uname.version != val {
            config.uname.version = val;
            changed = true;
        }
    }

    changed
}

const BRIDGED_KEY_ORDER: &[&str] = &[
    "enable_avc_log_spoofing",
    "hide_custom_recovery",
    "paths_hiding__data_local_tmp",
    "paths_hiding__non_standard_sdcard_android",
    "hide_sus_mnts_for_non_su_procs",
    "kernel_umount",
    "su_compat",
    "selinux_hide",
    "hide_injections",
    "usb_debugging",
    "developer_options",
    "enable_log",
    "hide_modules_img",
    "spoof_system_properties",
    "spoof_cmdline_or_bootconfig",
    "spoof_uname",
    "custom_spoof_uname",
    "custom_uname_kernel_release",
    "custom_uname_kernel_version",
];
''',
)

# ---------------------------------------------------------------------------
# Device-specific consistency hardening: do not contradict Samsung's real
# bootconfig warranty_bit=1 with Android property values of 0.
# ---------------------------------------------------------------------------
prop = read("module/prop_table.sh")
for line in [
    "ro.vendor.boot.warranty_bit=0\n",
    "ro.vendor.warranty_bit=0\n",
    "ro.boot.warranty_bit=0\n",
    "ro.warranty_bit=0",
]:
    prop = prop.replace(line, "")
write("module/prop_table.sh", prop)

# ---------------------------------------------------------------------------
# WebUI exposure for the safe new booleans. custom_kernel_umounts remains an
# advanced CLI/config field intentionally; blindly editing unmount paths in UI
# is not appropriate for a stable Samsung/AVF configuration.
# ---------------------------------------------------------------------------
replace_once(
    "webui/src/lib/types.ts",
    '''  auto_hide_tmp: boolean;
  avc_log_spoofing: boolean;''',
    '''  auto_hide_tmp: boolean;
  cleanup_sus_marker: boolean;
  hide_nonstandard_android: boolean;
  sync_su_compat: boolean;
  sync_selinux_hide: boolean;
  avc_log_spoofing: boolean;''',
)
replace_once(
    "webui/src/lib/store.ts",
    '''    auto_hide_recovery: true,
    auto_hide_tmp: true,
    avc_log_spoofing: true,''',
    '''    auto_hide_recovery: true,
    auto_hide_tmp: true,
    cleanup_sus_marker: true,
    hide_nonstandard_android: false,
    sync_su_compat: false,
    sync_selinux_hide: false,
    avc_log_spoofing: true,''',
)
replace_once(
    "webui/src/lib/store.ts",
    '''      'auto_hide_rooted_folders', 'auto_hide_recovery', 'auto_hide_tmp',
      'avc_log_spoofing', 'susfs_log',''',
    '''      'auto_hide_rooted_folders', 'auto_hide_recovery', 'auto_hide_tmp',
      'cleanup_sus_marker', 'hide_nonstandard_android', 'sync_su_compat', 'sync_selinux_hide',
      'avc_log_spoofing', 'susfs_log',''',
)

replace_once(
    "webui/src/components/settings/SusfsSection.tsx",
    '''                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.kernelUmount')}</div>
                    <div class="settings__item-desc">{t('susfs.kernelUmountDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.kernel_umount} onChange={(v) => handleBreneToggle('kernel_umount', v)} />
                </div>''',
    '''                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.kernelUmount')}</div>
                    <div class="settings__item-desc">{t('susfs.kernelUmountDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.kernel_umount} onChange={(v) => handleBreneToggle('kernel_umount', v)} />
                </div>
                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.syncSuCompat')}</div>
                    <div class="settings__item-desc">{t('susfs.syncSuCompatDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.sync_su_compat} onChange={(v) => handleBreneToggle('sync_su_compat', v)} />
                </div>
                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.syncSelinuxHide')}</div>
                    <div class="settings__item-desc">{t('susfs.syncSelinuxHideDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.sync_selinux_hide} onChange={(v) => handleBreneToggle('sync_selinux_hide', v)} />
                </div>''',
)
replace_once(
    "webui/src/components/settings/SusfsSection.tsx",
    '''                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.hideDataLocalTmp')}</div>
                    <div class="settings__item-desc">{t('susfs.hideDataLocalTmpDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.auto_hide_tmp} onChange={(v) => handleBreneToggle('auto_hide_tmp', v)} />
                </div>''',
    '''                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.hideDataLocalTmp')}</div>
                    <div class="settings__item-desc">{t('susfs.hideDataLocalTmpDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.auto_hide_tmp} onChange={(v) => handleBreneToggle('auto_hide_tmp', v)} />
                </div>
                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.cleanupSusMarker')}</div>
                    <div class="settings__item-desc">{t('susfs.cleanupSusMarkerDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.cleanup_sus_marker} onChange={(v) => handleBreneToggle('cleanup_sus_marker', v)} />
                </div>
                <div class="settings__item">
                  <div class="settings__item-content">
                    <div class="settings__item-label">{t('susfs.hideNonstandardAndroid')}</div>
                    <div class="settings__item-desc">{t('susfs.hideNonstandardAndroidDesc')}</div>
                  </div>
                  <Toggle checked={store.settings.brene.hide_nonstandard_android} onChange={(v) => handleBreneToggle('hide_nonstandard_android', v)} />
                </div>''',
)

for locale, values in {
    "en": {
        "susfs.cleanupSusMarker": "Clean SUS storage marker",
        "susfs.cleanupSusMarkerDesc": "Remove writable ..5.u.S redirect leftovers once after boot",
        "susfs.hideNonstandardAndroid": "Hide non-standard Android folders",
        "susfs.hideNonstandardAndroidDesc": "Hide direct /storage/emulated/0/Android children except data, media and obb (advanced)",
        "susfs.syncSuCompat": "Persist SU compatibility",
        "susfs.syncSuCompatDesc": "Enable and save the ReSukiSU/KernelSU su_compat feature after boot",
        "susfs.syncSelinuxHide": "Persist SELinux hide",
        "susfs.syncSelinuxHideDesc": "Enable and save the ReSukiSU/KernelSU selinux_hide feature after boot",
    },
    "de": {
        "susfs.cleanupSusMarker": "SUS-Speichermarker bereinigen",
        "susfs.cleanupSusMarkerDesc": "Entfernt ..5.u.S-Redirect-Reste einmalig nach dem Boot",
        "susfs.hideNonstandardAndroid": "Nichtstandard-Android-Ordner verbergen",
        "susfs.hideNonstandardAndroidDesc": "Verbirgt direkte Unterordner von /storage/emulated/0/Android außer data, media und obb (erweitert)",
        "susfs.syncSuCompat": "SU-Kompatibilität persistent setzen",
        "susfs.syncSuCompatDesc": "Aktiviert und speichert ReSukiSU/KernelSU su_compat nach dem Boot",
        "susfs.syncSelinuxHide": "SELinux-Hide persistent setzen",
        "susfs.syncSelinuxHideDesc": "Aktiviert und speichert ReSukiSU/KernelSU selinux_hide nach dem Boot",
    },
}.items():
    rel = f"webui/src/locales/{locale}.json"
    data = json.loads(read(rel))
    data.update(values)
    write(rel, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

# Static source assertions: fail here rather than package a partial port.
checks = {
    "src/core/config.rs": [
        "pub cleanup_sus_marker: bool",
        "pub hide_nonstandard_android: bool",
        "pub sync_su_compat: bool",
        "pub sync_selinux_hide: bool",
        "pub custom_kernel_umounts: Vec<String>",
    ],
    "src/susfs/brene.rs": [
        "RECOVERY_LOOP_PATHS",
        "cleanup_sus_markers",
        "hide_nonstandard_android_children",
        "sync_ksu_features",
        "apply_custom_kernel_umounts",
        'Path::new("/data/adb/ksud")',
    ],
    "src/bridge/brene.rs": [
        "custom_kernel_umount.txt",
        "hide_custom_recovery",
        "paths_hiding__non_standard_sdcard_android",
        "Critical v0.0.66 compatibility rule",
    ],
    "webui/src/lib/types.ts": ["cleanup_sus_marker", "sync_selinux_hide"],
}
for rel, needles in checks.items():
    text = read(rel)
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"verification failed: {needle!r} missing in {rel}")

for forbidden in [
    "ro.vendor.boot.warranty_bit=0",
    "ro.vendor.warranty_bit=0",
    "ro.boot.warranty_bit=0",
    "ro.warranty_bit=0",
]:
    if forbidden in read("module/prop_table.sh"):
        raise SystemExit(f"warranty-bit consistency cleanup failed: {forbidden}")

print("ZeroMount BRENE v0.0.66 safe port applied successfully")
