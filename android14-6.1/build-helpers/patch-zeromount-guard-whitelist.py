#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if old not in text:
        raise SystemExit(f"expected anchor missing in {rel}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"anchor is not unique in {rel}: count={text.count(old)}")
    write(rel, text.replace(old, new, 1))


# Keep this fork visibly distinct from upstream v2.0.216-dev.
replace_once(
    "Cargo.toml",
    'version = "2.0.216-dev"',
    'version = "2.0.216-dev.guard1"',
)

# Restore the persistent allowed_modules field that existed before the
# 2026-03-26 guard self-disable refactor. Keep the new single-bootcount guard.
replace_once(
    "src/core/config.rs",
    "fn default_systemui_absent() -> u32 { 25 }\n\n#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct GuardConfig {",
    "fn default_systemui_absent() -> u32 { 25 }\nfn default_allowed_modules() -> Vec<String> { vec![\"meta-zeromount\".to_string()] }\n\n#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct GuardConfig {",
)
replace_once(
    "src/core/config.rs",
    "    #[serde(default)]\n    pub systemui_monitor_enabled: bool,\n}\n\nimpl Default for GuardConfig {",
    "    #[serde(default)]\n    pub systemui_monitor_enabled: bool,\n    #[serde(default = \"default_allowed_modules\")]\n    pub allowed_modules: Vec<String>,\n}\n\nimpl Default for GuardConfig {",
)
replace_once(
    "src/core/config.rs",
    "            systemui_absent_timeout_secs: 25,\n            systemui_monitor_enabled: false,\n        }",
    "            systemui_absent_timeout_secs: 25,\n            systemui_monitor_enabled: false,\n            allowed_modules: default_allowed_modules(),\n        }",
)

# Re-add the CLI commands that the v2.0.216 WebUI already calls.
replace_once(
    "src/cli/mod.rs",
    "    #[command(name = \"clear-lockout\")]\n    ClearLockout,\n    /// Print guard status",
    "    #[command(name = \"clear-lockout\")]\n    ClearLockout,\n    /// Add a module ID to the persistent guard whitelist\n    Allow { name: String },\n    /// Remove a module ID from the persistent guard whitelist\n    Disallow { name: String },\n    /// Print guard status",
)

# Replace guard dispatcher with a version that validates module IDs, persists
# the allowlist in config.toml and exposes it through `guard status`.
write(
    "src/guard/mod.rs",
    r'''pub mod monitors;
pub mod recovery;

use std::path::Path;

use anyhow::{bail, Result};

use crate::cli::GuardAction;
use crate::core::config::ZeroMountConfig;

const SELF_MODULE: &str = "meta-zeromount";
const MODULES_DIR: &str = "/data/adb/modules";

pub fn handle_guard(action: GuardAction) -> Result<()> {
    let config = ZeroMountConfig::load(None)?;

    // Management operations must work even when the runtime guard is disabled.
    match &action {
        GuardAction::Status => return print_status(&config),
        GuardAction::Allow { name } => return allow_module(config, name),
        GuardAction::Disallow { name } => return disallow_module(config, name),
        GuardAction::ClearLockout => {
            recovery::clear_lockout();
            return Ok(());
        }
        _ => {}
    }

    if !config.guard.enabled {
        tracing::debug!("guard disabled, skipping");
        return Ok(());
    }

    match action {
        GuardAction::Check => {
            if recovery::is_locked_out()
                || Path::new("/data/adb/modules/meta-zeromount/disable").exists()
            {
                std::process::exit(1);
            }
        }
        GuardAction::WatchBoot => monitors::wait_boot_completed(&config)?,
        GuardAction::WatchZygote => {
            monitors::watch_zygote(&config)?;
        }
        GuardAction::WatchSystemui => monitors::watch_systemui(&config)?,
        GuardAction::Recover => recovery::execute(&config),
        GuardAction::Status
        | GuardAction::ClearLockout
        | GuardAction::Allow { .. }
        | GuardAction::Disallow { .. } => unreachable!(),
    }

    Ok(())
}

fn valid_module_id(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn allow_module(mut config: ZeroMountConfig, name: &str) -> Result<()> {
    if !valid_module_id(name) {
        bail!("invalid module ID: {name:?}");
    }

    let module_path = Path::new(MODULES_DIR).join(name);
    if name != SELF_MODULE && !module_path.is_dir() {
        bail!("module does not exist: {name}");
    }

    if !config.guard.allowed_modules.iter().any(|m| m == name) {
        config.guard.allowed_modules.push(name.to_string());
        config.guard.allowed_modules.sort();
        config.guard.allowed_modules.dedup();
        config.save()?;
    }

    println!("allowed: {name}");
    Ok(())
}

fn disallow_module(mut config: ZeroMountConfig, name: &str) -> Result<()> {
    if !valid_module_id(name) {
        bail!("invalid module ID: {name:?}");
    }
    if name == SELF_MODULE {
        bail!("{SELF_MODULE} is self-managed and cannot be removed from the whitelist");
    }

    config.guard.allowed_modules.retain(|m| m != name);
    if !config.guard.allowed_modules.iter().any(|m| m == SELF_MODULE) {
        config.guard.allowed_modules.push(SELF_MODULE.to_string());
    }
    config.guard.allowed_modules.sort();
    config.guard.allowed_modules.dedup();
    config.save()?;

    println!("disallowed: {name}");
    Ok(())
}

fn print_status(config: &ZeroMountConfig) -> Result<()> {
    let bootcount = ZeroMountConfig::read_bootcount();
    let disabled = Path::new("/data/adb/modules/meta-zeromount/disable").exists();
    let lockout = recovery::is_locked_out();
    println!("bootcount: {bootcount}");
    println!("disabled: {disabled}");
    println!("recovery_lockout: {lockout}");
    println!("allowed_modules: {}", config.guard.allowed_modules.join(", "));
    Ok(())
}
''',
)

# Safe recovery semantics for the custom fork:
# - Default behavior is unchanged: if only meta-zeromount is whitelisted,
#   recovery self-disables ZeroMount only.
# - If the user explicitly adds protected modules, recovery also disables only
#   *ZeroMount-scannable mount modules* that are NOT whitelisted. Script-only,
#   manual-mount and skip_mount modules remain untouched. This avoids restoring
#   the old pre-refactor "disable everything" nuclear recovery.
write(
    "src/guard/recovery.rs",
    r'''use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::core::config::ZeroMountConfig;
use crate::modules::scanner::{scan_modules, ScanOptions};

const MODULE_DIR: &str = "/data/adb/modules/meta-zeromount";
const MODULES_DIR: &str = "/data/adb/modules";
const ACTIVITY_LOG: &str = "/data/adb/zeromount/activity.log";
const RECOVERY_LOCKOUT: &str = "/data/adb/zeromount/.recovery_lockout";
const SELF_MODULE: &str = "meta-zeromount";

pub fn execute(config: &ZeroMountConfig) -> ! {
    let timestamp = timestamp_iso8601();
    let whitelist: HashSet<&str> = config
        .guard
        .allowed_modules
        .iter()
        .map(String::as_str)
        .collect();

    let has_explicit_whitelist = config
        .guard
        .allowed_modules
        .iter()
        .any(|m| m != SELF_MODULE);

    let mut disabled_managed = Vec::new();

    if has_explicit_whitelist {
        let opts = ScanOptions {
            exclude_hosts: config.mount.exclude_hosts_modules,
            blacklist: &config.mount.module_blacklist,
        };

        match scan_modules(Path::new(MODULES_DIR), &opts) {
            Ok(modules) => {
                for module in modules {
                    if whitelist.contains(module.id.as_str()) {
                        continue;
                    }
                    let disable_path = module.path.join("disable");
                    if fs::File::create(&disable_path).is_ok() {
                        disabled_managed.push(module.id);
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "guard whitelist: scoped module scan failed"),
        }
    }

    // Preserve v2.0.216's safe self-disable behavior as the primary recovery.
    let _ = fs::File::create(Path::new(MODULE_DIR).join("disable"));

    let msg = format!(
        "[{timestamp}] guard_recovery: zeromount self-disabled; scoped_disabled={} [{}]; protected=[{}]",
        disabled_managed.len(),
        disabled_managed.join(", "),
        config.guard.allowed_modules.join(", ")
    );

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(ACTIVITY_LOG) {
        let _ = writeln!(f, "{msg}");
    }
    tracing::error!("{msg}");

    let description = if disabled_managed.is_empty() {
        "⚠️ Guard recovery — ZeroMount self-disabled. Re-enable manually.".to_string()
    } else {
        format!(
            "⚠️ Guard recovery — ZeroMount self-disabled; {} managed modules isolated. Whitelist preserved.",
            disabled_managed.len()
        )
    };
    let _ = crate::utils::platform::write_description_to_module_prop(&description);

    let _ = fs::remove_file("/data/adb/zeromount/.bootcount");
    let _ = fs::write(RECOVERY_LOCKOUT, timestamp.as_bytes());

    let _ = Command::new("/system/bin/svc")
        .args(["power", "reboot"])
        .status();
    std::process::exit(1);
}

pub fn is_locked_out() -> bool {
    Path::new(RECOVERY_LOCKOUT).exists()
}

pub fn clear_lockout() {
    let _ = fs::remove_file(RECOVERY_LOCKOUT);
}

fn timestamp_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
''',
)

# Complete the Rust -> WebUI guard status contract. The TypeScript model already
# expected allowedModules/pfdMarkers/svcMarkers, but v2.0.216 did not serialize them.
replace_once(
    "src/cli/webui_init.rs",
    "    pub disabled: bool,\n    pub last_recovery: Option<String>,\n}",
    "    pub disabled: bool,\n    pub last_recovery: Option<String>,\n    pub allowed_modules: Vec<String>,\n    pub pfd_markers: u32,\n    pub svc_markers: u32,\n}",
)
replace_once(
    "src/cli/webui_init.rs",
    "        disabled: std::path::Path::new(\"/data/adb/modules/meta-zeromount/disable\").exists(),\n        last_recovery,\n    };",
    "        disabled: std::path::Path::new(\"/data/adb/modules/meta-zeromount/disable\").exists(),\n        last_recovery,\n        allowed_modules: config.guard.allowed_modules.clone(),\n        pfd_markers: 0,\n        svc_markers: 0,\n    };",
)

# Fix false-positive success UI: kernelsu-alt returns errno/stdout/stderr instead
# of rejecting the Promise when a shell command exits non-zero.
replace_once(
    "webui/src/lib/store.ts",
    "    try {\n      await runShell(`${PATHS.BINARY} guard allow ${name}`);\n      setGuardStatus(prev => ({",
    "    try {\n      const result = await runShell(`${PATHS.BINARY} guard allow ${name}`);\n      if (result.errno !== 0) throw new Error(result.stderr || result.stdout || `guard allow failed: ${result.errno}`);\n      setGuardStatus(prev => ({",
)
replace_once(
    "webui/src/lib/store.ts",
    "    try {\n      await runShell(`${PATHS.BINARY} guard disallow ${name}`);\n      setGuardStatus(prev => ({",
    "    try {\n      const result = await runShell(`${PATHS.BINARY} guard disallow ${name}`);\n      if (result.errno !== 0) throw new Error(result.stderr || result.stdout || `guard disallow failed: ${result.errno}`);\n      setGuardStatus(prev => ({",
)

# Make the UI description accurately reflect the safe scoped semantics.
replace_once(
    "webui/src/locales/en.json",
    '"guard.whitelistDesc": "Whitelisted modules survive boot guard recovery"',
    '"guard.whitelistDesc": "Whitelisted ZeroMount-managed modules survive scoped guard isolation"',
)
replace_once(
    "webui/src/locales/de.json",
    '"guard.whitelistDesc": "Whitelisted modules survive boot guard recovery"',
    '"guard.whitelistDesc": "Freigegebene ZeroMount-Module bleiben bei der gezielten Guard-Isolierung aktiv"',
)

# Static assertions so CI fails instead of silently packaging a partial port.
checks = {
    "src/cli/mod.rs": ["Allow { name: String }", "Disallow { name: String }"],
    "src/core/config.rs": ["pub allowed_modules: Vec<String>"],
    "src/guard/mod.rs": ["allowed_modules:", "allow_module", "disallow_module"],
    "src/guard/recovery.rs": ["has_explicit_whitelist", "scan_modules", "scoped_disabled"],
    "src/cli/webui_init.rs": ["pub allowed_modules: Vec<String>", "allowed_modules: config.guard.allowed_modules.clone()"],
    "webui/src/lib/store.ts": ["guard allow failed", "guard disallow failed"],
}
for rel, needles in checks.items():
    text = read(rel)
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"verification failed: {needle!r} missing from {rel}")

print("ZeroMount v2.0.216-dev.guard1 guard whitelist patch applied successfully")
