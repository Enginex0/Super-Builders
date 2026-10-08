#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?}"
DEFCONFIG="${2:?}"

cd "$KERNEL_ROOT"

echo "[+] Setting up Baseband Guard wrapper"
echo "[+] Current directory: $(pwd)"

# Upstream Baseband-guard setup kann bei Samsung/GKI manchmal Exit-Code 1 liefern,
# obwohl Repo, Symlink, Makefile und Kconfig bereits teilweise korrekt gesetzt wurden.
curl -LSs https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh -o /tmp/setup-bbg-upstream.sh

set +e
bash /tmp/setup-bbg-upstream.sh
BBG_RC=$?
set -e

if [ "$BBG_RC" -ne 0 ]; then
  echo "::warning::Baseband Guard upstream setup returned exit code $BBG_RC"
  echo "::warning::Continuing if Baseband-guard files were created"

  if [ ! -d "$KERNEL_ROOT/Baseband-guard" ]; then
    echo "FATAL: Baseband-guard directory was not created"
    exit 1
  fi
fi

# BBG in der aktiven Defconfig aktivieren
grep -qxF "CONFIG_BBG=y" "$DEFCONFIG" || echo "CONFIG_BBG=y" >> "$DEFCONFIG"

# CONFIG_LSM setzen/ergänzen
LSM_VALUE='CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf,baseband_guard"'

if grep -q '^CONFIG_LSM=' "$DEFCONFIG"; then
  if ! grep -q '^CONFIG_LSM=.*baseband_guard' "$DEFCONFIG"; then
    sed -i "s|^CONFIG_LSM=.*|$LSM_VALUE|" "$DEFCONFIG"
  fi
else
  echo "$LSM_VALUE" >> "$DEFCONFIG"
fi

# Wichtig:
# Das Script ist bereits in samsung-source/kernel_platform/common/
# Deshalb ist der korrekte relative Pfad NUR security/Kconfig
KCONFIG_PATH="security/Kconfig"

if [ ! -f "$KCONFIG_PATH" ]; then
  echo "::warning::Kconfig file not found at $KCONFIG_PATH"
  echo "::warning::Current directory is: $(pwd)"
  echo "::warning::Searching possible Kconfig files for debug:"
  find . -maxdepth 4 -path '*/security/Kconfig' -print || true
  echo "::warning::Skipping extra LSM default patch, continuing build"
  exit 0
fi

echo "[+] Using Kconfig: $KCONFIG_PATH"

# baseband_guard in die default-LSM-Liste einfügen, wenn noch nicht vorhanden
sed -i '/^config LSM$/,/^help$/{
  /^[[:space:]]*default/ {
    /baseband_guard/! s/lockdown/lockdown,baseband_guard/
  }
}' "$KCONFIG_PATH"

echo "[+] Baseband Guard setup wrapper completed"
