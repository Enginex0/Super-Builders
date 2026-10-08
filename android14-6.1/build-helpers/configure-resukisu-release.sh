#!/bin/bash
set -euo pipefail

KSU_ROOT="${1:?ReSukiSU source directory}"
EXPECTED_BRANCH="${2:?expected ReSukiSU branch}"
EXPECTED_COMMIT="${3:?expected ReSukiSU commit}"
TARGET_VERSION_CODE="${4:?target ReSukiSU version code}"
MANAGER_CERT_SIZE="${5:-}"
MANAGER_CERT_HASH="${6:-}"
PYTHON_BIN="${PYTHON3:-python3}"

[[ "$TARGET_VERSION_CODE" =~ ^[0-9]+$ ]] || {
  echo "::error::Invalid ReSukiSU version code: $TARGET_VERSION_CODE"
  exit 1
}

ACTUAL_COMMIT=$(git -C "$KSU_ROOT" rev-parse HEAD)
[[ "$ACTUAL_COMMIT" == "$EXPECTED_COMMIT" ]] || {
  echo "::error::ReSukiSU pin mismatch: expected $EXPECTED_COMMIT, got $ACTUAL_COMMIT"
  exit 1
}

BRANCH_REF="refs/remotes/origin/$EXPECTED_BRANCH"
git -C "$KSU_ROOT" show-ref --verify --quiet "$BRANCH_REF" || {
  echo "::error::ReSukiSU branch ref is missing: $BRANCH_REF"
  exit 1
}
git -C "$KSU_ROOT" merge-base --is-ancestor "$EXPECTED_COMMIT" "$BRANCH_REF" || {
  echo "::error::ReSukiSU commit $EXPECTED_COMMIT is not on origin/$EXPECTED_BRANCH"
  exit 1
}

COMMIT_COUNT=$(git -C "$KSU_ROOT" rev-list --count HEAD)
UPSTREAM_VERSION_CODE=$((30700 + COMMIT_COUNT))
[[ "$TARGET_VERSION_CODE" == "$UPSTREAM_VERSION_CODE" ]] || {
  echo "::error::ReSukiSU version mismatch: source=$UPSTREAM_VERSION_CODE requested=$TARGET_VERSION_CODE"
  exit 1
}
VERSION_OFFSET=$((TARGET_VERSION_CODE - 30000 - COMMIT_COUNT))
((VERSION_OFFSET >= 0)) || {
  echo "::error::Target version code is lower than the pinned source history"
  exit 1
}

if [[ -n "$MANAGER_CERT_SIZE" || -n "$MANAGER_CERT_HASH" ]]; then
  [[ "$MANAGER_CERT_SIZE" =~ ^0x[0-9a-fA-F]+$ ]] || {
    echo "::error::Invalid custom manager certificate size: $MANAGER_CERT_SIZE"
    exit 1
  }
  [[ "$MANAGER_CERT_HASH" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "::error::Invalid custom manager certificate hash"
    exit 1
  }
fi

"$PYTHON_BIN" - "$KSU_ROOT" "$VERSION_OFFSET" "$TARGET_VERSION_CODE" \
  "$MANAGER_CERT_SIZE" "$MANAGER_CERT_HASH" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
offset = int(sys.argv[2])
target = int(sys.argv[3])
cert_size = sys.argv[4]
cert_hash = sys.argv[5].lower()


def replace_once(path, pattern, replacement, description):
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        return
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(
            f"Cannot apply {description} exactly once in {path}: matches={count}"
        )
    path.write_text(updated, encoding="utf-8")


kbuild = root / "kernel/Kbuild"
replace_once(
    kbuild,
    r"^KSU_VERSION := \$\(shell expr 30000 \+ \$\(KSU_LOCAL_VERSION\) \+ [0-9]+\)$",
    f"KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + {offset})",
    "kernel version override",
)

manager_gradle = root / "manager/build.gradle.kts"
manager_text = manager_gradle.read_text(encoding="utf-8")
if 'extra["managerVersionCode"]' in manager_text:
    manager_version_assignment = (
        f'extra["managerVersionCode"] = 30000 + getGitCommitCount() + {offset}'
    )
    manager_version_pattern = (
        r'^extra\["managerVersionCode"\]\s*=\s*'
        r'30000 \+ getGitCommitCount\(\) \+ [0-9]+$'
    )
else:
    manager_version_assignment = (
        f"val managerVersionCode by extra(30000 + getGitCommitCount() + {offset})"
    )
    manager_version_pattern = (
        r"^val managerVersionCode by extra\(30000 \+ "
        r"getGitCommitCount\(\) \+ [0-9]+\)$"
    )
replace_once(
    manager_gradle,
    manager_version_pattern,
    manager_version_assignment,
    "manager version override",
)

ksud_build = root / "userspace/ksud/build.rs"
ksud_comment = "For historical reasons" if offset == 700 else "Pinned release offset"
replace_once(
    ksud_build,
    r"^    let version_code = 30000 \+ [0-9]+ \+ version_code; // For historical reasons$",
    f"    let version_code = 30000 + {offset} + version_code; // {ksud_comment}",
    "ksud version override",
)

if cert_size and cert_hash:
    text = kbuild.read_text(encoding="utf-8")
    assignments = (
        f"KSU_EXPECTED_SIZE := {cert_size}\n"
        f"KSU_EXPECTED_HASH := {cert_hash}\n\n"
    )
    if assignments not in text:
        if re.search(r"^KSU_EXPECTED_(?:SIZE|HASH) :=", text, re.MULTILINE):
            raise SystemExit(f"Conflicting custom manager certificate in {kbuild}")
        marker = "# Custom Signs\n"
        if text.count(marker) != 1:
            raise SystemExit(f"Cannot locate custom-sign marker exactly once in {kbuild}")
        kbuild.write_text(text.replace(marker, assignments + marker), encoding="utf-8")

checks = {
    kbuild: [
        f"KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + {offset})",
    ],
    manager_gradle: [
        manager_version_assignment,
    ],
    ksud_build: [
        f"let version_code = 30000 + {offset} + version_code;",
    ],
}
if cert_size and cert_hash:
    checks[kbuild].extend(
        [f"KSU_EXPECTED_SIZE := {cert_size}", f"KSU_EXPECTED_HASH := {cert_hash}"]
    )
for path, markers in checks.items():
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Missing configured ReSukiSU marker in {path}: {marker}")

print(f"Configured ReSukiSU target version code: {target}")
if cert_size and cert_hash:
    print(f"Configured paired manager certificate: size={cert_size} sha256={cert_hash}")
PY

# KernelSU userspace may submit the same try-umount path more than once during
# boot. The kernel already rejects the duplicate without changing the list;
# make that ADD idempotent so ksud does not report a harmless EEXIST as an error.
HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UMOUNT_HELPER="$HELPER_DIR/make-resukisu-umount-add-idempotent.sh"
[[ -f "$UMOUNT_HELPER" ]] || {
  echo "::error::Missing ReSukiSU umount idempotency helper: $UMOUNT_HELPER"
  exit 1
}
bash "$UMOUNT_HELPER" "$KSU_ROOT"

# Upstream UAPI 4 multiplexes Dynamic Manager GET and mutating operations on
# one ioctl. Let the registered manager query GET, while the helper injects a
# handler-level uid-0 guard for SET/SET_SYNCHRONOUS/WIPE.
DYNAMIC_MANAGER_HELPER="$HELPER_DIR/apply-resukisu-dynamic-manager-get-permission.py"
[[ -f "$DYNAMIC_MANAGER_HELPER" ]] || {
  echo "::error::Missing ReSukiSU dynamic-manager permission helper: $DYNAMIC_MANAGER_HELPER"
  exit 1
}
"$PYTHON_BIN" "$DYNAMIC_MANAGER_HELPER" "$KSU_ROOT"

TAG=$(git -C "$KSU_ROOT" describe --abbrev=0 --tags 2>/dev/null || true)
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || {
  echo "::error::Unexpected ReSukiSU release tag at $EXPECTED_COMMIT: ${TAG:-none}"
  exit 1
}

echo "ReSukiSU source branch: $EXPECTED_BRANCH"
echo "ReSukiSU source commit: $EXPECTED_COMMIT"
echo "ReSukiSU source commit count: $COMMIT_COUNT"
echo "ReSukiSU upstream version code: $UPSTREAM_VERSION_CODE"
echo "ReSukiSU requested version code: $TARGET_VERSION_CODE"
echo "ReSukiSU release tag: $TAG"
