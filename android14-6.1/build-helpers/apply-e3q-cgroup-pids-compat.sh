#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common kernel tree is required}"

[[ -d "$COMMON_TREE" ]] || {
  echo "::error::Missing common kernel tree: $COMMON_TREE"
  exit 1
}

# Samsung SM-S928B / e3q vendor modules are built against the stock cgroup
# layout with CONFIG_CGROUP_PIDS disabled. Do not patch cgroup core in an
# attempt to make the PIDs controller coexist with those prebuilts.
echo "Samsung e3q: CONFIG_CGROUP_PIDS remains disabled; no cgroup core compatibility patch applied"
