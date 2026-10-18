#!/bin/bash
# colonel-tier.sh - Apply the Colonel tier in a local build
# Run after ksu-next and susfs/zeromount tiers
# FLAGS = Logic | C/H Files = Movement | DISC = Proof | PATCH = Seal
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COLONEL_TIER="$REPO_ROOT/colonel"

echo "=== Colonel Tier ==="
echo "Tier 3: VFS Environment Shaping + Kotoamatsukami obfuscation"

# Verify colonel source is in kernel
KERNEL_DIR="${1:-kernel-source}"
if [ ! -d "$KERNEL_DIR/fs/koto/colonel" ]; then
    echo "ERROR: $KERNEL_DIR/fs/koto/colonel not found"
    echo "Run KSU+SUSFS tier first to set up the koto/ base"
    exit 1
fi

echo "=== Colonel source files present: ==="
ls -la "$KERNEL_DIR/fs/koto/colonel/" | head -10

# Verify Clang 17 is available
if ! command -v clang-17 >/dev/null 2>&1; then
    echo "WARNING: clang-17 not in PATH, will use clang-12 only"
fi

# Verify Kotoamatsukami plugin
KOTO_SO="$COLONEL_TIER/../bin/build/Kotoamatsukami.so"
if [ -f "$KOTO_SO" ]; then
    echo "Kotoamatsukami plugin: $KOTO_SO"
else
    echo "Kotoamatsukami plugin NOT FOUND - will build without obfuscation"
    echo "  Build with: cd $REPO_ROOT/.. && git clone Kotoamatsukami && cd Kotoamatsukami && mkdir build && cd build && cmake .. && make -j"
fi

# Set up CC to use colonel wrapper
cat > "$KERNEL_DIR/.colonel-cc" << 'CC_WRAPPER'
#!/bin/bash
# Auto-generated CC wrapper for Colonel tier
exec /usr/local/bin/colonel-cc "$@"
CC_WRAPPER
chmod +x "$KERNEL_DIR/.colonel-cc"

echo "=== Colonel tier ready ==="
echo "Build with:"
echo "  cd $KERNEL_DIR"
echo "  make O=out Image.lz4 modules -j\$(nproc)"
