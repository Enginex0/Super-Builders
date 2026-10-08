#!/usr/bin/env python3
"""Fail closed when the e3q AnyKernel command-line policy is malformed."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


LIVE_BAD_CMDLINE = """watchdog.stop_on_reboot=\"0\" sec-battery.sales_code=\"EUX\"
kasan.page_alloc.sample=10 kasan.stacktrace=off bootconfig loglevel=6 kpti=0
kasan=off loop.max_part=7 off off off 4M off 4M"""

REQUIRED_CALLS = {
    "cpufreq.default_governor=": "",
    "kpti=": "",
    "kasan=": "kasan=off",
}


def fail(message: str) -> None:
    raise SystemExit(f"S928B AnyKernel cmdline audit failed: {message}")


def patch_cmdline(tokens: list[str], key: str, replacement: str) -> None:
    """Model AnyKernel3's patch_cmdline contract for one command-line token."""
    match = next((index for index, token in enumerate(tokens) if key in token), None)
    if match is None:
        if replacement:
            tokens.append(replacement)
        return
    if replacement:
        tokens[match] = replacement
    else:
        tokens.pop(match)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("anykernel_dir", type=Path)
    parser.add_argument("--require-log-buf", action="store_true")
    args = parser.parse_args()

    anykernel = args.anykernel_dir / "anykernel.sh"
    core = args.anykernel_dir / "tools" / "ak3-core.sh"
    if not anykernel.is_file() or not core.is_file():
        fail(f"missing anykernel.sh or tools/ak3-core.sh under {args.anykernel_dir}")

    script = anykernel.read_text(encoding="utf-8")
    core_text = core.read_text(encoding="utf-8")
    if "# patch_cmdline <cmdline entry name> <replacement string>" not in core_text:
        fail("unexpected AnyKernel3 patch_cmdline API")

    call_list = re.findall(
        r'^\s*patch_cmdline\s+"([^"]*)"\s+"([^"]*)"\s*$',
        script,
        flags=re.MULTILINE,
    )
    key_counts = Counter(key for key, _ in call_list)
    duplicate_keys = sorted(key for key, count in key_counts.items() if count != 1)
    if duplicate_keys:
        fail(f"patch_cmdline keys must appear exactly once: {duplicate_keys}")
    calls = dict(call_list)
    expected = dict(REQUIRED_CALLS)
    if args.require_log_buf:
        expected["log_buf_len="] = "log_buf_len=4M"
    for key, replacement in expected.items():
        if calls.get(key) != replacement:
            fail(f"expected patch_cmdline {key!r} {replacement!r}, found {calls.get(key)!r}")

    unsafe = [
        (key, replacement)
        for key, replacement in calls.items()
        if replacement in {"off", "4M"}
    ]
    if unsafe:
        fail(f"bare replacement values would corrupt /proc/cmdline: {unsafe}")

    if "sanitize_s928b_cmdline()" not in script:
        fail("standalone-token sanitizer is missing")
    if script.count("sanitize_s928b_cmdline") != 2:
        fail("standalone-token sanitizer must be defined and called exactly once")
    if "patch_bootconfig" in script:
        fail("kernel command-line policy must not rewrite vendor_boot bootconfig")

    tokens = LIVE_BAD_CMDLINE.split()
    tokens = [token for token in tokens if token not in {"off", "4M"}]
    for key, replacement in calls.items():
        patch_cmdline(tokens, key, replacement)

    if any(token in {"off", "4M"} for token in tokens):
        fail("simulated command line still contains bare off/4M tokens")
    if any(token == "kpti=0" for token in tokens):
        fail("simulated command line still contains kpti=0")
    if tokens.count("kasan=off") != 1:
        fail("simulated command line must contain exactly one kasan=off")
    if "kasan.stacktrace=off" not in tokens:
        fail("exact-key matching removed kasan.stacktrace=off unexpectedly")
    if args.require_log_buf and tokens.count("log_buf_len=4M") != 1:
        fail("simulated command line must contain exactly one log_buf_len=4M")
    if 'sec-battery.sales_code="EUX"' not in tokens:
        fail("EUX sales-code token was altered")
    print(
        "Verified S928B AnyKernel cmdline policy: bare off/4M removed, "
        "exact key replacement used, vendor_boot bootconfig untouched."
    )


if __name__ == "__main__":
    main()
