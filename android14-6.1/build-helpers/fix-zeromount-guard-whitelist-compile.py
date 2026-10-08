#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
path = root / "src/guard/mod.rs"
text = path.read_text(encoding="utf-8")

replacements = {
    "GuardAction::WatchBoot => monitors::wait_boot_completed(&config)?,": "GuardAction::WatchBoot => {\n            monitors::wait_boot_completed(&config)?;\n        }",
    "GuardAction::WatchSystemui => monitors::watch_systemui(&config)?,": "GuardAction::WatchSystemui => {\n            monitors::watch_systemui(&config)?;\n        }",
}

for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit(f"expected exactly one compiler-fix anchor: {old!r}; count={text.count(old)}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
print("ZeroMount Guard monitor return-type fix applied")
