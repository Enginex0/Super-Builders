#!/usr/bin/env python3
"""Add Enhanced SUSFS declarations without relocating or changing upstream structs."""
from pathlib import Path
import re
import sys

patch, header = map(Path, sys.argv[1:])
source = header.read_text(encoding="utf-8")
if "struct st_susfs_sus_kstat_redirect {" in source:
    raise SystemExit("Enhanced SUSFS header already present; unexpected partial/repeated application")
added = "\n".join(line[1:] for line in patch.read_text(encoding="utf-8").splitlines()
                  if line.startswith("+") and not line.startswith("+++"))
matches = list(re.finditer(r"struct st_susfs_sus_kstat_redirect \{.*?\n\s*int\s+err;", added, re.S))
if len(matches) != 1:
    raise SystemExit("Expected one Enhanced SUSFS userspace redirect structure")
redirect = matches[0][0] + "\n};\n"
structs = re.findall(r"^struct st_susfs_sus_kstat(?:_hlist)? \{.*?^};", source, re.M | re.S)
if len(structs) != 2:
    raise SystemExit("Expected intact upstream KSTAT request and hash-entry layouts")
anchor = structs[1]
source = source.replace(anchor, anchor + "\n\n" + redirect, 1)
declarations = """
struct super_block;
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT_REDIRECT
void susfs_add_sus_kstat_redirect(void __user **user_info);
#endif
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER
bool susfs_check_unicode_bypass(const char __user *filename);
#endif
bool susfs_is_hidden_name(const char *name, int namlen, uid_t caller_uid);
bool susfs_is_hidden_ino(struct super_block *sb, unsigned long ino);

"""
anchor = "/* susfs_init */"
if source.count(anchor) != 1:
    raise SystemExit("Expected unique top-level SUSFS declaration anchor")
source = source.replace(anchor, declarations + anchor, 1)
# ReSukiSU's native userspace uses bit 8 for ctime seconds. Upstream's
# comparison typo aliases bit 0 and ignores requests selecting only ctime.
source = source.replace('#define KSTAT_SPOOF_CTIME_TV_SEC (1 < 8)',
                        '#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)')
if re.findall(r"^struct st_susfs_sus_kstat(?:_hlist)? \{.*?^};", source, re.M | re.S) != structs:
    raise SystemExit("Upstream KSTAT layout changed during header adaptation")
header.write_text(source, encoding="utf-8", newline="\n")
print("PASS: Enhanced SUSFS header added; upstream KSTAT UAPI and internal layouts preserved")
