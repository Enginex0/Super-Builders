#!/bin/bash
set -euo pipefail

COMMON_TREE="${1:?common tree}"
TARGET="$COMMON_TREE/init/main.c"
CPUFREQ="$COMMON_TREE/drivers/cpufreq/cpufreq.c"

[[ -f "$TARGET" ]] || {
  echo "::error::Kernel init source is unavailable: $TARGET"
  exit 1
}

[[ -f "$CPUFREQ" ]] || {
  echo "::error::CPUFreq source is unavailable: $CPUFREQ"
  exit 1
}

python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "S928B daily: let Samsung PowerHAL select CPUFreq governors"

helper = r'''/* S928B daily: let Samsung PowerHAL select CPUFreq governors. */
static void __init strip_cmdline_key(char *cmdline, const char *key)
{
	char *read = cmdline;
	char *write = cmdline;
	size_t key_len = strlen(key);

	while (*read) {
		char *end;
		size_t token_len;

		while (*read == ' ')
			read++;
		if (!*read)
			break;

		end = strchr(read, ' ');
		if (!end)
			end = read + strlen(read);
		token_len = end - read;

		if (token_len <= key_len || strncmp(read, key, key_len) ||
		    read[key_len] != '=') {
			if (write != cmdline)
				*write++ = ' ';
			memmove(write, read, token_len);
			write += token_len;
		}
		read = end;
	}
	*write = '\0';
}

'''

if marker not in text:
    anchor = "static void __init setup_command_line(char *command_line)\n"
    if text.count(anchor) != 1:
        raise SystemExit("setup_command_line definition anchor is not unique")
    text = text.replace(anchor, helper + anchor, 1)

    call = "\tsetup_command_line(command_line);\n"
    replacement = (
        call
        + '\tstrip_cmdline_key(saved_command_line, "cpufreq.default_governor");\n'
        + '\tstrip_cmdline_key(static_command_line, "cpufreq.default_governor");\n'
    )
    if text.count(call) != 1:
        raise SystemExit("setup_command_line call anchor is not unique")
    text = text.replace(call, replacement, 1)

required = (
    marker,
    'strip_cmdline_key(saved_command_line, "cpufreq.default_governor");',
    'strip_cmdline_key(static_command_line, "cpufreq.default_governor");',
)
missing = [needle for needle in required if text.count(needle) != 1]
if missing:
    raise SystemExit(f"S928B command-line audit failed: {missing}")

forbidden = (
    'strip_cmdline_key(saved_command_line, "log_buf_len");',
    'strip_cmdline_key(static_command_line, "log_buf_len");',
)
present = [needle for needle in forbidden if needle in text]
if present:
    raise SystemExit(f"S928B log_buf_len must remain visible: {present}")

path.write_text(text, encoding="utf-8")
print("S928B CPUFreq command-line override will be ignored and hidden")
print("Samsung PowerHAL remains responsible for selecting the governor")
print("S928B log_buf_len remains visible for post-boot ADB verification")
print("CONFIG_LOG_BUF_SHIFT and AnyKernel both request the audited 4 MiB size")
PY

python3 - "$CPUFREQ" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old_max = "module_param_array(max_freqs, int, NULL, 440);"
old_min = "module_param_array(min_freqs, int, NULL, 440);"
new_max = "module_param_array(max_freqs, int, NULL, 0440);"
new_min = "module_param_array(min_freqs, int, NULL, 0440);"

if old_max in text:
    if text.count(old_max) != 1:
        raise SystemExit("Unexpected duplicate max_freqs module parameter")
    text = text.replace(old_max, new_max, 1)
elif text.count(new_max) != 1:
    raise SystemExit("Samsung max_freqs module parameter was not found")

if old_min in text:
    if text.count(old_min) != 1:
        raise SystemExit("Unexpected duplicate min_freqs module parameter")
    text = text.replace(old_min, new_min, 1)
elif text.count(new_min) != 1:
    raise SystemExit("Samsung min_freqs module parameter was not found")

if text.count(new_max) != 1 or text.count(new_min) != 1:
    raise SystemExit("S928B CPUFreq permission audit failed")

path.write_text(text, encoding="utf-8")
print("S928B CPUFreq max_freqs/min_freqs permissions corrected: 440 -> 0440")
print("This removes the invalid sysfs 0670 mode without making the parameters writable")
PY
