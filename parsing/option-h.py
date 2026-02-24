#!/usr/bin/env python3
import sys
import re

DEFINE_RE = re.compile(
    r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b'
)

def extract_macros(path):
    macros = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = DEFINE_RE.match(line)
            if m:
                name = m.group(1)
                if not name.startswith("OPTION_"):
                    macros.append(name)
    return macros

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} config.h")
        sys.exit(1)

    config_h = sys.argv[1]
    macros = extract_macros(config_h)

    with open(config_h, "a", encoding="utf-8") as f:
        f.write("\n/* OPTION_ aliases (auto-generated) */\n")
        for m in macros:
            f.write(f"#define OPTION_{m} {m}\n")

if __name__ == "__main__":
    main()
