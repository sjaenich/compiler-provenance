import re


DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+1\s*$')
UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')

# matches any object-like define (not function-like)
DEFINE_OTHER_RE = re.compile(
    r'^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()'
)

path = "/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/curl_config.h"
out_path = "/workspaces/RevEng/other_defines.h"

with open(path, "r", encoding="utf-8", errors="ignore") as f, \
     open(out_path, "w", encoding="utf-8") as out:

    out.write("/* Auto-extracted non-boolean defines */\n\n")

    for line in f:
        print(line.rstrip())

        handled = False

        # ✅ boolean defines (#define FOO 1)
        match = DEFINE_BOOL_RE.match(line)
        if match:
            macro_name = match.group(1)
            print("Bools", macro_name)
            handled = True

        # ✅ undef comments
        m_undef = UNDEF_RE.match(line)
        if m_undef:
            macro_name = m_undef.group(1)
            
            print("Bools", macro_name, "false")
            handled = True

        # ✅ everything else that is a #define
        if not handled:
            m_other = DEFINE_OTHER_RE.match(line)
            if m_other:
                out.write(line)
