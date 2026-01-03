import re
from collections import defaultdict

def parse_configure(configure_path):
    """
    Parse configure script to map --enable / --with options to defined macros.
    """
    mapping = defaultdict(list)
    with open(configure_path) as f:
        lines = f.readlines()

    current_option = None
    enable_var = None

    for line in lines:
        # Detect option assignment
        m = re.match(r'\s*--(enable|with)-(\w+)', line)
        if m:
            current_option = f"--{m.group(1)}-{m.group(2)}"
            continue

        # Detect setting shell variable for option
        m2 = re.match(r'\s*(\w+)=yes', line)
        if m2 and current_option:
            enable_var = m2.group(1)
            continue

        # Detect macros written with echo or AC_DEFINE
        if enable_var and enable_var in line:
            # naive extraction of macro
            macro_match = re.search(r'#define\s+(\w+)', line)
            if macro_match:
                mapping[current_option].append(macro_match.group(1))

    return dict(mapping)

if __name__ == "__main__":
    mapping = parse_configure("/root/buildroot/buildroot-2025.02.4/output/build/libcurl-7.71.1/configure")
    for option, macros in mapping.items():
        print(f"{option} -> {macros}")
