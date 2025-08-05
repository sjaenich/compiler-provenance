#!/usr/bin/env python3
import re
import os
import sys
import subprocess
from pathlib import Path

def error_exit(message):
    print(f"[ERROR] {message}")
    sys.exit(1)

def find_package_dir(pkg_name):
    pkg_path = Path("package")
    for path in pkg_path.rglob(pkg_name + ".mk"):
        if path.parent.name == pkg_name:
            return path
    return None

def patch_version(mk_path, version):
    text = mk_path.read_text()
    pkg_var = mk_path.stem.upper()

    pattern = re.compile(rf"{pkg_var}_VERSION\s*=\s*.*")
    if pattern.search(text):
        text = pattern.sub(f"{pkg_var}_VERSION = {version}", text)
        print(f"[INFO] Set version to {version} in {mk_path}")
    else:
        print(f"[WARN] No VERSION line found for {pkg_var}; skipping version set.")

      # Check if _SITE needs to be modified
    site_pattern = re.compile(rf"{pkg_var}_SITE\s*=\s*(.*)")
    site_match = site_pattern.search(text)
    if site_match and "gnome.org" in site_match.group(1):
        major_minor = extract_major_minor(version)
        new_site = f"https://download.gnome.org/sources/{mk_path.stem}/{major_minor}"
        text = site_pattern.sub(f"{pkg_var}_SITE = {new_site}", text)
        print(f"[INFO] Updated SITE to {new_site}")

    mk_path.write_text(text)


def patch_cflags(mk_path, cflags):
    mk_text = mk_path.read_text()

    # Try to inject CFLAGS if not already overridden
    injected = False
    lines = mk_text.splitlines()
    for i, line in enumerate(lines):
        if "_CONF_ENV" in line and "CFLAGS" in line:
            lines[i] = f'{line} CFLAGS="{cflags}"'
            injected = True
            break

    if not injected:
        # Add a new line if no CFLAGS exist
        var_prefix = mk_path.stem.upper()
        lines.append(f'{var_prefix}_CONF_ENV += CFLAGS="{cflags}"')

    mk_path.write_text("\n".join(lines))
    print(f"[INFO] Injected CFLAGS into {mk_path}")

def build_package(pkg_name):
    result = subprocess.run(["make", pkg_name], stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("[BUILD ERROR]")
        print(result.stderr)
        sys.exit(1)
    else:
        print("[BUILD SUCCESS]")
 #       print(result.stdout)

def main():

    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: buildroot_package_builder.py <package-name> <cflags> [version]")
        sys.exit(1)


    package = sys.argv[1]
    cflags = sys.argv[2]
    version = sys.argv[3] if len (sys.argv) == 4 else None


    mk_path = find_package_dir(package)
    if not mk_path:
        error_exit(f"Could not find .mk file for package '{package}'.")

    if version:
        patch_version(mk_path, version)

    patch_cflags(mk_path, cflags)
    build_package(package)

if __name__ == "__main__":
    main()

