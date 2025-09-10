#!/usr/bin/env python3
import os
import re
import subprocess
import requests
import tarfile
from io import BytesIO
from bs4 import BeautifulSoup
import argparse
from buildsystem import BuildSystem

# Try these releases in order (latest first)
OPENWRT_RELEASES = [
    # "releases/24.10.2",
    # "releases/23.05.5",
    # "releases/22.03.6",
    # "releases/21.02.7",
    # "releases/19.07.5/",
    # "releases/18.06.9/",
    # "releases/17.01.7/",
    "chaos_calmer/15.05.1/",
    # "barrier_breaker/14.07/",
    # "attitude_adjustment/12.09/",
    # "backfire/10.03.1/",
    # "kamikaze/8.09.2/",
]

BASE_URL = "https://downloads.openwrt.org/"

# libc fallback mapping: prefer detected, but fall back to musl if needed
LIBC_PREFERENCE = {
    "uclibc": ["uclibc", "l"],
    "glibc":  ["glibc", "musl"],
    "musl":   ["musl"],
    None:     ["musl"]
}


TARGETS = {
    "adm5120": {
        "Platform": "Infineon/ADMtek ADM5120",
        "Architecture": "MIPS",
        "Endianness": "big/little",
        "Developers": ["florian", "juhosg"],
        "Notes": "adm5120"
    },
    "adm8668": {
        "Platform": "Infineon/ADMtek ADM8668",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "adm8668?"
    },
    "ar7": {
        "Platform": "Texas Instruments AR7",
        "Architecture": "MIPS",
        "Endianness": "big/little",
        "Developers": ["florian"],
        "Notes": "ar7"
    },
    "ar71xx": {
        "Platform": "Atheros AR71xx/AR724x/913x",
        "Architecture": "MIPS",
        "Endianness": "big",
        "Developers": ["juhosg", "Kaloz"],
        "Notes": "ar71xx"
    },
    "arc770": {
        "Platform": "Synopsys DesignWare ARC 770D",
        "Architecture": "ARC",
        "Endianness": "little",
        "Developers": ["abrodkin"],
        "Notes": "arc770"
    },
    "archs38": {
        "Platform": "Synopsys DesignWare ARC HS38",
        "Architecture": "ARC",
        "Endianness": "little",
        "Developers": ["abrodkin"],
        "Notes": "archs38"
    },
    "at91": {
        "Platform": "Atmel AT91",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["hcg", "claudio"],
        "Notes": "at91"
    },
    "atheros": {
        "Platform": "Atheros AR231x/5312",
        "Architecture": "MIPS",
        "Endianness": "big",
        "Developers": ["nbd", "Kaloz"],
        "Notes": "atheros"
    },
    "au1000": {
        "Platform": "RMI/AMD Alchemy 1500/1550",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["florian", "nico"],
        "Notes": "au1000"
    },
    "avr32": {
        "Platform": "Atmel AT32AP7000",
        "Architecture": "AVR32",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "avr32"
    },
    "bcm53xx": {
        "Platform": "Broadcom BCM47xx/53xx",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["rmilecki"],
        "Notes": "bcm53xx"
    },
    "brcm-2.4": {
        "Platform": "Broadcom BCM47xx/53xx",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["nbd", "pavlov"],
        "Notes": "brcm-2.4"
    },
    "brcm2708": {
        "Platform": "Broadcom BCM2708",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "brcm2708"
    },
    "brcm47xx": {
        "Platform": "Broadcom BCM47xx/53xx",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["nbd", "mbm", "pavlov"],
        "Notes": "brcm47xx"
    },
    "brcm63xx": {
        "Platform": "Broadcom BCM63xx",
        "Architecture": "MIPS",
        "Endianness": "big",
        "Developers": ["florian", "cshore?", "jogo"],
        "Notes": "brcm63xx"
    },
    "cns3xxx": {
        "Platform": "Cavium Networks CNS3xxx",
        "Architecture": "ARM",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "cns3xxx?"
    },
    "cobalt": {
        "Platform": "Cobalt Microservers",
        "Architecture": "MIPS32/64",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "cobalt"
    },
    "ep93xx": {
        "Platform": "Cirrus Logic EP93xx",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "ep93xx"
    },
    "imx23": {
        "Platform": "Freescale i.MX23 series",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["wigyori"],
        "Notes": ""
    },
    "iop32x": {
        "Platform": "Intel IOP32x",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["Kaloz"],
        "Notes": "iop32x"
    },
    "ixp4xx": {
        "Platform": "Intel IXP42x",
        "Architecture": "ARM",
        "Endianness": "big",
        "Developers": ["Kaloz", "rwhitby"],
        "Notes": "ixp4xx"
    },
    "gemini": {
        "Platform": "Cortina CS351x (StormSemi SL351x)",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["Kaloz"],
        "Notes": "gemini"
    },
    "kirkwood": {
        "Platform": "Marvell MV88F61xx/MV88F62xx",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["Kaloz"],
        "Notes": "kirkwood"
    },
    "lantiq": {
        "Platform": "Lantiq FALC-ON/XWAY",
        "Architecture": "MIPS",
        "Endianness": "big & little",
        "Developers": ["blogic?"],
        "Notes": "lantiq?2"
    },
    "magicbox": {
        "Platform": "AMCC PowerPC 405",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["nbd", "Kaloz"],
        "Notes": "magicbox1"
    },
    "malta": {
        "Platform": "MIPS Technologies Inc. Malta CoreLV",
        "Architecture": "MIPS32/64",
        "Endianness": "big & little",
        "Developers": ["florian"],
        "Notes": "malta"
    },
    "mcs814x": {
        "Platform": "Moschip MCS814x",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "mcs814x"
    },
    "mpc52xx": {
        "Platform": "Freescale MPC52xx",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["juhosg"],
        "Notes": "mpc52xx?"
    },
    "mpc83xx": {
        "Platform": "Freescale MPC83xx",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "mpc83xx?"
    },
    "mpc85xx": {
        "Platform": "Freescale MPC85xx",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "mpc85xx?"
    },
    "mvebu": {
        "Platform": "Marvell Armada XP/370",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["luka", "Kaloz"],
        "Notes": "mvebu"
    },
    "mxs": {
        "Platform": "Freeescale i.MX23/28",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["wigyori"],
        "Notes": "mxs?"
    },
    "netlogic": {
        "Platform": "Broadcom/Netlogic XLP/XLR",
        "Architecture": "MIPS64",
        "Endianness": "big",
        "Developers": ["florian"],
        "Notes": "netlogic?"
    },
    "octeon": {
        "Platform": "Cavium Networks Octeon",
        "Architecture": "MIPS64",
        "Endianness": "big",
        "Developers": ["Kaloz", "blogic?"],
        "Notes": "octeon"
    },
    "olpc": {
        "Platform": "x86",
        "Architecture": "x86",
        "Endianness": "little",
        "Developers": ["ryd?", "blogic?"],
        "Notes": "olpc?"
    },
    "orion": {
        "Platform": "Marvell MV88F518x/MV88F528x",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["Kaloz"],
        "Notes": "orion"
    },
    "oxnas": {
        "Platform": "PLXTECH/Oxford NAS782x/OX82x",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["dangole"],
        "Notes": "oxnas?"
    },
    "pistachio": {
        "Platform": "MIPS interAptiv cXT200",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["wigyori", "luka"],
        "Notes": "pistachio?"
    },
    "ppc40x": {
        "Platform": "AMCC PPC40x",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "ppc40x"
    },
    "ppc44x": {
        "Platform": "AMCC PPC44x",
        "Architecture": "PowerPC",
        "Endianness": "big",
        "Developers": ["Kaloz"],
        "Notes": "ppc44x"
    },
    "ps3": {
        "Platform": "Sony PS3 Game Console",
        "Architecture": "PowerPC64",
        "Endianness": "big",
        "Developers": ["geoff"],
        "Notes": "ps3"
    },
    "pxa": {
        "Platform": "Marvell/Intel PXA250",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["Kaloz"],
        "Notes": "pxa"
    },
    "ramips": {
        "Platform": "Ralink RT28xx/RT305X",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["Kaloz", "juhosg", "blogic?"],
        "Notes": "ramips?"
    },
    "rb532": {
        "Platform": "Mikrotik RouterBoard 532",
        "Architecture": "MIPS",
        "Endianness": "little",
        "Developers": ["nbd", "florian"],
        "Notes": "rb532"
    },
    "realview": {
        "Platform": "ARM Ltd. Realview EB",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "realview"
    },
    "rdc": {
        "Platform": "RDC321x/RDC861x",
        "Architecture": "i486",
        "Endianness": "little",
        "Developers": ["florian"],
        "Notes": "rdc"
    },
    "sibyte": {
        "Platform": "Broadcom/SiByte SB1",
        "Architecture": "MIPS32/64",
        "Endianness": "big/little",
        "Developers": ["Kaloz"],
        "Notes": "sibyte"
    },
    "sunxi": {
        "Platform": "AllWinner A1x/A20",
        "Architecture": "ARM",
        "Endianness": "little",
        "Developers": ["wigyori"],
        "Notes": "sunxi?"
    },
    "uml": {
        "Platform": "User Mode Linux",
        "Architecture": "native",
        "Endianness": "native",
        "Developers": ["groz?", "nico"],
        "Notes": "uml"
    },
    "x86": {
        "Platform": "x86",
        "Architecture": "x86",
        "Endianness": "little",
        "Developers": ["nbd", "nico", "pavlov"],
        "Notes": "x86"
    }
}




def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
def resolve_symlink(path):
    return os.path.realpath(path) if os.path.islink(path) else path

def detect_libc_type_and_version(path):
    """Returns (libc_type, version)"""
    libc_type = None
    version = None

    # 1. Try readelf .comment
    comment = run_cmd(f"readelf -p .comment {path}")
    if "uClibc" in comment:
        libc_type = "uClibc"
        vmatch = re.search(r'uClibc\s+(\d+\.\d+(\.\d+)?)+(\.\d+)?', comment)
        if vmatch:
            version = vmatch.group(0)
    elif "musl" in comment.lower():
        libc_type = "musl"
        vmatch = re.search(r'musl libc (\d+\.\d+(\.\d+)?)+(\.\d+)?', comment, re.I)
        if vmatch:
            version = vmatch.group(0)
    elif "GCC" in comment or "GNU" in comment:
        libc_type = "glibc"
        vmatch = re.search(r'GCC: \([^)]+\s+(\d+\.\d+)', comment)
        if vmatch:
            version = vmatch.group(0)
    
    # 2. Fallback: use filename
    if not version:
        fname = os.path.basename(path)
        vmatch = re.search(r'(\d+\.\d+(\.\d+)?)+(\.\d+)?', fname)
        if vmatch:
            version = vmatch.group(0)
    
    # 3. Fallback: use strings
    if not libc_type:
        strings_out = run_cmd(f"strings -n 4 {path}")
        if "uClibc" in strings_out:
            libc_type = "uClibc"
        elif "musl" in strings_out:
            libc_type = "musl"
        elif "GLIBC" in strings_out:
            libc_type = "glibc"

    return libc_type, version

def analyze_library(path):
    real_path = resolve_symlink(path)
    result = {
        "path": path,
        "real_path": real_path,
        "libc": None,
        "version": None,
        "arch": None,
        "endian": None
    }

    result["libc"], result["version"] = detect_libc_type_and_version(real_path)

    # Detect arch and endian via 'file'
    file_out = run_cmd(f"file {real_path}")
    if "ARM" in file_out:
        result["arch"] = "arm"
    elif "MIPS" in file_out:
        result["arch"] = "mips"
    elif "Intel" in file_out or "x86" in file_out:
        result["arch"] = "x86"

    if "LSB" in file_out:
        result["endian"] = "little"
    elif "MSB" in file_out:
        result["endian"] = "big"

    return result

def search_rootfs(rootfs_path):
    results = []
    for dirpath, dirnames, filenames in os.walk(rootfs_path):
        for fname in filenames:
            if re.match(r'(ld-linux.*\.so.*|libc\.so.*)', fname):
                full_path = os.path.join(dirpath, fname)
                info = analyze_library(full_path)
                # results.append(info)
    return info

def analyze_binary(binary_path, rootfs_path):
    info = {"arch": None, "endian": None, "libc": None, "gcc": None, "build": None}

    # use 'file' for architecture + endian
    file_out = run_cmd(f"file {binary_path}")
    if "ARM" in file_out:
        info["arch"] = "arm"
    elif "MIPS" in file_out:
        info["arch"] = "mips"
    elif "Intel" in file_out or "x86" in file_out:
        info["arch"] = "x86"

    if "LSB" in file_out:
        info["endian"] = "little"
    elif "MSB" in file_out:
        info["endian"] = "big"

    results = search_rootfs(rootfs_path=rootfs_path)
    # use strings to detect libc and gcc
    info["libc"] = results["libc"]
    info["version"] = results["version"]
        

    build_sys = BuildSystem(rootfs=rootfs_path)
    build_sys.detect_build_system()
    info["build"] = build_sys.type
    
    return info

def suggest_toolchain_prefix(info, libc):
    if info["arch"] == "arm" and info["endian"] == "little":
        prefix = "arm-openwrt-linux"
    elif info["arch"] == "arm" and info["endian"] == "big":
        prefix = "armeb-openwrt-linux"
    elif info["arch"] == "mips" and info["endian"] == "little":
        prefix = "mipsel-openwrt-linux"
    elif info["arch"] == "mips" and info["endian"] == "big":
        prefix = "mips-openwrt-linux"
    else:
        return None
    libc = info["libc"]
    return f"{prefix}-{libc}gnueabi"

def find_toolchain_urls(toolchain, release):
    base = f"{BASE_URL}{release}/targets/"
    resp = requests.get(base) 
    if resp.status_code != 200:
        base = f"{BASE_URL}{release}/"
        resp = requests.get(base) 
        if resp.status_code !=200:
            return []

    soup = BeautifulSoup(resp.text, "html.parser")
    matches = []

    for link in soup.find_all("a"):
        href = link.get("href")
        if href and not href.startswith("../"):
            for board in TARGETS:
                
                if board in str(href) and TARGETS[board]["Architecture"].lower() == info["arch"] and info["endian"] in TARGETS[board]["Endianness"]:
                    target_url = base + href
                    matches = crawl_for_sdks(target_url,info=info, matches=matches)
            #         sub = requests.get(target_url)
            #         subsoup = BeautifulSoup(sub.text, "html.parser")
            #         for s in subsoup.find_all("a"):
            # # print("Target", target_url, sub)
            #             subhref = s.get("href")
            #             subsub = requests.get(target_url+subhref)
            #             print(target_url+subhref)
            #             if "sunxi" in str(subhref):
            #                 print(subsub.text)

            #             if "openwrt-sdk" in subsub.text and toolchain in subsub.text:
                            
            #                 subsubsoup = BeautifulSoup(subsub.text, "html.parser")
            #                 for s in subsubsoup.find_all("a"):
            #                     sdk_href = s.get("href")
            #                     if sdk_href and sdk_href.startswith("openwrt-sdk") and sdk_href.endswith(".tar.xz"):
            #                         matches.append(target_url + sdk_href)
    return matches



def crawl_for_sdks(base_url, info, matches, visited=None):
    """Recursively crawl subdirectories starting from base_url and
    collect SDK/toolchain download links that match the toolchain string."""
    if visited is None:
        visited = set()

    if base_url in visited:
        return
    visited.add(base_url)
    
    try:
        resp = requests.get(base_url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        # print(f"⚠️ Failed to fetch {base_url}: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")

    for link in soup.find_all("a"):
        href = link.get("href")
        if not href or href in ("../", "./"):
            continue

        # Build full URL
        full_url = base_url.rstrip("/") + "/" + href
        
        # If it looks like a tarball and matches toolchain, collect it and toolchain in href
        if str(href).lower().startswith("openwrt-sdk") and info["libc"] in str(href).lower() and info["version"] in str(href).lower():
            if full_url not in matches:
                matches.append(full_url)
                print("Match added", full_url)

        # If it's a subdirectory (heuristic: ends with '/'), recurse
        elif href.endswith("/"):
            crawl_for_sdks(full_url, info, matches, visited)

        if len(matches) >= 4:
            return matches

    return matches


def download_and_extract(url, output_dir="toolchains"):
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Downloading SDK from {url} ...")
    resp = requests.get(url, stream=True)
    resp.raise_for_status()
    tarball = BytesIO(resp.content)

    print("[+] Extracting SDK ...")
    with tarfile.open(fileobj=tarball, mode="r:xz") as tar:
        tar.extractall(path=output_dir)
        sdk_root = tar.getnames()[0].split("/")[0]  # top-level folder
    sdk_path = os.path.join(output_dir, sdk_root)
    print(f"[+] SDK extracted to {sdk_path}/")
    return sdk_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect and download OpenWrt toolchain for a binary")
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("rootfs", help="Path to rootfs of the binary")
    parser.add_argument("--list-only", action="store_true", help="Only list possible SDK URLs without downloading")
    args = parser.parse_args()

    info = analyze_binary(args.binary, args.rootfs)
    print("[*] Analysis:", info)

    libc_candidates = {"uclibc"}
    print(f"[+] Trying libc candidates (in order): {libc_candidates}")

    found_any = False
    for libc in libc_candidates:
        toolchain = suggest_toolchain_prefix(info, libc)
        if not toolchain:
            continue
        print(f"[+] Suggested toolchain prefix: {toolchain}")
        for rel in OPENWRT_RELEASES:
            urls = find_toolchain_urls(toolchain, rel)
            if urls:
                found_any = True
                if args.list_only:
                    print(f"[+] Found {len(urls)} SDK(s) in {rel}:")
                    for u in urls:
                        print("   ", u)
                else:
                    url = urls[0]  # pick first match
                    print(f"[+] Found SDK in release {rel}: {url}")
                    sdk_path = download_and_extract(url)
                    print(f"[i] Add to PATH: export PATH={sdk_path}/staging_dir/toolchain-*/bin:$PATH")
                    exit(0)

    if not found_any:
        print("[-] Could not find a matching SDK in tested releases.")