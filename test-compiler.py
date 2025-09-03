import subprocess
import angr
import os
from configuration import VulnerabilityRecord, load_vulnerability_file
import sys
import logging
from pathlib import Path
from typing import Optional



test_logger = logging.getLogger("test"); 
test_logger.setLevel(logging.INFO); 
test_logger.addHandler(logging.FileHandler("test.log"))
    


SOURCE_FILE = "main.c"
REFERENCE_BINARY = "/libpng14.so.14.3.0"
WORK_DIR = "./bin_compare"

affected_functions = {
    "CVE-2011-1935": "pcap_activate_linux",
    "CVE-2024-8006": "pcap_findalldevs",
    "CVE-2019-15165": "pcap_ng_check_header",
    "CVE-2019-15161": "daemon_msg_findallif_req",
    "CVE-2016-9841": "inflate_fast",
    "CVE-2016-9840": "inflate_table",
    "CVE-2016-9842": "inflateMark",
    "CVE-2023-45853": "zipOpenNewFileInZip4_64",
    "CVE-2016-9843": "crc32_z",
    "CVE-2022-37434": "inflate",
    "CVE-2018-25032": "deflateInit2_",
    "CVE-2016-10087": "png_free_data",
    "CVE-2017-12652": "png_read_chunk_header"
}


# Dictionary: {name: path_to_compiler}
compilers = {
    "openwrt-uclibc": "/root/openwrt/staging_dir/toolchain-arm_cortex-a8+vfpv3_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/bin/arm-openwrt-linux-gcc",
    # "gcc-11": "/usr/bin/arm-linux-gnueabi-gcc-11",
    # "gcc-13": "/usr/bin/arm-linux-gnueabi-gcc-13",
    # "arm-none-gcc": "/usr/bin/arm-none-eabi-gcc",
    # "uclibc-gcc": "/root/buildroot-uclibc/output/host/bin/arm-buildroot-linux-uclibcgnueabi-gcc.real",
    # "gcc-14": "/usr/bin/arm-linux-gnueabi-gcc-14",
    # "clang-15": "/usr/bin/clang-15",
    # "clang-16": "/usr/bin/clang-16",
    # "clang-17": "/usr/bin/clang-17",
    # "clang-18": "/usr/bin/clang-18",
}

flags_list = [
    ["-O0"],
    ["-O1"],
    ["-O2"],
    ["-O3"],
    ["-Os"],
    ["-Os -flto"],
    # ["-Os -fno-unroll-loops"],
    ["-Os -fno-stack-protector -D_LARGEFILE_SOURCE"],
    # ["-Os -D_LARGEFILE_SOURCE  --target=arm-linux-gnueabi"],
    # ["-Os -finline-functions  --target=arm-linux-gnueabi"],
    # ["-Os -finline-functions"],
    # ["-Os -finline-limit"],
    ["-Os -fno-stack-protector"],
    # ["-O2 -flto"],
]



def is_elf(file_path: Path) -> bool:
    """Check if a file is an ELF binary by reading its magic bytes."""
    try:
        with file_path.open("rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception:
        return False

def find_longest_elf_so_path(package_name: str,
                            #  buildroot_output: Path = Path("/root/buildroot/buildroot-2025.02.4/output/build")
                             buildroot_output: Path = Path("/root/buildroot-uclibc/output/build")
                            ) -> Optional[Path]:
    """
    Finds the ELF .so file with the longest filename for the given package
    inside the Buildroot build output directory.

    Args:
        package_name: The name of the package (e.g., "libpng").
        buildroot_output: Path to Buildroot's build output directory.

    Returns:
        Path to the ELF .so file with the longest filename, or None if not found.
    """
    # Find all build folders starting with package_name-
    matches = list(buildroot_output.glob(f"{package_name}-*"))
    if not matches:
        return None

    # Pick the most recently modified directory (latest build)
    build_dir = max(matches, key=lambda p: p.stat().st_mtime)

    # Search recursively for all .so files
    so_files = list(build_dir.rglob("*.so*"))
    if not so_files:
        return None

    # Filter only ELF files
    elf_so_files = [f for f in so_files if is_elf(f)]
    if not elf_so_files:
        return None

    # Find the ELF .so file with the longest filename
    longest_elf_so = max(elf_so_files, key=lambda p: len(p.name))
    return longest_elf_so



def compile_source(compiler_path, flags, package_name, version):
    try:
        # Would be cool if there was an script that downloads the specific compiler that we want to try.
        # package_name = "libpng"
        # version = "1.4.3"
        cmd = f"make {package_name}-dirclean"
        # subprocess.run(cmd,cwd='/root/buildroot/buildroot-2025.02.4', shell=True, check=True)
        subprocess.run(cmd,cwd='/root/buildroot-uclibc', shell=True, check=True)
        

        env = os.environ.copy()

        env["MY_REAL_COMPILER"]=f"{compiler_path}"
        env["MY_EXTRA_FLAGS"]=flags[0]

        cmd =  f"uv run package_builder.py {package_name} {flags} {version} {compiler_path}"
        # subprocess.run(cmd,cwd='/root/buildroot/buildroot-2025.02.4/', shell=True, check=True,stdout=subprocess.PIPE ,env=env)
        subprocess.run(cmd,cwd='/root/buildroot-uclibc', shell=True, check=True, stdout=subprocess.PIPE ,env=env)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed with {compiler_path} {' '.join(flags)}", e)
        return False

def compare_binaries(bin1, bin2, function_name):
    try:
        print("Binaries", bin2, bin1)
        proj1 = angr.Project(bin2, auto_load_libs=False)
        proj2 = angr.Project(bin1, auto_load_libs=False)
        proj1.analyses.CFGFast()
        f1_address = proj1.loader.find_symbol(function_name).rebased_addr
        print("First Address", f1_address)
        f1 = proj1.kb.functions[f1_address]
        result = proj1.analyses.BinDiff(proj2)
    #   f2_address = [f[1] for f in result.function_matches if f[0]==f1_address][0]
        f2_address = proj2.loader.find_symbol(function_name).rebased_addr
        print("Second Address", f2_address)
        for match in result.function_matches:
            f1_address = match[0]
            symb = proj1.loader.find_symbol(f1_address)
            print("Symbol", symb)
            if symb is not None:
                f2_address = match[1]
                symb2 = proj2.loader.find_symbol(symb.name)
                if symb2 is not None:
                    f2_address = symb2.rebased_addr
                func_diff = result.get_function_diff(f1_address,f2_address)
                difference = len(func_diff.block_matches) 
                
                similarity = difference / (len(func_diff.attributes_a) + len(func_diff.unmatched_blocks[0]) + len(func_diff.unmatched_blocks[1]))
                test_logger.info(f"Function: {symb} {symb2} {similarity}")
        
    
        # func_diff = result.get_function_diff(f1_address,f2_address)
        # difference = len(func_diff.attributes_a) - len(func_diff.block_matches) 
        # difference = len(func_diff.block_matches)
        # print("Identical blocks", len(func_diff.identical_blocks))        
        # similarity = 1 - (difference / len(func_diff.attributes_a))
        # similarity = difference / (len(func_diff.attributes_a) + len(func_diff.unmatched_blocks[0]) + len(func_diff.unmatched_blocks[1]))
        # test_logger.info(f"Function: {symb} {symb2} {similarity}")
        # test_logger.info(f"Similarity: {similarity} Identical blocks: {len(func_diff.identical_blocks)}")
        return float(similarity)
    except Exception as e:
       print("Error running angr BinDiff", e)
       return 0.0

def get_low_hanging_fruit(bin):
    cmd = ["strings", bin, "| grep stack_chk"]
    subprocess.run(cmd, check=True)
    

def test_compilers(reference_binary, library, version, function_name):
    best_score = 0.0
    best_config = None
    for compiler_name, compiler_path in compilers.items():
        if not os.path.exists(compiler_path):
            print(f"Skipping {compiler_name}: not found at {compiler_path}")
            continue

        for flags in flags_list:
            output_path = find_longest_elf_so_path(library)
            output_path = str(output_path)
            if compile_source(compiler_path, flags, library, version):
                test_logger.info(f"Compiler infos: {compiler_path} {flags}")
                score = compare_binaries(output_path, reference_binary, function_name)
                print(f"{compiler_name} {' '.join(flags)} => Similarity: {score:.4f}")

                if score > best_score:
                    best_score = score
                    best_config = (compiler_name, flags)
    return best_config, best_score


def main():
    # Configure logging
    logging.basicConfig(
        filename="/root/compiler_provenance.log",         # Log file name
        filemode="a",                  # Append mode ("w" to overwrite)
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,        # Minimum level to log,
        force=True
    )
    log = logging.getLogger()
    log.info("Test log entry")
    os.makedirs(WORK_DIR, exist_ok=True)
    covered_paths = list()

    
    library = sys.argv[1]
    results = load_vulnerability_file("karonte-"+library+".json")
    
    for r in results:
        print("Version", r.version)
        if r.cve_number in affected_functions:
            function_name = affected_functions[r.cve_number]
        else:
            continue
        for p in r.paths:
            if "tcpdump" in p:
                continue
            if p in covered_paths:
                continue
            else:
                covered_paths.append(p)
                best_config, best_score = test_compilers(p, library, r.version,function_name)
                if best_config:
                    print("\n🎯 Best Match Found:")
                    print(f"Compiler: {best_config[0]}")
                    test_logger.info(f"Compiler: {best_config[0]}")
                    print(f"Flags: {' '.join(best_config[1])}")
                    test_logger.info(f"Flags: {' '.join(best_config[1])}")
                    print(f"Similarity score: {best_score:.4f}")
                    test_logger.info(f"Similarity score: {best_score:.4f}")
                    test_logger.info(f"Version {r.version}, Path {p}")
                else:
                    print("No successful compilation or similarity comparison.")
                    test_logger.error(f"No successful compilation or similarity comparison.{p}")

if __name__ == "__main__":
    main()