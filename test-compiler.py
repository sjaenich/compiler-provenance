import subprocess
import angr
import os


SOURCE_FILE = "main.c"
REFERENCE_BINARY = "/libpng14.so.14.3.0"
WORK_DIR = "./bin_compare"

# Dictionary: {name: path_to_compiler}
compilers = {
    "gcc-11": "/usr/bin/arm-linux-gnueabi-gcc-11",
    "gcc-13": "/usr/bin/arm-linux-gnueabi-gcc-13",
    "gcc-14": "/usr/bin/arm-linux-gnueabi-gcc-14",
    "clang-12": "/usr/bin/clang-12",
    "clang-16": "/usr/bin/clang-16",
}

flags_list = [
    # ["-O0"],
    # ["-O1"],
    # ["-O2"],
    # ["-O3"],
    ["-Os -fno-stack-protector"],
    ["-Os"]
    # ["-O3 -fno-stack-protector"],
    # ["O2 -fno-inline"],
]

def compile_source(compiler_path, flags, output_binary):
    try:
        # Would be cool if there was an script that downloads the specific compiler that we want to try.
        package_name = "libpng"
        version = "1.4.3"
        cmd = f"make libpng-dirclean"
        subprocess.run(cmd,cwd='/root/buildroot/buildroot-2025.02.4', shell=True, check=True)
        

        env = os.environ.copy()

        env["MY_REAL_COMPILER"]=f"{compiler_path}"
        env["MY_EXTRA_FLAGS"]=flags[0]

        cmd =  f"uv run package_builder.py {package_name} {flags} {version} {compiler_path}"
        subprocess.run(cmd,cwd='/root/buildroot/buildroot-2025.02.4/', shell=True, check=True,stdout=subprocess.PIPE ,env=env)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed with {compiler_path} {' '.join(flags)}", e)
        return False

def compare_binaries(bin1, bin2, function_name):
 #   try:
        # Needs to be changed to angr 
    function_name = "png_free_data"
    proj1 = angr.Project(bin1, auto_load_libs=False)
    proj2 = angr.Project(bin2, auto_load_libs=False)
    proj1.analyses.CFGFast()
    f1_address = proj1.loader.find_symbol(function_name).rebased_addr
    f1 = proj1.kb.functions[f1_address]
    result = proj1.analyses.BinDiff(proj2)
 #   f2_address = [f[1] for f in result.function_matches if f[0]==f1_address][0]
    f2_address = proj2.loader.find_symbol(function_name).rebased_addr
    func_diff = result.get_function_diff(f1_address,f2_address)
    difference = len(func_diff.attributes_a) - len(func_diff.block_matches) 
    similarity = 1 - (difference / len([b for b in f1.blocks]))
    return float(similarity)
    #except Exception as e:
     #   print("Error running angr BinDiff", e)
      #  return 0.0

def get_low_hanging_fruit(bin):
    cmd = ["strings", bin, "| grep stack_chk"]
    subprocess.run(cmd, check=True)
    

def main():
    os.makedirs(WORK_DIR, exist_ok=True)
    best_score = 0.0
    best_config = None

    for compiler_name, compiler_path in compilers.items():
        if not os.path.exists(compiler_path):
            print(f"Skipping {compiler_name}: not found at {compiler_path}")
            continue

        for flags in flags_list:
            output_name = f"{compiler_name}_{'_'.join(f.replace('-', '') for f in flags)}"
            output_path = "/root/buildroot/buildroot-2025.02.4/output/build/libpng-1.4.3/.libs/libpng14.so.14.3.0"

            if compile_source(compiler_path, flags, output_path):
                score = compare_binaries(output_path, REFERENCE_BINARY, None)
                print(f"{compiler_name} {' '.join(flags)} => Similarity: {score:.4f}")

                if score > best_score:
                    best_score = score
                    best_config = (compiler_name, flags)

    if best_config:
        print("\n🎯 Best Match Found:")
        print(f"Compiler: {best_config[0]}")
        print(f"Flags: {' '.join(best_config[1])}")
        print(f"Similarity score: {best_score:.4f}")
    else:
        print("No successful compilation or similarity comparison.")

if __name__ == "__main__":
    main()

