import subprocess
import angr
import os

SOURCE_FILE = "main.c"
REFERENCE_BINARY = "reference_binary"
WORK_DIR = "./bin_compare"

# Dictionary: {name: path_to_compiler}
compilers = {
    "gcc-11": "/usr/bin/gcc-11",
    "gcc-13": "/usr/bin/gcc-13",
    "clang-12": "/usr/bin/clang-12",
    "clang-16": "/usr/bin/clang-16",
}

flags_list = [
    ["-O0"],
    ["-O1"],
    ["-O2"],
    ["-O3"],
    ["-Os"],
    ["-O3", "-march=native"],
    ["-O2", "-fno-inline"],
]

def compile_source(compiler_path, flags, output_binary):
    try:
        # Would be cool if there was an script that downloads the specific compiler that we want to try.
        cmd = [compiler_path, SOURCE_FILE, "-o", output_binary] + flags
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed with {compiler_path} {' '.join(flags)}")
        return False

def compare_binaries(bin1, bin2, function_name):
    try:
        # Needs to be changed to angr 
        proj1 = angr.Project(bin1, auto_load_libs=False)
        proj2 = angr.Project(bin2, auto_load_libs=False)
        proj1.analyses.CFGFast()
        f1_address = proj1.loader.find_symbol(function_name)
        f1 = proj1.kb.functions[f1_address]
        result = proj1.analyses.BinDiff(proj2)
        f2_address = [f[1] for f in bindiff.function_matches.items() if f[0]==f1_address][0]
        func_diff = result._function_diffs[(f1_address,f2_address)]
        difference = len([b for b in f1.blocks]) - len(func_diff.block_matches) 
        similarity = 1 - (difference / len([b for b in f1.blocks]))

        return float(similarity)
    except Exception as e:
        print("Error running angr BinDiff", e)
        return 0.0

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
            output_path = os.path.join(WORK_DIR, output_name)

            if compile_source(compiler_path, flags, output_path):
                score = compare_binaries(output_path, REFERENCE_BINARY)
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

