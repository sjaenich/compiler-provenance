#!/usr/bin/env python3
import shlex
import argparse
from collections import defaultdict

def parse_cflags(cflags_str):
    tokens = shlex.split(cflags_str)
    parsed = defaultdict(list)

    for token in tokens:
        if token.startswith("-O"):
            parsed["optimization"].append(token)
        elif token.startswith("-g"):
            parsed["debug"].append(token)
        elif token.startswith("-I"):
            parsed["include"].append(token[2:] or "")
        elif token.startswith("-D"):
            parsed["defines"].append(token[2:] or "")
        elif token.startswith("-W"):
            parsed["warnings"].append(token)
        else:
            parsed["other"].append(token)

    return parsed

def reconstruct_cflags(parsed):
    flags = []
    flags.extend(parsed["optimization"])
    flags.extend(parsed["debug"])
    flags.extend([f"-I{inc}" for inc in parsed["include"]])
    flags.extend([f"-D{define}" for define in parsed["defines"]])
    flags.extend(parsed["warnings"])
    flags.extend(parsed["other"])
    return " ".join(flags)

def main():
    parser = argparse.ArgumentParser(description="Parse and modify CFLAGS")
    parser.add_argument("cflags", help="CFLAGS string to parse")
    parser.add_argument("--set-opt", help="Override optimization level (e.g. -O0, -O3)")
    parser.add_argument("--add-define", help="Add a -D define", action="append")
    parser.add_argument("--remove-opt", action="store_true", help="Remove optimization flags")
    parser.add_argument("--remove-debug", action="store_true", help="Remove debug flags like -g")

    args = parser.parse_args()

    parsed = parse_cflags(args.cflags)

    if args.remove_debug:
        parsed["debug"] = []

    if args.remove_opt:
        parsed["optimization"] = []

    if args.set_opt:
        parsed["optimization"] = [args.set_opt]

    if args.add_define:
        parsed["defines"].extend(args.add_define)

    print(reconstruct_cflags(parsed))

if __name__ == "__main__":
    main()

