import os
import re
import csv
import argparse
from parsing.string_detector import CStringExtractor

# Regex patterns for C preprocessor directives
ifdef_re = re.compile(r'^\s*#\s*ifdef\s+(\w+)')
ifndef_re = re.compile(r'^\s*#\s*ifndef\s+(\w+)')
if_re = re.compile(r'^\s*#\s*if\s+(.+)')
else_re = re.compile(r'^\s*#\s*else')
endif_re = re.compile(r'^\s*#\s*endif')

# File extensions to scan
SOURCE_EXTENSIONS = (".c", ".cpp", ".cc", ".h", ".hpp")

def analyze_file(path, search_strings, inferred_macros):
    """Walks through a file and finds which macros must be active for each search string."""
    conditions_stack = []
    results = {s: [] for s in search_strings}
    disable_macros = []
    enable_macros = []
    rows = []
    

    with open("libcurl_features_clean", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        enable_macros_append = [row["added"] for row in rows if row["added"].strip()]
        enable_macros.extend(enable_macros_append)
        
        disable_macros_append = [row["removed"] for row in rows if row["removed"].strip()]
        disable_macros.extend(disable_macros_append)

    
    if inferred_macros is None:
        inferred_macros = set(disable_macros)
    # Now you can filter, sort, or search
    try:
        
        string_extractor = CStringExtractor()
        string_literals = string_extractor.extract_from_file(path)
        functions = string_literals["functions"]
        strings = string_literals["strings"]
        # print(strings)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            
            for lineno, line in enumerate(f, start=1):
                # Track preprocessor state
                
                if m := ifdef_re.match(line):
                    conditions_stack.append((m.group(1), False))
                elif m := ifndef_re.match(line):
                    conditions_stack.append((m.group(1), False))
                elif if_re.match(line):
                    # Simplify #if expressions (not full C parser)
                    conditions_stack.append((if_re.match(line).group(1).strip(), True))
                elif else_re.match(line):
                    if conditions_stack:
                        macro, val = conditions_stack.pop()
                        if val is not None:
                            conditions_stack.append((macro, not val))
                        else:
                            conditions_stack.append((f"NOT({macro})", None))
                elif endif_re.match(line):
                    if conditions_stack:
                        conditions_stack.pop()
                
                # Check for search strings in the current line
                # for s in search_strings:
                for s in strings:   
                    if s in line:
                        if s in search_strings:
                            if strings[s] == lineno:
                                # print(s, strings[s], line) 
                                active_conditions = [f"{m}={'1' if v else '0' if v is not None else '?'}" for m, v in conditions_stack]
                                for m,v in conditions_stack:
                                    
                                    if m in enable_macros:
                                        inferred_macros.add(m)
                                        print("Enabled", m, s, lineno, path)
                                    elif m in disable_macros:
                                        print("Disabled", m, s, lineno,path)
                                        if not v:    
                                            if m in inferred_macros:
                                                inferred_macros.remove(m)
                                                # print("Disabled", m, s, lineno,path)
                                        # print(inferred_macros)
                                    
                                        # print("no Match", disable_macros)



                                results[s].append({
                                    "file": path,
                                    "line": lineno,
                                    "conditions": active_conditions.copy()
                                })
                
    except (OSError, UnicodeDecodeError):
        pass

    # print("Inferred Macros", inferred_macros)
    # return results
    features = set()
    for m in inferred_macros:
        # print(rows)
        for r in rows:
            if m == r['removed']:
                option = r['option'].replace("enable", "disable")
                option.replace("with", "without")
                # option = r["option"].replace("with", "without")
                # print(option, "This is", m, r["option"])
                features.add(option)
            elif m == r['added']:
                option = r['option']
                features.add(option)
                # print(r['option'], r['removed'], r["added"], "This is" ,m)
    # print(features)
    return inferred_macros

def walk_sources(root, search_strings):
    """Walk through all source files under root."""
    all_results = {s: [] for s in search_strings}
    inferred_macros = None
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if fname.endswith(SOURCE_EXTENSIONS):
                fpath = os.path.join(dirpath, fname)
                inferred_macros = analyze_file(fpath, search_strings, inferred_macros)
                # inferred_macros = inferred_macros & file_results if inferred_macros and file_results else file_results
                # for s in search_strings:
                #     all_results[s].extend(file_results[s])
    # return all_results
    print(inferred_macros)
    return inferred_macros

def load_strings(path, min_len=3):
    s = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            val = line.strip()
            if len(val) >= min_len:
                s.add(val)
    return s


def main():
    parser = argparse.ArgumentParser(
        description="Find which macros must be active for specific strings in source code."
    )
    parser.add_argument("root", help="Root directory to search")
    parser.add_argument("--strings-file", required=True, help="File from `strings` binary output")
    args = parser.parse_args()
    
    strings = load_strings(args.strings_file)
    print(f"[*] Loaded {len(strings)} strings from binary")
    results = walk_sources(args.root, strings)
    return
    for s, matches in results.items():
        print(f"\n=== Results for '{s}' ===")
        if not matches:
            print("No occurrences found.")
            continue
        for m in matches:
            cond = " & ".join(m["conditions"]) if m["conditions"] else "(always active)"
            # if "(always active)" not in cond:
                # print(f"{m['file']}:{m['line']} → {cond}")


if __name__ == "__main__":
    main()