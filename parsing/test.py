import sys
import z3
import re
import json
from z3 import *
import os
from string_parser import StringParser, SourceStringEntry
from reverse_engineering.information.information_extractor import InformationExtractor
from macrostringconnection import SourceFile
from reverse_engineering.features.feature_extractor import FeatureExtractor
from pathlib import Path



def sym(x):
    return x.value() if isinstance(x, Symbol) else x

def parse_options_file(path):
    good = []
    buf = ""
    depth = 0

    with open(path, encoding="utf-8") as f:
        for line in f:
            buf += line
            depth += line.count("(") - line.count(")")

            # We reached a balanced S-expression
            if depth == 0 and buf.strip():
                try:
                    expr = loads(buf)
                except Exception:
            # malformed → discard
                    buf = ""
                    continue

            # structural validation
                if (
                    isinstance(expr, list)
                    and expr
                    and sym(expr[0]) == "option"
                    ):
                    good.append(expr)
                    print(good)
                    buf = ""

    return good
import re
from collections import defaultdict

def parse_macro_file_2(path):
    entries = []
    current = defaultdict(str)
    accumulating_help = False

    # Regex to detect the fields
    name_re = re.compile(r'name:\s*["\']?(.*?)(["\']|$)')
    help_re = re.compile(r'help:\s*["\']?(.*?)(["\']|$)')
    def_re  = re.compile(r'definition:\s*["\']?(.*?)(["\']|$)')

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()
            if not line:
                accumulating_help = False
                continue

            # Check for name (starts a new entry)
            m = name_re.search(line)
            if m:
                if current:  # save previous entry if exists
                    entries.append(dict(current))
                    current.clear()
                current['name'] = m.group(1).strip()
                accumulating_help = False
                continue

            # Check for help
            m = help_re.search(line)
            if m:
                help_text = m.group(1).strip()
                if 'help' in current:
                    current['help'] += '\n' + help_text
                else:
                    current['help'] = help_text
                accumulating_help = True
                continue

            # Check for definition
            m = def_re.search(line)
            if m:
                current['definition'] = m.group(1).strip()
                accumulating_help = False
                continue

            # If we are accumulating help, append this line too
            if accumulating_help:
                current['help'] +=  line.strip()

    # Add last entry
    if current:
        entries.append(dict(current))

    return entries






def parse_macro_file(path):
    """
    Parses a file containing lines with 'name', 'help', 'definition' fields.
    Returns a list of dicts.
    """
    entries = []
    current = defaultdict(str)

    # Regex to detect the fields
    name_re = re.compile(r'name:\s*["\']?(.*?)(["\']|$)')
    help_re = re.compile(r'help:\s*["\']?(.*?)(["\']|$)')
    def_re  = re.compile(r'definition:\s*["\']?(.*?)(["\']|$)')

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Check each field
            m = name_re.search(line)
            if m:
                if current:  # save previous entry if exists
                    entries.append(dict(current))
                    current.clear()
                current['name'] = m.group(1).strip()
                continue

            m = help_re.search(line)
            if m:
                # accumulate multiline help
                if 'help' in current:
                    current['help'] += '\n' + m.group(1).strip()
                else:
                    current['help'] = m.group(1).strip()
                continue

            m = def_re.search(line)
            if m:
                current['definition'] = m.group(1).strip()
                continue

    # Add last entry
    if current:
        entries.append(dict(current))

    return entries


if __name__ == "__main__":   
    
    filepath = sys.argv[1]
    binary_path = sys.argv[2]
    # library = sys.argv[3]
    filepath = Path(filepath)
    binary_path = Path(binary_path)
    # binary_strings = InformationExtractor(binary_path)


    # source = SourceFile(filepath,binary_strings, library)
    
    # solver = source.get_macro_formulas()

    # print(solver.check(), solver.model())
    path = Path("/root/buildroot/buildroot-2025.02.4/output/build/libcurl-7.71.1/enable-options.json")
    
    


    # options = parse_macro_file_2(path)
    # result = dict()
    # for option in options:
    #     try:
    #         if option['definition'] != "":
    #             # print(option["name"], option["help"], option["definition"])
    #             macros = [m.strip() for m in option['definition'].split(';') if m.strip()]
    #                 # Find enable and disable flags
    #             enable_match = re.search(r'--enable-[\w-]+', option["help"])
    #             disable_match = re.search(r'--disable-[\w-]+', option["help"])

    #             # Map enable flag to macros that *disable* the feature (i.e., macros with DISABLE_)
    #             if enable_match:
    #                 result[enable_match.group()] = [m for m in macros if 'ENABLE' in m.upper()]

    #             # Map disable flag to the same macros (since disabling sets these macros)
    #             if disable_match:
    #                 result[disable_match.group()] = [m for m in macros if 'DISABLE' in m.upper()]
    #     except KeyError:
    #         print("Key does not exist")

    # print(result)
    features = FeatureExtractor()
    features.extract(filepath, binary_path)
    print(features.feature_map)