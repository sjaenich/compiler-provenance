#!/usr/bin/env python3
"""
extract_string_regions.py

Extract "string regions" from a C source file using Pygments.
A region starts with a string literal and continues through
string literals, identifier tokens (macros), and whitespace-only text.
Region ends when any other (non-whitespace) token appears.

Usage:
    python extract_string_regions.py lib/ftp.c
    python extract_string_regions.py lib/ftp.c --join
    python extract_string_regions.py lib/ftp.c --debug
"""
import argparse
from pygments import lex
from pygments.lexers import CLexer
from pygments.token import Token


PUNCT_TOKENS = {
    Token.Punctuation,     # ',', ';', '(', ')', '{', '}', etc.
}
def extract_string_regions(code, debug=False):
    """
    Returns a list of regions, each region is a list of token texts.
    """
    regions = []
    current = []
    in_region = False

    for tok_type, tok_val in lex(code, CLexer()):
        if debug:
            print(f"TOKEN: {tok_type} -> {repr(tok_val)}")

        # Start a region only when we see a string literal
        if tok_type in PUNCT_TOKENS:
            if not in_region:
                in_region = True
                current = []
                continue

        # If already in a region, allow:
        # - more string literals
        # - any Token.Name.* (macros, identifiers)
        # - whitespace-only Token.Text
        if in_region:
            if tok_type in Token.Name:
                current.append(tok_val)
                continue

            if tok_type in Token.Literal.String:
                current.append(tok_val)
                continue

            if tok_type is Token.Text.Whitespace:
                # preserve whitespace optionally (helps with readability)
                if len(current) > 0:
                    current.append(tok_val)
                continue
            print("Region ended by", current, tok_val, tok_type)
            # anything else terminates the region
            if len(current)>1:
                regions.append(current)
            current = []
            in_region = False
            # Do NOT consume this token as part of a new region (it may be punctuation etc.)
            continue

        # Outside region: ignore everything until a string literal starts
        continue
        
    # trailing region
    if in_region and current:
        print("CURRENT", current)
        if len(current) > 1:
            regions.append(current)
    return regions

def reconstruct_region(parts, keep_quotes=True, normalize_ws=True):
    """
    Join region parts into a single string.
    keep_quotes: keep the literal quotes from the original tokens
    normalize_ws: collapse internal whitespace to a single space
    """
    if normalize_ws:
        # replace any pure-whitespace tokens with a single space
        cleaned = []
        for p in parts:
            if p.isspace():
                cleaned.append(" ")
            else:
                cleaned.append(p)
        return "".join(cleaned)
    else:
        return "".join(parts)

def main():
    p = argparse.ArgumentParser(description="Extract C string regions (strings + macros) using Pygments.")
    p.add_argument("file", help="C source file (e.g. lib/ftp.c)")
    p.add_argument("--debug", action="store_true", help="Print every token (type + value) for debugging")
    p.add_argument("--join", action="store_true", help="Print regions reconstructed/joined")
    args = p.parse_args()

    src = open(args.file, "r", encoding="utf-8").read()
    regions = extract_string_regions(src, debug=args.debug)

    if not regions:
        print("No regions found.")
        return

    for i, r in enumerate(regions):
        #print(f"--- Region {i} (parts: {len(r)}) ---")
            # show printable repr to see whitespace clearly
        if args.join:
            print("  -> Reconstructed:", repr(reconstruct_region(r)))
        print()

if __name__ == "__main__":
    main()

