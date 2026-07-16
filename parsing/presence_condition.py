import re
from ast import literal_eval
from z3.z3 import *
 
 
# def split_on_top_level_AND(text: str):
#     parts = []
#     depth = 0
#     current = []

#     tokens = text.replace("(", " ( ").replace(")", " ) ").split()

#     i = 0
#     while i < len(tokens):
#         tok = tokens[i]

#         if tok == "(":
#             depth += 1
#             current.append(tok)

#         elif tok == ")":
#             depth -= 1
#             current.append(tok)

#         elif depth == 0 and tok == "AND":
#             # top-level split
#             parts.append(" ".join(current).strip())
#             current = []
#         else:
#             current.append(tok)

#         i += 1

#     if current:
#         parts.append(" ".join(current).strip())

#     return parts

def split_on_top_level_AND(text: str):
    parts = []
    start = 0
    depth = 0
    in_bar_symbol = False
    i = 0

    while i < len(text):
        ch = text[i]

        if ch == "|":
            in_bar_symbol = not in_bar_symbol
            i += 1
            continue

        if not in_bar_symbol:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif (
                depth == 0
                and text.startswith("AND", i)
                and (i == 0 or text[i - 1].isspace())
                and (i + 3 == len(text) or text[i + 3].isspace())
            ):
                part = text[start:i].strip()
                if part:
                    parts.append(part)

                start = i + 3
                i += 3
                continue

        i += 1

    tail = text[start:].strip()
    if tail:
        parts.append(tail)

    return parts


def parse_AND_connected_smt2(text: str):
    z3_exprs = []

    for part in split_on_top_level_AND(text):
        try:
            smt = parse_smt2_string(part)
        except Exception as e:
            raise ValueError(f"Could not parse SMT-LIB block:\n{part}") from e

        z3_exprs.extend(
            normalize_defined_symbols(e)
            for e in smt
            if isinstance(e, BoolRef)
        )

    if not z3_exprs:
        raise ValueError(f"SMT-LIB produced no Boolean assertions:\n{text}")

    return simplify(And(*z3_exprs))




# def parse_AND_connected_smt2(text: str):
#     parts = split_on_top_level_AND(text)
#     z3_exprs = []

#     for p in parts:
#         # parse each SMT-LIB block separately
        
#         # p = re.sub(r'\bdefined\s+([A-Za-z0-9_]+)', r'\1', p)
#         p = re.sub(r'\(\s*([A-Za-z0-9_]+)\s*\)', r'\1', p)
#         p = re.sub(r'\|\s*([^|]+?)\s*\|', r'|\1|', p)
#         try:
#             smt = parse_smt2_string(p)
#         except Exception as e:
#             print("SMT parse failed:")
#             print(p)
#             print(e)
#             continue
#         z3_exprs.extend(smt)
#     # AND all extracted assertions together
#         # for e in z3_exprs:
#         #     print(e, type(e))
#         #     if isinstance(e,BoolRef):
#         #         print("this is it", e)
#         # raise KeyError
#     bool_exprs = [
#         normalize_defined_symbols(e)
#         for e in z3_exprs
#         if isinstance(e, BoolRef)
#     ]

#     if not bool_exprs:
#         raise ValueError(f"SMT-LIB produced no Boolean assertions:\n{text}")

#     return And(*bool_exprs)
    
    # return And(*[e for e in z3_exprs if isinstance(e, BoolRef)])


def strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def defined_macro_name(name: str):
    m = re.fullmatch(
        r'\(\s*defined\s+([A-Za-z_][A-Za-z0-9_]*)\s*\)',
        name.strip(),
    )
    return m.group(1) if m else None


def normalize_defined_symbols(expr):
    replacements = []

    def visit(e, seen):
        key = e.hash()
        if key in seen:
            return
        seen.add(key)

        if is_const(e) and e.num_args() == 0:
            macro = defined_macro_name(e.decl().name())
            if macro is not None:
                replacements.append((e, Bool(macro)))

        for child in e.children():
            visit(child, seen)

    visit(expr, set())
    return substitute(expr, *replacements) if replacements else expr



class PresenceCondition():
    def __init__(self):
        self.line = -1
        self.file_path = None
        self.pc = None
        self.string_literal = None
        self.macro = dict()
    

    def parse(self, pc_string: str):
        pc_string = pc_string.replace("'Value': '\"'\"'", "'Value': \"'\"")
        pc_string = literal_eval(pc_string)
        self.line = int(pc_string["Line"])
        self.pc = parse_AND_connected_smt2(pc_string["PC"])
        # self.string_literal = []
        self.macro = strip_quotes(pc_string["Value"])