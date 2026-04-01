import re
from ast import literal_eval
from z3.z3 import *
 
def split_on_top_level_AND(text: str):
    parts = []
    depth = 0
    current = []

    tokens = text.replace("(", " ( ").replace(")", " ) ").split()

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok == "(":
            depth += 1
            current.append(tok)

        elif tok == ")":
            depth -= 1
            current.append(tok)

        elif depth == 0 and tok == "AND":
            # top-level split
            parts.append(" ".join(current).strip())
            current = []
        else:
            current.append(tok)

        i += 1

    if current:
        parts.append(" ".join(current).strip())

    return parts


def parse_AND_connected_smt2(text: str):
    parts = split_on_top_level_AND(text)
    z3_exprs = []

    for p in parts:
        # parse each SMT-LIB block separately
        
        p = re.sub(r'\bdefined\s+([A-Za-z0-9_]+)', r'\1', p)
        p = re.sub(r'\(\s*([A-Za-z0-9_]+)\s*\)', r'\1', p)
        p = re.sub(r'\|\s*([^|]+?)\s*\|', r'|\1|', p)
        try:
            smt = parse_smt2_string(p)
        except:
            continue
        z3_exprs.extend(smt)
    # AND all extracted assertions together
        # for e in z3_exprs:
        #     print(e, type(e))
        #     if isinstance(e,BoolRef):
        #         print("this is it", e)
        # raise KeyError
    return And(*[e for e in z3_exprs if isinstance(e, BoolRef)])


def strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


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