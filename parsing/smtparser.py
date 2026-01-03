from z3 import *


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
        smt = parse_smt2_string(p)
        z3_exprs.extend(smt)

    # AND all extracted assertions together
    return And(*[e for e in z3_exprs if isinstance(e, BoolRef)])


# ------------------------------
# Example usage
# ------------------------------

text = """
(declare-fun |(defined USE_GREETING)| () Bool)
(assert (or (and |(defined USE_GREETING)|)))
 AND
(declare-fun |(defined MACRO)| () Bool)
(assert (or (and (not |(defined MACRO)|))))
"""

expr = parse_AND_connected_smt2(text)
print(expr)
