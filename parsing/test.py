from pygments import lex
from pygments.lexers import CLexer
from pygments.token import String, Name
import sys

def extract_string_segments(filename):
    with open(filename, "r", encoding="utf-8") as f:
        code = f.read()

    segments = []
    buffer = []

    for token_type, token_value in lex(code, CLexer()):
        print(token_type, token_value)
        if token_type in String or token_type is Name:
            # We only care about:
            # - string literals (String.*)
            # - bare identifiers (macro names)
            buffer.append(token_value)
        else:
            # If we hit another token type, flush buffer
            if buffer:
                segments.append(" ".join(buffer))
                buffer = []

    # flush at end
    if buffer:
        segments.append(" ".join(buffer))

    return segments

if __name__ == "__main__":
    path = sys.argv[1]
    for seg in extract_string_segments(path):
        print(seg)

