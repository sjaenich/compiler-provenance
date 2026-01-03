import re
import sys
from dataclasses import dataclass
from pathlib import Path
from tree_sitter import Language, Parser
from tree_sitter import Query, QueryCursor
import tree_sitter_c as csitter
import codecs


class StringParser: 
    def __init__(self, path: Path):
        language = Language(csitter.language())
        parser = Parser(language)
        self.strings: list[SourceStringEntry] = []
        self.strings_with_unresolved_macros: list[list[SourceStringEntry]] = []
        self.__code = Path(path).read_bytes()
        self.__tree = parser.parse(self.__code)


    def print_tree(self, node, indent=0):
        start = node.start_point
        end = node.end_point
        snippet = self.__code[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        print("  " * indent + f"{node.type} [{start} → {end}] {snippet!r}")
        for child in node.children:
            self.print_tree(child, indent + 1)


    def extract_string_literals(self):
        """Yield (text, start_line) for all string literals, grouped for concatenation."""
        STRING_LITERAL_QUERY ='(string_literal) @string (concatenated_string) @concat'
        LANGUAGE = Language(csitter.language())
        query = Query(LANGUAGE, STRING_LITERAL_QUERY)
        query_cursor = QueryCursor(query)
        matches = query_cursor.matches(self.__tree.root_node)
        for match in matches:
            if match[0] == 0:
                for capture in match[1]['string']:
                    node = capture
                    text = self.__code[node.start_byte:node.end_byte].decode()
                    line = node.start_point[0] + 1
                    self.strings.append(SourceStringEntry(text,line))
            else:
                for capture in match[1]['concat']:
                    node = capture
                    macro = False
                    concat = []
                    for child in node.children:
                        if child.type == "string_literal":
                            text = self.__code[child.start_byte:child.end_byte].decode()
                            line = child.start_point[0] + 1
                            concat.append(SourceStringEntry(text,line))
                        if child.type == "identifier":
                            text =  self.__code[child.start_byte:child.end_byte].decode()
                            line = child.start_point[0] + 1
                            macro = True
                            concat.append(SourceStringEntry(text,line,macro))
                    if macro:
                        self.strings_with_unresolved_macros.append(concat)

                    text = self.__code[node.start_byte:node.end_byte].decode()
                    line = node.start_point[0] + 1
                    self.strings.append(SourceStringEntry(text, line))
    
    def clean_string_literals(self) -> None:
        for string in self.strings:
            string.content = clean_string(string.content)
        for concat in self.strings_with_unresolved_macros:
            for string in concat:
                string.content = clean_string(string.content)






@dataclass
class SourceStringEntry:
    """Represents a string found in the source code."""
    content: str
    line_number: int
    macro: bool = False
    def __hash__(self):
        return hash((self.content, self.line_number))
    



def clean_string(s: str) -> str:
    """
    Cleans a string so that only visible characters remain.
    - Removes surrounding quotes
    - Converts escape sequences (\n, \t, \\ etc.) to their actual characters
    - Strips invisible control characters if needed
    """
    # Remove all single and double quotes
    s = s.replace('"', '').replace("'", "")
    
    # Decode escape sequences
    
    s = decode_escapes_preserving_unicode(s)
    
    # Optional: remove other non-printable characters
    s = ''.join(c for c in s if c.isprintable() or c in ('\n', '\t', ' '))
        
    return s

def decode_escapes_preserving_unicode(s: str) -> str:
    """
    Decode escape sequences like \n, \t, \\ but
    keep all non-ASCII unicode characters intact.
    """
    def replace(match):
        return bytes(match.group(0), "utf-8").decode("unicode_escape")

    decoded = re.sub(r'\\[abfnrtv"\'\\]', replace, s)
        # Step 2: Remove empty or whitespace-only lines
    lines = decoded.splitlines()
    nonempty_lines = [line for line in lines if line.strip() != ""]

    return "\n".join(nonempty_lines)
