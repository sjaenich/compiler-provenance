import clang
from clang import cindex
from clang.cindex import TranslationUnitLoadError
cindex.Config.set_library_file("/usr/lib/llvm-18/lib/libclang.so.1")

class CStringExtractor:
    def __init__(self):
        """
        Initialize the extractor.
        """

        import clang.cindex


        self.strings = []
        global CursorKind
        CursorKind = clang.cindex.CursorKind




    def extract_from_file(self, filepath):
        """
        Parse a C file and collect all string literals.
        :param filepath: Path to the C source file
        :return: List of string literals
        """
        index = cindex.Index.create()
        try:
            tu = index.parse(filepath)
        except TranslationUnitLoadError:
            pass
        tokens = list(tu.get_tokens(extent=tu.cursor.extent))
        # self.strings = [token.spelling for token in tokens if token.kind.name == "LITERAL"]
        # self._visit_node(tu.cursor)
        functions = set()
        strings = dict()

        tokens = list(tu.get_tokens(extent=tu.cursor.extent))
        prev_token = None
        paren_open = False
        # print("Länge", len(tokens))
        for token in tokens:
            # Capture string literals
            # print("These are the tokens", token)
            if token.kind.name == "LITERAL" and token.spelling.startswith('"'):
                # strings.append({
                #     "value": token.spelling.strip('"'),
                #     "line": token.location.line,
                #     "column": token.location.column,
                # })
                if ".h" not in token.spelling.strip('"'):
                    strings[token.spelling.strip('"')] = token.location.line
                
            # Very simple heuristic for function names:
            # identifier followed by '(' (but not 'if', 'for', etc.)
            if (prev_token
                and prev_token.kind.name == "IDENTIFIER"
                and token.spelling == "("
                and prev_token.spelling not in ("if", "for", "while", "switch", "return")):
                functions.add((prev_token.spelling, prev_token.location.line))

            prev_token = token

        return {"functions": sorted(list(functions)), "strings": strings}
        
        


    def _visit_node(self, node):
        """
        Recursively visit AST nodes.
        """
        # Check if the node is a string literal
        if node.kind == CursorKind.STRING_LITERAL:
            value = node.spelling.strip('"')
            location = node.location
            self.strings.append({
                "value": value,
                "file": location.file.name if location.file else None,
                "line": location.line,
                "column": location.column
            })
        # Recurse into children
        for child in node.get_children():
            self._visit_node(child)
