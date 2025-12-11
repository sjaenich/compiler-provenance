import sys
import z3
from z3 import *
import os
from string_parser import StringParser, SourceStringEntry
from reverse_engineering.information.information_extractor import InformationExtractor
from superc import SuperC
from presence_condition import PresenceCondition


if __name__ == "__main__":   
    
    filepath = sys.argv[1]
    binary_path = sys.argv[2]
    library = sys.argv[3]
    sp = StringParser(filepath)
    sp.extract_string_literals()
    sp.clean_string_literals()
    binary_strings = InformationExtractor(file_path=binary_path)

        
    for concat in sp.strings_with_unresolved_macros:
        arguments = []
        for string in concat:
            if string.macro:
                presence_conditions = SuperC().get_pc_and_macro_values(filepath,library,string.line_number,string.macro) 
                if len(presence_conditions) > 0:
                    string 
                arguments.append(x)
            else:
                arguments.append(string.content)

        for target in binary_strings.strings:
            s = Solver()
            s.add(Concat(arguments) == target)
            if s.check() == sat:
                print("This is  the model", s.model())
                break

def create_new_strings_from_concat(concat : list[SourceStringEntry], presence_conditions: list[PresenceCondition]) -> list[str]:
    new_strings = []
    arguments = []
    for pc in  presence_conditions:
        arguments.append

@dataclass    
class TreePath:
    data: list[SourceStringEntry]

def get_variants(e: SourceStringEntry) -> list[SourceStringEntry]:
    pass

def get_all(input: list[SourceStringEntry], outputs: list[TreePath]) -> list[TreePath]:
    if len(input) == 0:
        return outputs
    head = input[0]
    variants = get_variants(head)
    tail = concat[1:]
    old_outputs = outputs.copy()
    outputs.clear()
    for variant in variants:   
        for output in old_outputs:
            outputs.append(TreePath(output.data + [variant]))
    return get_all(tail, outputs)