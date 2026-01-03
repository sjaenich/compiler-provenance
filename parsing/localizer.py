import sys
from collections import defaultdict
import z3
from z3 import *
from z3 import And
import os
from string_parser import StringParser, SourceStringEntry
from reverse_engineering.information.information_extractor import InformationExtractor
from superc import SuperC
from presence_condition import PresenceCondition
from dataclasses import dataclass





@dataclass    
class TreePath:
    data: list[SourceStringEntry]
    presence_conditions: BoolRef


    def __add__(self, other: "TreePath") -> "TreePath":
        if not isinstance(other, TreePath):
            return NotImplemented
        return TreePath(self.data + other.data, And(self.presence_conditions,other.presence_conditions))
    def head(self) -> "TreePath":
        return TreePath([self.data[0]],self.presence_conditions)

    def tail(self) -> "TreePath":
        return TreePath(self.data[1:], self.presence_conditions)
    
    def to_string(self) -> str:
        string =""
        for sse in self.data:
            string += sse.content
        return string

    def to_z3(self) -> BoolRef:
        arguments = []
        for sse in self.data:
            if sse.macro:
                x = String(sse.content)
                arguments.append(x)
            else:
                arguments.append(sse.content)
        return arguments

    def contains_unresolved_macro(self) -> bool:
        for sse in self.data:
            if sse.macro:
                return True
        return False
    
    def __len__(self) -> int:
        return len(self.data)

def get_variants(entry: TreePath, filepath, library) -> list[TreePath]:
    variants = []
    if len(entry.data) >1:
        return ValueError("TreePath should only have length 1")
    if entry.data[0].macro:
        presence_conditions = SuperC().get_pc_and_macro_values(filepath, library, entry.data[0].line_number, entry.data[0].content)
        for pc in presence_conditions:
            if pc.macro == "undefined":
                entry.presence_conditions = And(entry.presence_conditions, pc.pc)
                variants.append(entry)
            else:
                new_sse = SourceStringEntry(pc.macro, pc.line, False)
                new_tp = TreePath([new_sse], pc.pc)
                variants.append(new_tp)
    else:
        variants.append(entry)
    return variants


def get_all(input: TreePath, outputs: list[TreePath], filepath, library) -> list[TreePath]:
    if len(input) == 0:
        return outputs
    h = input.head()
    
    variants = get_variants(h, filepath, library)
    tail = input.tail()
    old_outputs = outputs.copy()
    outputs.clear()
    for variant in variants:
        # print("Variant", variant)    
        for output in old_outputs:
            # print("Output", output)
            outputs.append(output + variant)
        if outputs == []:
            outputs.append(variant)
    
    return get_all(tail, outputs, filepath, library)



def resolve_macros(unresolved: list[TreePath]) -> list[TreePath]:
    resolved_strings = []
    for concat in unresolved:
        concat_tp = TreePath(concat, True)
        resolved_strings += get_all(concat_tp, [],filepath, library)
    return resolved_strings

def get_pc_of_normal_strings(strings: list[TreePath]) -> list[TreePath]:
    resolved_strings = []
    entries = SuperC().get_pc_and_macro_values(filepath, library, None, None)
    for string in sp.strings:
        entry = entries[0]
        for e in entries:
            if e.line > string.line_number:
                break
            entry = e
        # entry = next((e for e in entries if e.line >= string.line_number),None)
        string_tp = TreePath([string], entry.pc)
        resolved_strings.append(string_tp)
    return resolved_strings


if __name__ == "__main__":
    
    filepath = sys.argv[1]
    binary_path = sys.argv[2]
    library = sys.argv[3]
    sp = StringParser(filepath)
    sp.extract_string_literals()
    sp.clean_string_literals()
    # print(sp.strings_with_unresolved_macros)
    binary_strings = InformationExtractor(file_path=binary_path)
    resolved_strings = []
    
    for concat in sp.strings_with_unresolved_macros:
        concat_tp = TreePath(concat, True)
        resolved_strings += get_all(concat_tp, [],filepath, library)

    strings = []
    entries = SuperC().get_pc_and_macro_values(filepath, library, None, None)
    for string in sp.strings:
        entry = entries[0]
        for e in entries:
            if e.line > string.line_number:
                break
            entry = e
        # entry = next((e for e in entries if e.line >= string.line_number),None)
        string_tp = TreePath([string], entry.pc)
        resolved_strings.append(string_tp)

    found_strings = defaultdict(list)
    final_solver = Solver()
    found = False
    print("Superc is done ")
    for string_tp in resolved_strings:
        arguments = []
        
        
        if string_tp.contains_unresolved_macro():
            arguments = string_tp.to_z3()
            for target in binary_strings.strings:
                s = Solver()
                s.add(Concat(arguments) == target)
                if s.check() == sat:
                    print("This is the model", s.model(), string_tp.presence_conditions)
                    found_strings[target].append((string_tp.presence_conditions, s.model()))
                    break
        else:
            string = string_tp.to_string() 
            for target in binary_strings.strings:
                if target == string:
                    print("This is a ", string, string_tp.presence_conditions)
                    found_strings[target].append((string_tp.presence_conditions, True))
                    found = True
                
    if not found:
        for string_tp in resolved_strings:
            if not string_tp.contains_unresolved_macro():
                final_solver.add(Not(string_tp.presence_conditions))
                print(final_solver)
                final_solver.add(string_tp.presence_conditions)
                final_solver.check()

    print(final_solver)