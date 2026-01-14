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
from reverse_engineering.features.feature_extractor import Feature, FeatureExtractor
from macrostringconnection import *


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
        
            if pc.macro == "undefined" or pc.macro == "None":
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
    for string in strings:
        entry = entries[0]
        for e in entries:
            if e.line > string.line_number:
                break
            entry = e
        # entry = next((e for e in entries if e.line >= string.line_number),None)
        string_tp = TreePath([string], entry.pc)
        resolved_strings.append(string_tp)
    return resolved_strings




def feature_states_from_solver(solver, features: dict[str, 'BoolRef']):
    """
    Given a solver and feature BoolRefs, return enabled/disabled/unknown features.
    """
    if solver.check() != sat:
        raise ValueError("Solver is UNSAT")

    model = solver.model()

    enabled = set()
    disabled = set()
    unknown = set()

    for name, feature in features.items():
        
        if type(feature) is bool:
            continue
        val = model.eval(feature)

        if is_true(val):
            enabled.add(name)
        elif is_false(val):
            disabled.add(name)
        else:
            unknown.add(name)

    return enabled, disabled, unknown
    




if __name__ == "__main__":
    
    filepatha = sys.argv[1]
    binary_path = Path(sys.argv[2])
    library = Path(sys.argv[3])
    conifgure_path = Path(sys.argv[4])
    m4_constraints_path = Path(sys.argv[5])
    binary_strings = InformationExtractor(binary_path)
    solver = Solver()
    # for filepath in tqdm(library.rglob("*.c")):
    #     print(filepath)
    #     sf = SourceFile(filepath, binary_strings, library)
    #     solver_a = sf.get_macro_formulas()
    #     solver.add(solver_a.assertions())
    #     if solver.check() == "unsat":
    #         print("ERROR", filepath)
    #         raise KeyError


    sf = SourceFile(filepatha, binary_strings, library)
    solver = sf.get_macro_formulas()
    raise KeyError
    if solver.check() == sat:
        print("HELL YEAH")
        # print(solver.model())
    # for c in solver.assertions():
    #     print(c)
    features = FeatureExtractor()


    features.extract(conifgure_path, m4_constraints_path)
    bools = features.macros_as_z3()
    
    enabled, disabled, unknown = feature_states_from_solver(solver, bools)

    print("Enabled features:")
    for f in sorted(enabled):
        print("  +", f)
    print("\nDisabled features:")
    for f in sorted(disabled):
        print("  -", f)
    print("\nUnknown Features")
    for f in sorted(unknown):
        print( " **", f)