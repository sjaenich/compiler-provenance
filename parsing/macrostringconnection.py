from dataclasses import dataclass
from pathlib import Path
from z3 import BoolRef
from z3 import *
from reverse_engineering.information.information_extractor import InformationExtractor
from parsing.string_parser import StringParser, SourceStringEntry
from localizer import TreePath
from localizer import *
from tqdm import tqdm

@dataclass
class MSC:
    presencecondtion: BoolRef
    line: int


class SourceFile:
    def __init__(self, source_file_path :Path, binary_strings: InformationExtractor, library_dir: str):
        self.source_file_path = source_file_path
        self.library_dir = library_dir
        self.binary_strings = binary_strings.strings
        self.source_strings: StringParser

    def get_macro_formulas(self) -> Solver:
        self.source_strings = StringParser(self.source_file_path)
        self.source_strings.extract_string_literals()
        self.source_strings.clean_string_literals()
        print("Getting the strings --> normal and resolved")
        normal_strings = self.source_strings.strings
        for strings in normal_strings:
            print("Normal", strings)
        resolved_strings = self.resolve_strings(self.source_strings.strings_with_unresolved_macros) 
        for s in resolved_strings:
            print("Resolved", s)
        print("Getting the macro string connections --> normal and resolved")
        msc_normal_strings = self.get_macro_string_connection(normal_strings)
        msc_resolved_strings = self.get_macro_string_tp_connection(resolved_strings)

        s = Solver()
        
        for msc in msc_normal_strings:
            if msc in msc_resolved_strings:
                s.add(Or(msc_normal_strings[msc], msc_resolved_strings[msc]))
                print(msc, "or")
            else:
                s.add(msc_normal_strings[msc])
                print(msc)
            if s.check() != sat:
                for c in s.assertions():
                    print(c)
                raise KeyError
        for msc in msc_resolved_strings:
            if False:
                continue
            else:
                s.add(msc_resolved_strings[msc])
            if s.check() != sat:
                for c in s.assertions():
                    print(c)
                raise KeyError
        return s


    def get_macro_string_tp_connection(self, resolved_strings: list[TreePath]) -> dict[int, BoolRef]:
        mscs = dict()
        found = False
        for string_tp in resolved_strings:
            arguments = []
            
            if string_tp.contains_unresolved_macro():
                arguments = string_tp.to_z3()
                for target in self.binary_strings:
                    s = Solver()
                    s.add(Concat(arguments) == target)
                    if s.check() == sat:
                        
                        m = s.model()
                        for d in m.decls():
                            pc = And(string_tp.presence_conditions, d() == m[d])
                        if string_tp.data[0].line_number not in mscs:
                            mscs[string_tp.data[0].line_number] = pc
                        else:
                            mscs[string_tp.data[0].line_number] = Or(mscs[string_tp.data[0].line_number], pc)
                        found = True
                        print(string_tp.data)
                          
            else:
                string = string_tp.to_string() 
                for target in self.binary_strings:
                    if target == string:
                        print(string)
                        if string_tp.data[0].line_number not in mscs:
                            mscs[string_tp.data[0].line_number] = string_tp.presence_conditions
                        else:
                            mscs[string_tp.data[0].line_number] = Or(mscs[string_tp.data[0].line_number], string_tp.presence_conditions)
                        found = True
        
            if not found:
                mscs[string_tp.data[0].line_number] = Not(string_tp.presence_conditions)
        return mscs                
                
                




    def get_macro_string_connection(self, strings: list[SourceStringEntry]) -> dict[int, BoolRef]:

        resolved_strings = []
        entries = SuperC().get_pc_and_macro_values(self.source_file_path, self.library_dir, None, None)
        for string in strings:
            entry = entries[0]
            for e in entries:
                if e.line > string.line_number:
                    break
                entry = e
        # entry = next((e for e in entries if e.line >= string.line_number),None)
            string_tp = TreePath([string], entry.pc)
            resolved_strings.append(string_tp)

        mscs = dict()
        for string in resolved_strings:
            found = False
            print(string)
            for target in self.binary_strings:
                if string.data[0].content == target:
                    if string.data[0].line_number not in mscs:
                        mscs[string.data[0].line_number] = string.presence_conditions
                    else:
                        mscs[string.data[0].line_number] = Or(mscs[string.data[0].line_number], string.presence_conditions)
                    found = True
            if not found:
                mscs[string.data[0].line_number] = Not(string.presence_conditions)

        return mscs




    def resolve_strings(self, unresolved: list[list[SourceStringEntry]]) -> list[TreePath]:
        resolved_strings = []
        for concat in tqdm(unresolved):
            concat_tp = TreePath(concat, True)
            resolved_strings += get_all(concat_tp, [], self.source_file_path, self.library_dir)

        return resolved_strings