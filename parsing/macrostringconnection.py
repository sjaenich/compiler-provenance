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
        self.str_to_pc: dict[str, BoolRef] = dict()
        self.macro_to_presence_condition: dict[str, BoolRef] = dict()
        self.macro_string_connection: dict[int, BoolRef] = dict()
        self.covered_lines: set[int] = set()


    def get_macro_formulas(self) -> Solver:
        s = Solver()
        self.source_strings = StringParser(self.source_file_path)
        self.source_strings.extract_string_literals()
        self.source_strings.clean_string_literals()
        print("Getting the strings --> normal and resolved")
        normal_strings = self.source_strings.strings
        resolved_strings = self.resolve_strings(self.source_strings.strings_with_unresolved_macros) 
        print("Getting the macro string connections --> normal and resolved")
        
        msc_normal_strings = self.get_macro_string_connection(normal_strings)
        if msc_normal_strings is None:
            return s
        print("Getting tp connections")
        msc_resolved_strings = self.get_macro_string_tp_connection(resolved_strings)
        if msc_resolved_strings is None:
            return s
      
       
        
        for msc in msc_normal_strings:
            # print(msc)
            # if msc in msc_resolved_strings:
            #     s.add(Or(msc_normal_strings[msc], msc_resolved_strings[msc]))
            # else:
            s.add(msc)
            if s.check() != sat:
                raise KeyError
        for msc in msc_resolved_strings:
            if msc in msc_normal_strings:
                continue
            else:
                s.add(msc)
            if s.check() != sat:
                # for c in s.assertions():
                    # print(c)
                raise KeyError
        return s



    def get_macro_string_tp_connection(self, resolved_strings: list[TreePath]) -> set[BoolRef]:
        macros = set()
        strings_to_presence_condition = dict()
        found = False
        for string_tp in resolved_strings:
            arguments = []
            line = string_tp.data[0].line_number
            if string_tp.contains_unresolved_macro():
                arguments = string_tp.to_z3()
                for target in self.binary_strings:
                    s = Solver()
                    s.add(Concat(arguments) == target)
                    if s.check() == sat:
                        m = s.model()
                        pc = string_tp.presence_conditions
                        for d in m.decls():
                            if d in self.macro_to_presence_condition:
                                pc = And(pc, d() == m[d])
                                pc = Or(pc, self.macro_to_presence_condition[d])
                                self.macro_to_presence_condition[d] = pc
                            else:
                                pc = And(pc, d() == m[d])
                                self.macro_to_presence_condition[d] = pc
                        if target not in strings_to_presence_condition:
                            strings_to_presence_condition[target] = pc                            
                        else:
                            strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], pc)
            else:
                string = string_tp.to_string() 
                for target in self.binary_strings:
                    if target == string:
                        if target not in self.strings_to_presence_condition: 
                            strings_to_presence_condition[target] = string_tp.presence_conditions
                        else:
                            strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], string_tp.presence_conditions)                            
                        found = True
        
            if not found:
                self.macro_string_connection[string_tp.data[0].line_number] = Not(string_tp.presence_conditions)

        for s in strings_to_presence_condition:
            macros.add(strings_to_presence_condition[s])

        self.str_to_pc.update(strings_to_presence_condition)
    
        return macros                
                
                




    def get_macro_string_connection(self, strings: list[SourceStringEntry]) -> dict[int, BoolRef]:
        macros = set()
        resolved_strings = []
        strings_to_presence_condition = dict()
        entries = SuperC().get_pc_and_macro_values(self.source_file_path, self.library_dir, None, None)
        if entries == []:
            print("No Presence Conditions for",  self.source_file_path)
            return None
        for string in strings:
            entry = entries[0]
            for e in entries:
                if e.line > string.line_number:
                    break
                entry = e
        # entry = next((e for e in entries if e.line >= string.line_number),None)
            string_tp = TreePath([string], entry.pc)
            resolved_strings.append(string_tp)
        
            
        for string in resolved_strings:
            found = False
            for target in self.binary_strings:
                if string.data[0].content == target:
                    if target not in strings_to_presence_condition:
                        strings_to_presence_condition[target] = string.presence_conditions
                    else:
                        strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], string.presence_conditions)        
                    found = True
            if not found:
                self.macro_string_connection[string.data[0].line_number] = Not(string.presence_conditions)

        for s in strings_to_presence_condition:
            macros.add(strings_to_presence_condition[s])
        
        self.str_to_pc.update(strings_to_presence_condition)
        

        
        return macros


    def resolve_strings(self, unresolved: list[list[SourceStringEntry]]) -> list[TreePath]:
        resolved_strings = []
        for concat in tqdm(unresolved):
            concat_tp = TreePath(concat, True)
            resolved_strings += get_all(concat_tp, [], self.source_file_path, self.library_dir)

        return resolved_strings