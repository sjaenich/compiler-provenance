from dataclasses import dataclass
from pathlib import Path
from z3 import BoolRef
from z3 import *
from reverse_engineering.information.information_extractor import InformationExtractor
from parsing.string_parser import StringParser, SourceStringEntry
from localizer import TreePath
from localizer import *


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
        resolved_strings = self.resolve_strings(self.source_strings.strings_with_unresolved_macros)
        print("Getting the macro string connections --> normal and resolved")
        msc_normal_strings = self.get_macro_string_connection(normal_strings)
        msc_resolved_strings = self.get_macro_string_tp_connection(resolved_strings)

        s = Solver()
        for msc in msc_normal_strings:
            if msc in msc_resolved_strings:
                s.add(Or(msc_normal_strings[msc], msc_resolved_strings[msc]))
            else:
                s.add(msc_normal_strings[msc])
        for msc in msc_resolved_strings:
            if msc in msc_normal_strings:
                continue
            else:
                s.add(msc_resolved_strings[msc])

        return s


    def get_macro_string_tp_connection(self, resolved_strings: list[TreePath]):
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
                        if string_tp.line_number not in mscs:
                            mscs[string_tp[0].line_number] = string_tp.presence_conditions
                        else:
                            mscs[string_tp[0].line_number] = OR(mscs[string_tp[0].line_number], string_tp.presence_conditions)
                        found = True
                          
            else:
                string = string_tp.to_string() 
                for target in self.binary_strings:
                    if target == string:
                        if string_tp.line_number not in mscs:
                            mscs[string_tp[0].line_number] = string_tp.presence_conditions
                        else:
                            mscs[string_tp[0].line_number] = OR(mscs[string_tp[0].line_number], string_tp.presence_conditions)
                        found = True
        
            if not found:
                mscs[string_tp.data[0].line_number] = string_tp.presence_conditions
        return mscs                
                
                




    def get_macro_string_connection(self, strings: list[SourceStringEntry]):
        mscs = dict()
        for string in strings:
            found = False
            presence_conditions = SuperC().get_pc_and_macro_values(self.source_file_path, self.library_dir, string.line_number, None)
            for target in self.binary_strings:
                if string.content == target:
                    if string.line_number not in mscs:
                        mscs[string.line_number] = presence_conditions[0].pc
                    else:
                        mscs[string.line_number] = OR(mscs[string.line_number], presence_conditions[0].pc)
                    found = True
            if not found:
                mscs[string.line_number] = Not(presence_conditions[0].pc)

        return mscs




    def resolve_strings(self, unresolved: list[list[SourceStringEntry]]) -> list[TreePath]:
        resolved_strings = []
        for concat in unresolved:
            concat_tp = TreePath(concat, True)
            resolved_strings += get_all(concat_tp, [], self.source_file_path, self.library_dir)

        return resolved_strings