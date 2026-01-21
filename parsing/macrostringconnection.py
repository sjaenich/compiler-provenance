from dataclasses import dataclass
from pathlib import Path
from z3.z3 import *
from z3.z3 import BoolRef
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
    def __init__(self, source_file_path :Path, binary_strings: InformationExtractor, library_dir: str, index: int):
        self.source_file_path = source_file_path
        self.library_dir = library_dir
        self.binary_strings = binary_strings.strings
        self.source_strings: StringParser
        self.str_to_pc: dict[str, BoolRef] = dict()
        self.macro_to_presence_condition: dict[str, BoolRef] = dict()
        self.macro_string_connection: dict[int, BoolRef] = dict()
        self.covered_lines: set[int] = set()
        self.solver: Solver = Solver()
        self.index_set: list = []
        self.source_code_strings: list[str] = []
        self.index: int = index

    def get_macro_formulas(self) -> Solver:
        self.solver = Solver()
        self.solver.set(unsat_core=True)
        self.source_strings = StringParser(self.source_file_path)
        self.source_strings.extract_string_literals()
        self.source_strings.clean_string_literals()
        print("Getting the strings --> normal and resolved")
        normal_strings = self.source_strings.strings
        resolved_strings = self.resolve_strings(self.source_strings.strings_with_unresolved_macros) 
        print("Getting the macro string connections --> normal ")


        s = String('s')
        i = Int('i') 
        BinaryStrings = self.binary_strings
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())

        self.add_string_presence_conditions(normal_strings)

        print("Getting the macro string connections --> resolved")
        self.add_string_tp_presence_conditions(resolved_strings)

        SourceStrings = self.source_code_strings
        IndexSet = self.index_set
        self.solver.assert_and_track(
            ForAll(
                [s],
                    (Implies(
                        Or([s ==  b for b in BinaryStrings]),   
                        Exists(
                            [i],
                            And(
                                Or([And(i == IntVal(v), s== r) for (r,v) in IndexSet]), 
                                InBinary(s, i)
                            )
                        )
                    ) for s in SourceStrings)
                )
            , Bool("Q_exists")
        )
        print("The solver is done being prepared")
        self.solver.assert_and_track(
           ForAll(
                [s,i],
                Implies(InBinary(s,i), Or([s == b for b in BinaryStrings]))
                ), Bool("Q_Inbinary")
        )   
        
        return self.solver



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
                        solver = Solver()
                        solver.add(pc)
                        if solver.check() == unsat:
                            print(string_tp.data, string_tp.presence_conditions)
                            raise KeyError
                        for d in m.decls():
                            if m[d] =="":
                                continue
                            if d in self.macro_to_presence_condition:
                                pc = And(pc, d() == m[d])
                                pc = Or(pc, self.macro_to_presence_condition[d])
                                self.macro_to_presence_condition[d] = pc
                            else:
                                pc = And(pc, d() == m[d])
                                print("d. ", d, d(), m[d])
                                print("target", target, pc)
                                self.macro_to_presence_condition[d] = pc
                            print("target", target, pc)
                        if target not in strings_to_presence_condition:
                            strings_to_presence_condition[target] = pc   
                            print("should be here", target)                         
                        else:
                            strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], pc)
                        print(target, m[d],d, line)
            else:
                string = string_tp.to_string() 
                for target in self.binary_strings:
                    if target == string:
                        if target not in strings_to_presence_condition: 
                            strings_to_presence_condition[target] = string_tp.presence_conditions
                        else:
                            strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], string_tp.presence_conditions)                            
                        found = True
                        print(target, "string", string_tp.data[0].line_number)        
            if not found:
                self.macro_string_connection[string_tp.data[0].line_number] = Not(string_tp.presence_conditions)

        for s in strings_to_presence_condition:
            macros.add(strings_to_presence_condition[s])

        solver = Solver()
        for s in strings_to_presence_condition:
            macros.add(strings_to_presence_condition[s])
            solver.add(strings_to_presence_condition[s])
            print(s, "solver")
            if solver.check() == unsat:
                print("oh no", s)
                raise KeyError

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
                        print(target, string.data[0].content, string.data[0].line_number, "first")
                    else:
                        strings_to_presence_condition[target] = Or(strings_to_presence_condition[target], string.presence_conditions)
                        print(target, string.data[0].content, "second")
                    found = True
            if not found:
                self.macro_string_connection[string.data[0].line_number] = Not(string.presence_conditions)
        # solver = Solver()
        # for s in strings_to_presence_condition:
        #     macros.add(strings_to_presence_condition[s])
        #     solver.add(strings_to_presence_condition[s])
        #     print(s)
        #     if solver.check() == unsat:
        #         print("oh no", s)
        #         raise KeyError
        self.str_to_pc.update(strings_to_presence_condition)
        

        
        return macros


    def resolve_strings(self, unresolved: list[list[SourceStringEntry]]) -> list[TreePath]:
        resolved_strings = []
        for concat in tqdm(unresolved):
            concat_tp = TreePath(concat, True)
            resolved_strings += get_all(concat_tp, [], self.source_file_path, self.library_dir)

        return resolved_strings



    def add_string_presence_conditions(self, strings: list[SourceStringEntry]):
        macros = set()
        resolved_strings = []
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
        strings_to_presence_condition = dict()
        entries = SuperC().get_pc_and_macro_values(self.source_file_path, self.library_dir, None, None)
        if entries == []:
            print("No Presence Conditions for",  self.source_file_path)
            return None
        for string in strings:
            if string.content.endswith(".h"):
                continue
            entry = entries[0]
            for e in entries:
                if e.line > string.line_number:
                    break
                entry = e
            string_tp = TreePath([string], entry.pc)
            resolved_strings.append(string_tp)
        
        for string_tp in resolved_strings:            
            self.index = self.index + 1
            string = string_tp.to_string()
            # print("normal",string_tp.presence_conditions == InBinary(StringVal(string), self.index) )
            label = Bool(f"pc_{string}_{self.index}")
            self.solver.assert_and_track(string_tp.presence_conditions == InBinary(StringVal(string), self.index), label)
            self.str_to_pc[label] = string_tp.presence_conditions 
            self.index_set.append((string, self.index))
            self.source_code_strings.append(string)
            # if self.solver.check() == sat:
            #     print('works')
            # else:
            #     core = self.solver.unsat_core()
            #     print("UNSAT CORE:")
            #     for c in core:
            #         print(c)
            #         print(self.str_to_pc[c])
            #     raise KeyError


    def add_string_tp_presence_conditions(self, resolved_strings: list[TreePath]):
        strings_to_presence_condition = dict()
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
        for string_tp in resolved_strings:
            arguments = []
            self.index = self.index + 1
            if string_tp.contains_unresolved_macro():
                arguments = string_tp.to_z3()
                # print("unresolved", string_tp.presence_conditions == InBinary(Concat(arguments), self.index))
                label = Bool(f"pc{Concat(arguments)}_{self.index}")
                self.solver.assert_and_track(string_tp.presence_conditions == InBinary(Concat(arguments), self.index), label)
                self.index_set.append((Concat(arguments), self.index))
                self.source_code_strings.append(Concat(arguments))
                self.str_to_pc[label] = string_tp.presence_conditions

            else:
                string = string_tp.to_string()
                label = Bool(f"pc_{string}_{self.index}")
                self.solver.assert_and_track(string_tp.presence_conditions == InBinary(StringVal(string), self.index), label)
                # print("resolved", string_tp.presence_conditions == InBinary(StringVal(string), self.index))
                self.index_set.append((string, self.index))
                self.source_code_strings.append(string)
                self.str_to_pc[label] = string_tp.presence_conditions
            
                            
            # if self.solver.check() == sat:
            #     print("works")
            # else:
            #     core = self.solver.unsat_core()
            #     print("UNSAT CORE:")
            #     for c in core:
            #         print(c)
            #         print(self.str_to_pc[c])
            #     raise KeyError