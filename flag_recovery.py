import shutil
import re
from collections import defaultdict


from z3.z3 import *

from .parsing.string_parser import StringParser, SourceStringEntry
from .reverse_engineering.information.information_extractor import InformationExtractor
from .parsing.superc import SuperC
from .parsing.presence_condition import PresenceCondition
from dataclasses import dataclass
from .reverse_engineering.features.feature_extractor import Feature, FeatureExtractor
from .parsing.macrostringconnection import *


class FlagRecovery:

    def __init__(self, source_dir: Path, binary_path: Path, config_h: Path, name: str, include_dir: str):
        self.source_dir = source_dir
        self.binary_path = binary_path
        self.library_dir = source_dir
        self.config_h = config_h
        self.include_dir = include_dir
        self.solver = Solver()
        self.SourceStrings = []
        self.IndexSet = []
        self.name = name

    def collect_presence_conditions(self) -> list[str]: 
        binary_strings = InformationExtractor(self.binary_path)
        index = 0
        for filepath in ["/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/http.c"]:
        # tqdm(self.source_dir.rglob("*.c")):
            print(filepath)
            # TODO: Add the config_h location and the new other_defines location, maybe just give the name... 
            sf = SourceFile(filepath, binary_strings, self.library_dir, index, self.config_h, self.name, self.include_dir)
            try:
                solver_a = sf.get_macro_formulas()
                self.solver.add(solver_a.assertions())
                index = sf.index
                self.SourceStrings.extend(sf.source_code_strings)
                print("Index set size", len(sf.index_set))
                self.IndexSet.extend(sf.index_set)
            except Exception as e:
                print("EXCEPTION", e)   
        return sf.binary_strings
    

    def add_groundtruth_to_solver(self):
        DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+1\s*$')
        UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')
        
        with open(str(self.config_h), "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = DEFINE_BOOL_RE.match(line)
                if match:
                    macro_name = match.group(1)
                    self.solver.add((Bool(macro_name)))
                    print("Bools", macro_name)
                m_undef = UNDEF_RE.match(line)        
                if m_undef:
                    macro_name = m_undef.group(1)
                    self.solver.add(Bool(macro_name) == False)
                    print("Bools", macro_name, "false")

    def find_external_strings(self, binary_strings) -> list[(str,int)]:
        self.solver.push()
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
        self.add_groundtruth_to_solver()

        for d in self.solver.assertions():
            print("Assertion", d)

        
        check = self.solver.check()
        if check == sat:
            print("HELL YEAH")
        else: 
            raise KeyError


        m = self.solver.model()
        print("INdexSet:", self.IndexSet)
        concrete = []  
        symbolic = []
        for (r, i) in self.IndexSet:
            if isinstance(r, str):
                print("concrete", r, i)
                concrete.append((r, i))
            else:
                symbolic.append((r, i))

    
        index_by_string = defaultdict(list)
        for (r, i) in concrete:
            index_by_string[r].append(i)

        index_by_symbol = defaultdict(list)
        for (r,i) in symbolic:
            print(r,i)
            index_by_symbol[r].append(i)
        not_active = []
        add_list = []
        for s in binary_strings:
            indices = index_by_string.get(s, [])        
            if indices:
                for i in indices:
                    print((s,i))
                    guard = False
                    eval = m.eval(InBinary(StringVal(s),IntVal(i)))
                    if eval == True:
                        print((s,i),"enabled")
                        add_list.append((s,i))
                        guard = True
                    elif eval == False:
                        not_active.append((s,i))
                        print((s,i), "not active")
                    else: 
                        print((s,i), "eval", eval)
                    print("Done index", s)
                if guard:
                    for i in indices:
                        add_list.append((s,i))
            indices = index_by_symbol.get(s, [])
        
        if indices:
            for i in indices:
                guard = False
                eval = m.eval(InBinary(StringVal(s),IntVal(i)))
                if eval == True:
                    print((s,i),"enabled")
                    add_list.append((s,i))
                    guard = True
                elif eval == False:
                    not_active.append((s,i))
                    print((s,i), "not active")
                else: 
                    print((s,i), "eval", eval)
                print("Done index", s)
            if guard:
                for i in indices:
                    add_list.append((s,i))

        keys = {first for first, _ in add_list}
        weird_strings = []
        print("Keys", keys)
        for (r,l) in not_active:
            if r in keys:
                continue
            weird_strings.append((r,l))
        self.solver.pop()
        return weird_strings

    def recover_macros(self, binary_strings, external_strings):
        self.solver.push()
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
        print("Binary strings:", binary_strings)
        concrete = []  
        symbolic = []
        for (r, i) in self.IndexSet:
            if isinstance(r, str):
                concrete.append((r, i))
            else:
                symbolic.append((r, i))

    
        index_by_string = defaultdict(list)
        for (r, i) in concrete:
            index_by_string[r].append(i)

        index_by_symbol = defaultdict(list)
        for (r,i) in symbolic:
            print(r,i)
            index_by_symbol[r].append(i)


            
        base = [first for first, _ in external_strings]


        for s in binary_strings:
            indices = index_by_string.get(s, [])        
            if indices:
                print(s, indices, index_by_string[s])
                if s in base:
                    continue
                print("Adding to solver:", s, indices)
                self.solver.add(
                    Or([InBinary(StringVal(s), IntVal(i)) for i in indices])
                )
        

        
        check = self.solver.check()
        if check == sat:
            print("HELL YEAH")
        else: 
            raise KeyError

        m = self.solver.model()
        macros = set()
        for ms in m.decls():
            macros.add((str(ms), str(m[ms])))
            print("decl", m[ms], ms)
        self.solver.pop()
        return macros

    def modify_config_h(self, name: str):
        DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+1\s*$')
        UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')
        DEFINE_OTHER_RE = re.compile(r'^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()')

        path = str(self.config_h)
        out_path = "/workspaces/RevEng/other_defines" + name + ".h"

        with open(path, "r", encoding="utf-8", errors="ignore") as f, \
            open(out_path, "w", encoding="utf-8") as out:
            out.write("/* Auto-extracted non-boolean defines */\n\n")
            for line in f:
                print(line.rstrip())
                handled = False
                match = DEFINE_BOOL_RE.match(line)
                if match:
                    macro_name = match.group(1)
                    handled = True
                m_undef = UNDEF_RE.match(line)
                if m_undef:
                    macro_name = m_undef.group(1)                    
                    handled = True
                if not handled:
                    m_other = DEFINE_OTHER_RE.match(line)
                    if m_other:
                        out.write(line)
        destination = "/workspaces/RevEng/" + name + ".h"
        self.config_h = Path(destination)
        shutil.move(path, destination)        

    def run(self) -> list[(str,str)]:

        self.modify_config_h(self.name)

        binary_strings = self.collect_presence_conditions()
        external_strings = self.find_external_strings(binary_strings)
        macros = self.recover_macros(binary_strings, external_strings)
        return macros
