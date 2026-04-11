import glob
import random
import shutil
import re
from collections import defaultdict
import os

from z3.z3 import *

from .parsing.string_parser import StringParser, SourceStringEntry
from .reverse_engineering.information.information_extractor import InformationExtractor
from .parsing.superc import SuperC
from .parsing.presence_condition import PresenceCondition
from dataclasses import dataclass
from .reverse_engineering.features.feature_extractor import Feature, FeatureExtractor
from .parsing.macrostringconnection import *


class FlagRecovery:
    
    def __init__(self, source_dir: Path, binary_path: Path, config_h: Path, name: str, include_dir: str, extra_include=None):
        self.source_dir = source_dir
        self.binary_path = binary_path
        self.library_dir = source_dir
        self.config_h = config_h
        self.include_dir = include_dir
        self.solver = Solver()
        self.SourceStrings = []
        self.IndexSet = []
        self.name = name
        self.approach = "standard"
        self.iteration = 0 
        self.strings_count = 0
        self.extra_include = extra_include




    def collect_presence_conditions(self) -> list[str]: 
        print("THIS IS BINARY PATH", self.binary_path)
        binary_strings = InformationExtractor(self.binary_path)
        index = 0
        # list_c = list(self.source_dir.glob("*.c")) + list(self.source_dir.glob("*/*.c"))
        for filepath in tqdm(self.source_dir.rglob("*.c")):
        # for filepath in tqdm(list_c):
        # for filepath in tqdm([Path("/worksrpaces/RevEng/buildroot-2025.02.4/output/build/libxml2-2.13.8/testapi.c")]):
            if "test" in filepath.name:
                continue
            print(filepath)
            # TODO: Add the config_h location and the new other_defines location, maybe just give the name... 
            sf = SourceFile(filepath, binary_strings, self.library_dir, index, self.config_h, self.name, self.include_dir, self.extra_include)
            # try:
            solver_a = sf.get_macro_formulas()
            # solver_a.check()
            # print("Solver alone Check worked")
            self.solver.add(solver_a.assertions())
            index = sf.index
            self.SourceStrings.extend(sf.source_code_strings)
            print("Index set size", len(sf.index_set))
            self.IndexSet.extend(sf.index_set)
            # self.solver.check()
            # print("Check worked")
            # except Exception as e:
                # print("EXCEPTION", e)   
        return sf.binary_strings




    def add_groundtruth_to_solver(self, config):
        DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+(.+?)\s*$')
        UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')
        
        output_path = f"/workspaces/RevEng/header/groundtruth/{self.name}_groundtruth.h" 
        if not os.path.isfile(output_path):
            output_path = str(self.config_h)

   

        output_path = config

        print("Adding ground truth to solver from config_h", output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            print("OPENED CONFIG")
            for line in f:
                print(line)
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
            




    def find_external_strings(self, binary_strings, external_strings, config) -> list[(str,int)]:
        self.solver.push()
        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
        
        
        
        self.add_groundtruth_to_solver(config)
        for d in self.solver.assertions():
            print("Assertion", d)

        
        check = self.solver.check()
        if check == sat:
            print("HELL YEAH")
        else: 
            return external_strings


        m = self.solver.model()
        print("IndexSet:", self.IndexSet)
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
        
        print("Weird strings", weird_strings)
        
        if len(external_strings) > 1:
            weird_strings = list(set(weird_strings) & set(external_strings))
        
        print("Weird strings - external strings", set(weird_strings) - set(external_strings))
        print("External strings- weird strings", set(external_strings) - set(weird_strings))      

        print("Not active removed", weird_strings)


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
                # print(s, indices, index_by_string[s])
                if s in base:
                    continue
                print("Adding to solver:", s, indices)
                self.solver.add(
                    Or([InBinary(StringVal(s), IntVal(i)) for i in indices])
                )
        self.solver.push()
        self.add_negative_constraints(binary_strings, index_by_string, base)
        check = self.solver.check()
        if check == sat:
            print("HELL YEAH")
        else: 
            self.solver.pop()
            check = self.solver.check()
            self.approach += "_no_negative_constraints"
            if check != sat:
                return []

        m = self.solver.model()
        macros = set()
        for ms in m.decls():
            if str(ms).startswith("InBinary"):
                continue    
            macros.add((str(ms), str(m[ms])))
            print("decl", m[ms], ms)
        self.solver.pop()
        return macros

    def add_negative_constraints(self, binary_strings, index_by_string, base):
        with open(f"/workspaces/RevEng/{self.name}_stripped_strings.txt", "r") as f:
            unique_strings = list(set(line.strip() for line in f if line.strip()))

        InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())

        for s in unique_strings:
            if s in base:
                continue
            if s not in binary_strings and len(s) > 10:
                indices = index_by_string.get(s, [])
                if indices:
                    self.solver.add(
                        And([Not(InBinary(StringVal(s), IntVal(i))) for i in indices])
                    )
                    print("Adding negative constraint for", s, indices)
              


    def modify_config_h(self, name: str):
        DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+(?:0|1)\s*$')
        UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')
        DEFINE_OTHER_RE = re.compile(r'^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()')

        path = str(self.config_h)
        out_path = "/workspaces/RevEng/header/other_defines/other_defines" + name + ".h"

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

    def run(self, stage: str) -> list[(str,str)]:

        # self.modify_config_h(self.name)
     
        self.config_h = Path("/workspaces/RevEng/header/libraries/" + self.name + ".h")
        binary_strings = self.collect_presence_conditions()
        iteration = 0
        external_strings = []
        self.approach = stage
        if stage == "initial":
            macros = self.recover_macros(binary_strings, external_strings)
        elif stage == "filter":
            # except Exception as e:       
            # dirs = [d for d in glob.glob("/workspaces/RevEng/buildroot-2025.02.4/output/build/"+ self.name +"_*_bundle/") if os.path.isfile(os.path.join(d, "config.h"))]
            dirs = [
                os.path.join(d, next(f for f in os.listdir(d) if f.endswith(".h")))
                for d in glob.glob(f"/workspaces/RevEng/buildroot-2025.02.4/output/build/{self.name}_*_bundle/")
                if any(f.endswith(".h") for f in os.listdir(d))
            ]
            selected = random.sample(dirs, min(3, len(dirs)))
            for config in selected:
                external_strings = self.find_external_strings(binary_strings, external_strings,config)
                print("External strings", external_strings)
            macros = self.recover_macros(binary_strings, external_strings)
    
        # external_strings = []
        return macros