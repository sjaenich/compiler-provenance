import sys
import random
from collections import defaultdict
import z3
import re
from z3 import *
import os
from string_parser import StringParser, SourceStringEntry
from reverse_engineering.information.information_extractor import InformationExtractor
from superc import SuperC
from presence_condition import PresenceCondition
from dataclasses import dataclass
from reverse_engineering.features.feature_extractor import Feature, FeatureExtractor
from macrostringconnection import *

base_strings = [('realloc', 3907), ('strdup', 3903), ('calloc', 3901), ('if_nametoindex', 2658), ('MD5_Init', 2704), ('MD5_Init', 2707), ('MD5_Init', 2710), ('MD5_Init', 2713), ('MD5_Init', 2716), ('MD5_Init', 2720), ('MD5_Update', 2705), ('MD5_Update', 2708), ('MD5_Update', 2711), ('MD5_Update', 2714), ('MD5_Update', 2717), ('MD5_Update', 2721), ('MD5_Final', 2706), ('MD5_Final', 2709), ('MD5_Final', 2712), ('MD5_Final', 2715), ('MD5_Final', 2718), ('MD5_Final', 2722), ('SHA256_Init', 68), ('SHA256_Init', 71), ('SHA256_Init', 74), ('SHA256_Init', 77), ('SHA256_Init', 80), ('SHA256_Init', 84), ('SHA256_Update', 69), ('SHA256_Update', 72), ('SHA256_Update', 75), ('SHA256_Update', 78), ('SHA256_Update', 81), ('SHA256_Update', 85), ('SHA256_Final', 70), ('SHA256_Final', 73), ('SHA256_Final', 76), ('SHA256_Final', 79), ('SHA256_Final', 82), ('SHA256_Final', 86), ('keep-alive', 857), ('curl', 2669), ('curl', 4666), ('curl', 4667), ('SSL Engine not supported', 6045), ('file type ENG for certificate not implemented', 6011), ('file type ENG for private key not supported', 6038), ('Curl_now', 2923), ('Curl_now', 2924), ('Curl_now', 2925), ('Curl_now', 2926)]



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
        print(feature, val)
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
    index = 0
    BinaryStrings = []
    SourceStrings = []
    IndexSet = []
    librarya = Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib")
    c_files = list(librarya.rglob("*.c"))
    # random.shuffle(c_files) 
    c_files = [
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/cookie.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/dict.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/ftp.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/hostip6.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/hostip.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/http2.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/http.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/http_proxy.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/tftp.c"),
        Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/ldap.c"),
    ]
    ground_truth = [
     "--disable-ntlm",
  "--disable-ntlm-wb",
  "--disable-curldebug",
  "--disable-libcurl-option",
  "--disable-ldap",
  "--disable-ldaps",
  "--disable-threaded-resolver",
  "--disable-verbose", 
  "--disable-ares", 
  "--enable-cookies", 
  "--enable-proxy",
  "--disable-websockets", 
  "--enable-dict",
  "--enable-gopher",
  "--enable-imap",
  "--enable-pop3",
  "--enable-rtsp",
  "--enable-smb",
  "--enable-smtp",
  "--enable-telnet",
  "--enable-tftp",
    ]
    # for filepath in tqdm(c_files[:10]):
    for filepath in tqdm(librarya.rglob("*.c")):
    # for filepath in [filepatha]:
    # , "/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/connect.c", "/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/lib/vquic/quiche.c"]:
        print(filepath)
        sf = SourceFile(filepath, binary_strings, library, index)
        try:
            solver_a = sf.get_macro_formulas()
            solver.add(solver_a.assertions())
            index = sf.index
            s = String('s')
            i = Int('i') 
            
            InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
            SourceStrings.extend(sf.source_code_strings)
            IndexSet.extend(sf.index_set)
        except Exception as e:
            print("EXCEPTION", e)   


    BinaryStrings.extend(sf.binary_strings)
        

    InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
 
    
    IsBinaryString = Function('IsBinaryString', StringSort(), BoolSort())
    IsInIndexSet = Function('IsInIndexSet', StringSort(),IntSort(),BoolSort())
    IsSourceString = Function('IsSourceString', StringSort(),BoolSort())
    s = String('s')
    b = String('b')

    # solver.add(ForAll(
    #     [s],
    #     IsBinaryString(s) == 
    #     Or([s ==b for b in BinaryStrings]))
    # )
 
    
    # solver.add(ForAll(
    #     [s],
    #     IsSourceString(s) == Or([s==r for r in SourceStrings])
    # ))
    
    r = String('r')
    v = String('v')
    # filter_solver.add(ForAll(
    #     [s,i],
    #     IsInIndexSet(s,i) == Or([And(s==r,i==v)for (r,v) in IndexSet]))
    # )



    t = String('t')
    l = Int('l')

    concrete = []   # (python_str, i)
    symbolic = []   # (StringRef, i)

    for (r, i) in IndexSet:
        if isinstance(r, str):
            concrete.append((r, i))
        else:
            symbolic.append((r, i))


    # count = Or([
    # If(IsInIndexSet(t, i), IsBinaryString(t), False)
    # for i in range(50)
    # ])
    print(len(IndexSet))
    print(len(concrete))
    print(len(symbolic))
    index_by_string = defaultdict(list)
    for (r, i) in concrete:
        index_by_string[r].append(i)

    index_by_symbol = defaultdict(list)
    for (r,i) in symbolic:
        print(r,i)
        index_by_symbol[r].append(i)

    base = [first for first, _ in base_strings]
    # base = []

    for s in BinaryStrings:
        indices = index_by_string.get(s, [])        
        if indices:
            print(s, indices, index_by_string[s])
            if s in base:
                continue
            solver.add(
                Or([InBinary(StringVal(s), IntVal(i)) for i in indices])
            )


    # for s in BinaryStrings:
    #     s_val = StringVal(s)

    #     conds = [
    #         Implies(r == s_val, InBinary(s_val, IntVal(i)))
    #         for (r, i) in symbolic
    #     ]

    #     if conds:
    #         solver.add(Or(conds))



    # for s in BinaryStrings:
    #     filtered = [(r, i) for (r, i) in IndexSet if m.eval(IsInIndexSet(StringVal(s), IntVal(i)))]
    #     if filtered != []:
    #         solver.add(Or([InBinary(StringVal(r),IntVal(i)) for (r,i) in filtered]))   


    
    # solver.add(
    #     ForAll(
    #         [t],
    #         Implies(count == 1, InBinary(t, w(t)))
    #     )
    # )
    
        

    
       

    features = FeatureExtractor()
   # raise KeyError

    features.extract(conifgure_path, m4_constraints_path)
    bools = features.macros_as_z3()
    # print(bools)
    # DEFINE_BOOL_RE = re.compile(r'^\s*#define\s+([A-Z0-9_]+)\s+1\s*$')
    # UNDEF_RE = re.compile(r'^\s*/\*\s*#undef\s+([A-Z0-9_]+)\s*\*/\s*$')
    # path = "/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/curl_config.h"
    # with open(path, "r", encoding="utf-8", errors="ignore") as f:
    #     for line in f:
    #         # print(line)
    #         match = DEFINE_BOOL_RE.match(line)
    #         if match:
    #             macro_name = match.group(1)
    #             solver.add((Bool(macro_name)))
    #             print("Bools", macro_name)
    #         m_undef = UNDEF_RE.match(line)        
    #         if m_undef:
    #             macro_name = m_undef.group(1)
    #             solver.add(Bool(macro_name) == False)
    #             print("Bools", macro_name, "false")
     
    
    for d in solver.assertions():
        print("Assertion", d)

    
    check = solver.check()
    if check == sat:
        print("HELL YEAH")
    else: 
        raise KeyError

    m = solver.model()

    for ms in m.decls():
        print("decl", m[ms], ms)

    not_active = []
    add_list = []
    for s in BinaryStrings:
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

    print("Done")
    diff = list(set(IndexSet) - set(add_list))
    print("Diff:", diff)
    print("Not active:", not_active)

    keys = {first for first, _ in add_list}
    weird_strings = []
    print("Keys", keys)
    for (r,l) in not_active:
    
        if r in keys:
            
            continue
        weird_strings.append((r,l))

    print("Not active removed:", weird_strings)

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