from z3.z3 import *
import re  
from pathlib import Path
from reverse_engineering.features.feature_extractor import Feature, FeatureExtractor

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


solver = Solver()
solver.from_file("state.smt2.old")
x=Bool("CURL_DISABLE_HTTP")
solver.add(x==False)


configure_path = Path("/workspaces/RevEng/buildroot-2025.02.4/output/build/libcurl-7.71.1/configure.ac")
m4_constraints_path = Path("/workspaces/RevEng/Tools/compiler-provenance/reverse_engineering/features/extract.m4")

features = FeatureExtractor()


features.extract(configure_path, m4_constraints_path)
bools = features.macros_as_z3()



enabled = set()
disabled = set()
unknown = set()
for name, feature in bools.items():
        
    if type(feature) is bool:
        continue
    
    solver.add(feature == True)
    

if solver.check() == unsat:
    print("Does not work")
    raise KeyError
print(bools)
model = solver.model()
print("Test", model.eval(Bool("CURL_DISABLE_COOKIES")))
for name, feature in bools.items():
        
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

print("Enabled features:")
for f in sorted(enabled):
    print("  +", f)
print("\nDisabled features:")
for f in sorted(disabled):
    print("  -", f)
print("\nUnknown Features")
for f in sorted(unknown):
    print( " **", f)
# if solver.check() == sat:
#     print(solver.model())




