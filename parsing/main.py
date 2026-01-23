from z3.z3 import *
import re  
HAVE_CONFIG_H = Bool('HAVE_CONFIG_H')
HTTP_ENABLE = Bool('HTTP_ENABLE')
M1 = Bool('HAVE_FTP')
M2 = Bool('HTTP_ENABLE')
M3 = Bool('HAVE_H')
MacroConditions = And(HAVE_CONFIG_H, HTTP_ENABLE)
X=String('X')
# Source string as Boolean
Source_http = Concat(StringVal("htt"), X)
# Source_http = StringVal('http')  # True if "http" exists in source
BinaryStrings = [
   "https"
]

SourceStrings = [
    StringVal("http"),
    StringVal("https"),
    Concat(StringVal("htt"), X )
]
p = " CURL_DISABLE_FTP "
print(p)
p = re.sub(r'^\s+|\s+$', '', p)
print(p)
Y=Int('Y')
# Binary string as Boolean
# True if "http" exists in binary

Equations = [ IntVal(1) , IntVal(2),  IntVal(3)]
InBinary = Function('InBinary', StringSort(), IntSort(), BoolSort())
s = String('s')
i = Int('i')
m = Bool('m')  # schematic; see note below
solver = Solver()
r = String('r')
Q = Function('Q', StringSort(),BoolSort())
solver.add((MacroConditions == InBinary(StringVal("https"), 1)))
# solver.add((And(M1, Not(M2))) == InBinary(StringVal("https"),IntVal(2)))
# solver.add((MacroConditions == InBinary(StringVal("https"),IntVal(3))))
# solver.add((M3 == InBinary(StringVal("http"), IntVal(4))))
# solver.add((M3) == InBinary(StringVal("https"),5))
# Solver Typechecking einschalten

# solver.add(
 
#     ForAll(
#         [s,i],
#         InBinary(s,i ) == Or([s == b for b in BinaryStrings])
#     )
 
# )

IndexSet = [ ("http" ,4), ("https",5) ]
 
solver.add(
    ForAll(
        [s],
        Implies(Or([s == t for t in SourceStrings]),
        Implies(
            Or([s ==  b for b in BinaryStrings]),   
            Exists(
                [i],
                And(
                    Or([And(i == IntVal(v), s== r) for (r,v) in IndexSet]), 
                    InBinary(s, i)
                )
            )
        )
        )
    )
)
# solver.add(
#     ForAll(
#         [s,i],
#         Implies(InBinary(s,i), Or([s == b for b in BinaryStrings]))
#     )
# )



print(solver.assertions())
# solver.add(ec)

# solver.add(EquivCondition)

print("Solver check:", solver.check())
if solver.check() == sat:
    m = solver.model()
    print("Macros and string values:")
    print("HAVE_CONFIG_H =", m.evaluate(Bool("HAVE_CONFIG_H")))
    print("HTTP_ENABLE   =", m.evaluate(HAVE_CONFIG_H))
    print("HAVE_FTP =", m.evaluate(M1))
    print("HTTP_ENABL 2 =", m.evaluate(M2))
    print("http  1 = ", m.evaluate(InBinary(StringVal("https"),2)))
    print("http 2 = ", m.evaluate(InBinary(StringVal("http"),3)))
    print("M3 =", m.evaluate(M3))