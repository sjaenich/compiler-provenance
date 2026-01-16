from z3.z3 import *

HAVE_CONFIG_H = Bool('HAVE_CONFIG_H')
HTTP_ENABLE = Bool('HTTP_ENABLE')
M1 = Bool('HAVE_FTP')
M2 = Bool('HTTP_ENABLE')
MacroConditions = And(HAVE_CONFIG_H, HTTP_ENABLE)
X=String('X')
# Source string as Boolean
Source_http = Concat(StringVal("htt"), X)
# Source_http = StringVal('http')  # True if "http" exists in source
BinaryStrings = [
    StringVal("http"),
    StringVal("https"),
]
# Binary string as Boolean
# True if "http" exists in binary
Binary_http = Bool('https')  
InBinary = Function('InBinary', StringSort(), BoolSort())
EquivConditions = [
    (MacroConditions == InBinary(Source_http)),
    ((And(M1, Not(M2))) == InBinary(StringVal("http")))
]
# Solver Typechecking einschalten

s = String('s')
solver = Solver()
solver.add(
    ForAll(
        [s],
        InBinary(s) == Or([s == b for b in BinaryStrings])
    )
)


solver.add(InBinary(Source_http))
solver.add(ec)

# solver.add(EquivCondition)

print("Solver check:", solver.check())
if solver.check() == sat:
    m = solver.model()
    print("Macros and string values:")
    print("HAVE_CONFIG_H =", m.evaluate(HAVE_CONFIG_H))
    print("HTTP_ENABLE   =", m.evaluate(HTTP_ENABLE))
    print("InBinary =", m.evaluate(InBinary(Source_http)))
    print("X =", m.evaluate(X))