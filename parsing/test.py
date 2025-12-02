import sys
import z3
from z3 import *
import os
from string_parser import StringParser, SourceStringEntry
from reverse_engineering.information.information_extractor import InformationExtractor




if __name__ == "__main__":   
    
    filepath = sys.argv[1]
    binary_path = sys.argv[2]
    sp = StringParser(filepath)
    sp.extract_string_literals()
    sp.clean_string_literals()
    binary_strings = InformationExtractor(file_path=binary_path)
#    for s in binary_strings.strings:
#        print(s)
 #   for string in sp.strings:
        # print(string.content)
#        print(sp.strings_with_unresolved_macros[0])
        
#        if string.content in binary_strings.strings:

            #print(string.content, string.line_number)
        
    for concat in sp.strings_with_unresolved_macros:
        arguments = []
        for string in concat:
            if string.macro:
                x = String(string.content)
                arguments.append(x)
            else:
                arguments.append(string.content)

        for target in binary_strings.strings:
            s = Solver()
            s.add(Concat(arguments) == target)
            if s.check() == sat:
                print("This is  == the model", s.model())
                break
