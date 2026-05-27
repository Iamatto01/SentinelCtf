import sys
from elftools.elf.elffile import ELFFile
from capstone import *

def analyze(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        if not text_sec:
            print("No .text section found.")
            return

        code = text_sec.data()
        addr = text_sec['sh_addr']

        # Look for functions by reading symtab if available
        symtab = elf.get_section_by_name('.symtab')
        if symtab:
            for sym in symtab.iter_symbols():
                if sym.name and sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                    print(f"Function {sym.name} at {hex(sym['st_value'])} size {sym['st_size']}")

analyze('f:/ctf/CFT OWASP/Question/Wraithlocker/wraithlocker')
