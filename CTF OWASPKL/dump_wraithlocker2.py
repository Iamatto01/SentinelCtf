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

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        with open('f:/ctf/CFT OWASP/wraithlocker.asm', 'w') as out:
            for i in md.disasm(code, addr):
                out.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))

analyze('f:/ctf/CFT OWASP/Question/Wraithlocker/wraithlocker')
print('Disassembled to wraithlocker.asm')
