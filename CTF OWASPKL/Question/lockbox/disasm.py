import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def disassemble_elf(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        if not text:
            print("No .text section found.")
            return

        code = text.data()
        addr = text['sh_addr']

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        with open('disasm.txt', 'w') as out:
            for i in md.disasm(code, addr):
                out.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))

if __name__ == '__main__':
    disassemble_elf('lockbox')
