import sys
from elftools.elf.elffile import ELFFile
from capstone import *

def analyze_elf(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        
        # Get rodata to find string offsets
        rodata = elf.get_section_by_name('.rodata')
        rodata_data = rodata.data()
        rodata_addr = rodata['sh_addr']
        
        with open('disasm.txt', 'w', encoding='utf-8') as out:
            out.write("--- RODATA STRINGS ---\n")
            offset = 0
            while offset < len(rodata_data):
                end = rodata_data.find(b'\0', offset)
                if end != -1 and end > offset:
                    s = rodata_data[offset:end].decode(errors='ignore')
                    if len(s) >= 4:
                        out.write(f"0x{rodata_addr + offset:x}: {s}\n")
                if end == -1: break
                offset = end + 1

            out.write("\n--- DISASSEMBLY ---\n")
            text = elf.get_section_by_name('.text')
            code = text.data()
            addr = text['sh_addr']
            
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(code, addr):
                out.write(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n")

if __name__ == '__main__':
    analyze_elf('host_memdiag')
