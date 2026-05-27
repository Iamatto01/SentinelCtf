import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL

def disassemble_elf(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        rodata = elf.get_section_by_name('.rodata')
        rodata_base = rodata['sh_addr'] if rodata else 0
        rodata_data = rodata.data() if rodata else b''
        
        def get_string(addr):
            if rodata_base <= addr < rodata_base + len(rodata_data):
                offset = addr - rodata_base
                end = rodata_data.find(b'\0', offset)
                if end != -1:
                    return rodata_data[offset:end]
            return None

        text = elf.get_section_by_name('.text')
        if not text:
            print("No .text section found.")
            return

        code = text.data()
        addr = text['sh_addr']

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        
        with open('disasm_annotated.txt', 'w') as out:
            for i in md.disasm(code, addr):
                comment = ""
                # Simple RIP-relative address calculation
                if "rip" in i.op_str:
                    try:
                        disp = 0
                        if '+' in i.op_str:
                            part = i.op_str.split('+')[1].split(']')[0].strip()
                            disp = int(part, 16)
                        elif '-' in i.op_str:
                            part = i.op_str.split('-')[1].split(']')[0].strip()
                            disp = -int(part, 16)
                        
                        target = i.address + i.size + disp
                        comment = f" ; target: {hex(target)}"
                        s = get_string(target)
                        if s:
                            comment += f" string: {s}"
                    except Exception as e:
                        pass
                
                out.write("0x%x:\t%s\t%s%s\n" % (i.address, i.mnemonic, i.op_str, comment))

if __name__ == '__main__':
    disassemble_elf('lockbox')
