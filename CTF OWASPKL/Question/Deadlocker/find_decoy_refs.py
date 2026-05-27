from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

with open('Deadlocker', 'rb') as f:
    elf = ELFFile(f)
    text_sec = elf.get_section_by_name('.text')
    text_data = text_sec.data()
    text_addr = text_sec.header.sh_addr

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print("Scanning .text for memory references to 0x2020...")
    for insn in md.disasm(text_data, text_addr):
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    if target == 0x2020:
                        print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}  --> target: {hex(target)}")
