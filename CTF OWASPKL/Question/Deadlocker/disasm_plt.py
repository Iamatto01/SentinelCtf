from elftools.elf.elffile import ELFFile
from capstone import *

with open('Deadlocker', 'rb') as f:
    elf = ELFFile(f)
    code = f.read()

# Let's find the file offset for 0x11e0
# 0x11e0 is in .plt.sec or .plt
# .plt starts at 0x1020, offset 0x1020
# Since .plt.sec is at 0x1140 (offset 0x1140) or similar, let's check
# Let's read from 0x11d0 to 0x11f0
offset = 0x11d0
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code[offset:offset+0x20], 0x11d0):
    print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
