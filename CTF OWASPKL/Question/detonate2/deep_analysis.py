import hashlib

data = open('detonate2.exe', 'rb').read()

# Maybe the check_flag function is not the only interesting function.
# Let me look at everything between .text start and end
# .text: offset=0x21a0 size=0xa21

# Let me check ALL functions in .text by looking at function prologues
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Disassemble the full .text section
text_data = data[0x21a0:0x21a0+0xa21]
functions = []
for insn in md.disasm(text_data, 0x21a0):
    if insn.mnemonic == 'push' and insn.op_str == 'rbp':
        # Check if next is mov rbp, rsp
        functions.append(insn.address)

print("Functions found (push rbp):")
for addr in functions:
    print(f"  {hex(addr)}")

# Known functions:
# 0x2289 = md5
# 0x2733 = check_flag
# 0x28f0 = main
# 0x2900 = char_traits<char>::length (overload)
# 0x2932 = __gnu_cxx::char_traits<char>::length

# Are there any other interesting functions?
# Let me check for any XOR operations that might hide data
print("\nXOR instructions in .text:")
for insn in md.disasm(text_data, 0x21a0):
    if insn.mnemonic == 'xor' and 'eax, eax' not in insn.op_str:
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

# Let me also check for any interesting constants
print("\nMOV with interesting constants:")
for insn in md.disasm(text_data, 0x21a0):
    if insn.mnemonic == 'mov' and '0x' in insn.op_str:
        # Skip common small values and MD5 constants
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                val = op.imm & 0xFFFFFFFF
                if val > 0xFF and val not in [
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                    0xffffff80,
                ]:
                    pass  # Too many to print
