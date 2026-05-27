"""
Try running the binary by creating the required file structure and using QEMU user mode.
Or alternatively, verify the snprintf output format more carefully.
"""

# Actually, let me re-examine the snprintf more carefully.
# The format string is at 0x3220: "%02x%02x%02x%02x"
# But wait, let me check if maybe it's "%02X" (uppercase)?

data = open('detonate2.exe', 'rb').read()
fmt = data[0x3220:0x3220+20]
print(f"Format string at 0x3220: {fmt}")
print(f"Hex: {fmt.hex()}")

# It's definitely lowercase %02x

# Let me also check: in the snprintf call, maybe the argument passing
# is different than what I assumed.
# 
# Looking at the code more carefully:
# 
# 0x2626: loop start (i=0..3)
#   0x262b: eax = M[i] (32-bit hash word)
#   0x2632: shr eax, 0x18 -> edx = byte3 (MSB)
#   0x2635: mov edx, eax
# 
# Wait. At 0x2632 it's `shr eax, 0x18`, which gives the MSB.
# Then `mov edx, eax` puts MSB in edx.
# But edx is also used later as the 4th arg to snprintf (pushed on stack).
# Let me verify by looking at the FULL sequence again.
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code = data[0x2626:0x26a4]
print("\nFull snprintf setup loop:")
for insn in md.disasm(code, 0x2626):
    print(f"  0x{insn.address:x}: {insn.mnemonic}\t{insn.op_str}")
