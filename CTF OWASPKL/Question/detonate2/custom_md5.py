import struct, math

# Standard MD5 K constants
K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

# Standard MD5 S constants
S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

def u32(x):
    return x & 0xFFFFFFFF

def rol32(x, n):
    return u32((x << n) | (x >> (32 - n)))

def custom_md5(data: bytes) -> str:
    """
    Reimplementation matching the exact disassembly of detonate2.exe
    
    Variable mapping from disassembly:
      [rbp-0x14] = a (h0)  -- init 0x67452301
      [rbp-0x18] = b (h1)  -- init 0xefcdab89
      [rbp-0x1c] = c (h2)  -- init 0x98badcfe
      [rbp-0x20] = d (h3)  -- init 0x10325476
      
    Working copies in the round loop:
      [rbp-0x38] = A  (initialized from a/h0)
      [rbp-0x3c] = B  (initialized from b/h1)
      [rbp-0x40] = C  (initialized from c/h2)
      [rbp-0x44] = D  (initialized from d/h3)
      [rbp-0x48] = i  (loop counter)
      [rbp-0x4c] = f
      [rbp-0x50] = g
    """
    
    # Init
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    
    # Padding (matching disasm)
    orig_len = len(data)
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    
    # Append length in bits as 8 bytes LE
    bit_len = orig_len * 8
    for i in range(8):
        msg.append((bit_len >> (i * 8)) & 0xFF)
    
    # Process each 64-byte block
    offset = 0
    while offset < len(msg):
        # Parse block into 16 x 32-bit words (little-endian)
        # From disasm: bytes read as byte0 | (byte1<<8) | (byte2<<16) | (byte3<<24)
        M = []
        for j in range(16):
            b0 = msg[offset + j*4]
            b1 = msg[offset + j*4 + 1]
            b2 = msg[offset + j*4 + 2]
            b3 = msg[offset + j*4 + 3]
            M.append(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
        
        # Working copies
        # From disasm at 0x2467-0x247c:
        # [rbp-0x38] = [rbp-0x14] = h0 = A
        # [rbp-0x3c] = [rbp-0x18] = h1 = B
        # [rbp-0x40] = [rbp-0x1c] = h2 = C
        # [rbp-0x44] = [rbp-0x20] = h3 = D
        A = h0
        B = h1
        C = h2
        D = h3
        
        for i in range(64):
            if i <= 15:
                # 0x2491-0x24a9:
                # f = (B & C) | (~B & D)
                f = (B & C) | ((~B & 0xFFFFFFFF) & D)
                g = i
            elif i <= 31:
                # 0x24b7-0x24e8:
                # f = (D & B) | (~D & C)
                f = (D & B) | ((~D & 0xFFFFFFFF) & C)
                g = (5 * i + 1) % 16
            elif i <= 47:
                # 0x24f3-0x251a:
                # f = B ^ C ^ D
                f = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                # 0x251f-0x2548:
                # f = (~D | B) ^ C
                f = ((~D & 0xFFFFFFFF) | B) ^ C
                g = (7 * i) % 16
            
            # 0x254b-0x2575: f += A + K[i] + M[g]
            # Actually from disasm:
            # edx = K[i]         (0x2558-0x255f)
            # edx += A           (0x2562-0x2565: edx += [rbp-0x38])
            # eax = M[g]         (0x2567-0x256c)
            # eax += edx         (0x2573: add eax, edx)
            # f += eax           (0x2575: add [rbp-0x4c], eax)
            f = u32(f + A + K[i] + M[g])
            
            # 0x2578-0x2587: Rotate A,B,C,D
            # A_new = D  ([rbp-0x38] = [rbp-0x44])
            # D_new = C  ([rbp-0x44] = [rbp-0x40])
            # C_new = B  ([rbp-0x40] = [rbp-0x3c])
            A_new = D
            D_new = C
            C_new = B
            
            # 0x258a-0x25aa: B = B + rol(f, S[i])
            # [rbp-0x3c] += rol(f, S[i])
            B_new = u32(B + rol32(f, S[i]))
            
            A = A_new
            B = B_new
            C = C_new
            D = D_new
        
        # 0x25bb-0x25d0:
        # h0 += A  ([rbp-0x14] += [rbp-0x38])
        # h1 += B  ([rbp-0x18] += [rbp-0x3c])
        # h2 += C  ([rbp-0x1c] += [rbp-0x40])
        # h3 += D  ([rbp-0x20] += [rbp-0x44])
        h0 = u32(h0 + A)
        h1 = u32(h1 + B)
        h2 = u32(h2 + C)
        h3 = u32(h3 + D)
        
        offset += 64
    
    # Output formatting from disasm (0x2626-0x26a8):
    # For each of the 4 words, output in BIG-ENDIAN order:
    # snprintf(buf+i*8, 9, "%02x%02x%02x%02x", byte0, byte1, byte2, byte3)
    # Where byte0=word&0xFF, byte1=(word>>8)&0xFF, byte2=(word>>16)&0xFF, byte3=(word>>24)&0xFF
    # Wait - from the disasm args to snprintf:
    # rcx = byte0 (LSB), r8d = byte1, r9d = byte2, stack = byte3 (MSB)
    # format: "%02x%02x%02x%02x" => prints byte0, byte1, byte2, byte3
    # THIS IS LITTLE-ENDIAN OUTPUT (LSB first)
    
    # Actually wait let me re-read:
    # 0x2632: shr eax, 0x18  -> byte3 (MSB) -> eventually pushed to stack (7th arg)
    # But wait, at 0x2635: mov edx, eax - edx = byte3
    # Then later at 0x2684: push rdx - pushes byte3 as 7th arg
    # BUT between 0x2635 and 0x2684, many other instructions modify edx.
    # Let me trace more carefully...
    #
    # Actually, I realize the format string args for snprintf are:
    # arg1(rdi)=buf, arg2(esi)=9, arg3(rdx)=fmt, arg4(ecx)=val1, arg5(r8d)=val2, arg6(r9d)=val3, arg7(stack)=val4
    #
    # 0x2632: shr eax,0x18 -> MSB, mov edx,eax -> edx=MSB (will become arg7 on stack)
    # 0x2646: movzx r9d, al (after shr eax,0x10) -> r9d=byte2 (arg6)
    # 0x2659: movzx r8d, al (after shr eax,8) -> r8d=byte1 (arg5) 
    # 0x2669: movzx eax, al (just low byte) -> byte0=LSB
    # 0x2685: mov ecx, eax -> ecx=byte0 (arg4, first %02x)
    #
    # So format prints: byte0(LSB), byte1, byte2, byte3(MSB) = little-endian
    
    result = ""
    for word in [h0, h1, h2, h3]:
        b0 = word & 0xFF
        b1 = (word >> 8) & 0xFF
        b2 = (word >> 16) & 0xFF
        b3 = (word >> 24) & 0xFF
        result += "%02x%02x%02x%02x" % (b0, b1, b2, b3)
    
    return result

# Also compute standard MD5 for comparison
import hashlib

input_str = b"C:\\Users\\OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\\Desktop\\local.txt"
print(f"Input: {input_str}")
print(f"Custom MD5: {custom_md5(input_str)}")
print(f"Stdlib MD5: {hashlib.md5(input_str).hexdigest()}")

# Also try just the fake flag
input2 = b"OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}"
print(f"\nInput: {input2}")
print(f"Custom MD5: {custom_md5(input2)}")
print(f"Stdlib MD5: {hashlib.md5(input2).hexdigest()}")
