# Lockbox - Writeup

## Challenge Description
The challenge provides a binary `lockbox` and a `friend_note.txt`. The note explains that the binary contains a secret message protected by THREE layers:
1. ROT13
2. Reversed string
3. Split into separate pieces scattered across memory

The friend claims the only way to get the message is by providing a 64-character HMAC key using `--unlock <code>`. Our goal is to prove them wrong using static analysis.

## Solution Steps

### 1. Static Analysis
Running `strings` on the binary reveals several strange, capitalized strings that look like they could be obfuscated flag fragments:
- `}LM33HD5`
- `_A0Z3Y_3`
- `1G0E_mCm`
- `3{YXCFNJ`

### 2. Finding the Assembly Instructions
By dumping the hex of the binary around these strings, we can see exactly how they are loaded into memory:
```assembly
48 b8 7d 4c 4d 33 33 48 44 35    mov rax, 0x35444833334d4c7d  // "}LM33HD5"
48 89 44 24 30                   mov [rsp+0x30], rax
48 b8 5f 41 30 5a 33 59 5f 33    mov rax, 0x335f59335a30415f  // "_A0Z3Y_3"
48 89 44 24 38                   mov [rsp+0x38], rax
48 b8 31 47 30 45 5f 6d 43 6d    mov rax, 0x6d436d5f45304731  // "1G0E_mCm"
48 89 44 24 40                   mov [rsp+0x40], rax
48 b8 33 7b 59 58 43 46 4e 4a    mov rax, 0x4a4e464358597b33  // "3{YXCFNJ"
48 89 44 24 48                   mov [rsp+0x48], rax
c6 44 24 50 42                   mov byte ptr [rsp+0x50], 0x42 // "B"
```

The pieces are loaded sequentially onto the stack. Because x86-64 is little-endian, the immediate values are stored exactly as they appear in the strings output.

### 3. Reversing the Layers of Protection
If we concatenate the memory blocks sequentially, we get:
`}LM33HD5_A0Z3Y_31G0E_mCm3{YXCFNJB`

To bypass the author's protections, we just perform the reverse operations:
1. **Reverse the string**: `B J N F C X Y { 3 m C m _ E 0 G 1 3 _ Y 3 Z 0 A _ 5 D H 3 3 M L }`
2. **Apply ROT13**: `O W A S P K L { 3 z P z _ R 0 T 1 3 _ L 3 M 0 N _ 5 Q U 3 3 Z Y }`

The resulting string perfectly translates into leetspeak for "ezpz_ROT13_LEMON_SQUEEZY", meaning our recovery was completely successful.

## Flag
`OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}`
