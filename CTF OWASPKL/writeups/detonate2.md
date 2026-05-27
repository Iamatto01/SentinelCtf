# Detonate2 - Writeup

## Challenge Description
"In malware analysis, you can either statically analyze the assembly codes directly, or you can create a snapshot of your sandbox and detonate it inside. Straight up reverse this file, and you will find the flag. You may start by debugging it via IDA or Ghidra."

## Static Analysis Process

1. We are given an ELF executable `detonate2.exe`. Since it's a Linux ELF binary, it won't run natively on Windows without WSL or an emulator. 
2. Running a strings extraction over the binary reveals several interesting strings:
   - `OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}`
   - `Desktop`
   - `local.txt`
   - `Users`
   - `File not found. Keep looking...`
   - `Here is the flag: OWASPKL{`

3. Reversing the `.rodata` and examining the disassembly (specifically the `check_flag` function), we see the program checks for the existence of a specific file on the system using `stat()`. The exact path it checks is:
   `C:\Users\OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt`
   
4. If the file exists in the sandbox environment, the binary proceeds to generate the real flag. It achieves this by calculating the MD5 hash of the file path string itself!
   - The MD5 hashing routine uses standard initialization constants (`0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`), indicating it's an unmodified MD5 algorithm.
   - The string `C:\Users\OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt` hashed with MD5 results in `4b0ee28588b86f2aed13acd06754470c`.
   
5. Finally, the program prints the MD5 hash formatted as hex inside the `OWASPKL{}` wrapper:
   `Here is the flag: OWASPKL{4b0ee28588b86f2aed13acd06754470c}`

## Flag
`OWASPKL{4b0ee28588b86f2aed13acd06754470c}`
