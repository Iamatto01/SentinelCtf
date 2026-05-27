# unpackme2 - Writeup

## Challenge Description
Identify the packer used for this binary, and unpack it. The flag for this challenge is made up of two parts: The name of the packer (in all caps), and the flag string in the binary. The flag string is a string in l33tspeak hidden in the program. The two parts are separated with an underscore.

Format: `OWASPKL{[PACKERNAME]_[EXAMPLEFLAG]}`

## Solution Steps

### 1. Identifying the Packer
Running `strings` or analyzing the `.exe` sections reveals a section named `.aspack`, and strings like `aspack` are clearly visible. This immediately tells us that the binary is packed using **ASPack**.
Therefore, the first part of our flag is `ASPACK`.

### 2. Unpacking the Binary
Instead of statically unpacking the binary, which can be tedious due to ASPack's section compression and IAT (Import Address Table) destruction, we can perform **dynamic unpacking** (the "hard way").

Since the process unpacks itself into memory before running, we can write a python script using the `ctypes` library to launch the process and dump its memory.
To prevent the process from terminating before we can dump its memory, we can use an API hooking technique:
1. Start the process in a `CREATE_SUSPENDED` state.
2. Hook the `kernel32.dll!ExitProcess` and `ntdll.dll!NtTerminateProcess` functions by overwriting their first bytes with an infinite loop (`EB FE` in hex).
3. Resume the thread. The process will unpack itself, run, and when it eventually tries to exit, it will hit the infinite loop and hang forever.
4. Once it hangs, we iterate through its memory regions using `VirtualQueryEx` and dump all committed memory to a file (`dump.bin`).

### 3. Extracting the Flag
With the memory dumped, we now have the fully unpacked strings. 
The challenge states that the flag is a hidden l33tspeak string. We can search the dumped memory for common l33tspeak patterns (e.g. searching for alphanumeric strings containing words like `m3`, `l33t`, `pwn`, etc.).

Running a quick python regex search:
```python
import re
data = open('dump.bin', 'rb').read()
strings = re.findall(b'[a-zA-Z0-9_!]{6,}', data)
# Filter strings containing 'm3'
print([s for s in set(strings) if b'm3' in s.lower()])
```

Among the output, we spot the string `Unpackm3C0mpl3te`. This matches the description perfectly.

## Flag
Combining the packer name and the l33tspeak string:
`OWASPKL{ASPACK_Unpackm3C0mpl3te}`
