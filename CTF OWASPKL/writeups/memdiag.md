# memdiag.ai - Writeup

## Challenge Description
During an endpoint crash response, an AI assistant provided a confident analysis of `host_memdiag`, claiming it to be a benign utility with a format-string vulnerability. We are tasked with proving whether the AI can be trusted by reversing the sample and recovering the hidden operator note. 

The tip explicitly warns us: "Treat the AI analysis report as evidence for interpretation, not as ground truth — the disassembly is the source of truth."

## Solution Steps

### 1. Initial Analysis
We begin by analyzing the `host_memdiag` binary. It's a 64-bit ELF executable. The AI report claims several things, such as an argument-gated branch (`memdiag-override`) and a format-string vulnerability in logging.

### 2. Reversing the Binary
By disassembling the binary (using tools like `radare2` or Python's `capstone`), we locate `main` and map out the control flow:
- The program checks `argc`. If arguments are passed, it expects `argv[2]` to equal `0xdeadc0de`.
- If the argument check passes, it hashes `argv[1]` using a custom rolling hash (`hash = hash * 0x83 + c`) and compares it against `0xa15ded69`.
- Calculating the hash of `memdiag-override` yields exactly `0xa15ded69`. This means the AI was at least correct about the override token.

### 3. Decrypting the Payloads
Upon exploring the functions, we notice several string decryption routines that the AI flagged as "isolated helper routines." These actually decode to:
1. `LIGA{f4k3_fl4g!h4h4}`
2. `LIGA{us3_ur_r34l_sk1ll_1f_ur_4_r34l_pl4y3r}`
3. `LIGA{s0lv3_w1th_ur_0wn_sk1ll_n0t_4I}`

These are all fake flags teasing us for relying on the AI. The AI's claim about a format-string vulnerability was a complete hallucination—the `printf` statements use hardcoded format strings correctly.

### 4. Extracting the Operator Note
If the correct arguments (`memdiag-override` and `0xdeadc0de`) are provided, and no debugger is detected (via a `ptrace` and timing check), the program writes a file named `./memdiag_dump.bmp`.
The contents of this file are decrypted using a 16-byte XOR key from the `.rodata` section.

If we manually extract and decrypt the 90-byte BMP blob using the XOR key, we get a valid Windows Bitmap file. The BMP header specifies an image width of 12 and a height of 1 (a 12x1 pixel image). 
The 36 bytes of pixel data decrypts to:
`AWOKPSt{L5urn_t4_0t_I5ury_tru0y3_}s3`

### 5. Decoding the BMP Pixel Data
In the BMP file format, 24-bit RGB pixel data is stored in **BGR (Blue, Green, Red)** order.
If we reverse every 3-byte chunk (representing one pixel) in the string:
- `A W O` -> `O W A`
- `K P S` -> `S P K`
- `t { L` -> `L { t`
- `5 u r` -> `r u 5`
- `n _ t` -> `t _ n`
- `4 _ 0` -> `0 _ 4`
- `t _ I` -> `I _ t`
- `5 u r` -> `r u 5`
- `y _ t` -> `t _ y`
- `r u 0` -> `0 u r`
- `y 3 _` -> `_ 3 y`
- `} s 3` -> `3 s }`

Concatenating the reversed chunks, we get the true hidden operator note:
`OWASPKL{tru5t_n0_4I_tru5t_y0ur_3y3s}`

## Flag
`OWASPKL{tru5t_n0_4I_tru5t_y0ur_3y3s}`
