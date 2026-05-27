# unpackme1 - Writeup

## Challenge Description
Identify the packer used for this binary, and unpack it. A simple anti-unpacking technique was applied to this packed binary. The flag is hidden in the unpacked file as a string. Format: `OWASPKL{Im_A_Flag}`

## Solution Steps

### 1. Initial Analysis
First, we analyze the binary to figure out what type of file it is. By checking the header, we can see that it's a 64-bit ELF Linux executable. 
Running strings or checking the binary for common packer signatures reveals the presence of `UPX!`.

### 2. Identifying the Anti-Unpacking Technique
When we attempt to unpack the binary using the standard UPX tool (`upx -d unpackme1`), we encounter an error:
`upx: unpackme1: NotPackedException: not packed by UPX`

Upon closer inspection of the binary using string analysis (or a hex editor), we find multiple occurrences of `VQY ` and `VQY!`. 
Comparing this to a standard UPX packed binary (which contains `UPX!`, `UPX0`, `UPX1`), we realize that the letters have been shifted by 1 character:
- U -> V
- P -> Q
- X -> Y

The anti-unpacking technique is simply corrupting the UPX magic bytes by shifting them to `VQY`.

### 3. Patching the Binary
To fix the binary so that the UPX tool can recognize it again, we just need to replace all instances of `VQY` with `UPX`. This can be done with a simple python script:

```python
# Read the corrupted packed binary
with open('unpackme1', 'rb') as f:
    data = f.read()

# Patch the magic bytes back to UPX
data = data.replace(b'VQY', b'UPX')

# Save the patched binary
with open('patched_unpackme1', 'wb') as f:
    f.write(data)
```

### 4. Unpacking
Now we can use the standard UPX tool to decompress the patched binary:
```bash
upx -d patched_unpackme1
```
This successfully restores the decompressed ELF binary.

### 5. Extracting the Flag
Finally, we search the decompressed binary for strings matching the flag format `OWASPKL{}`.
Running a regex search on the unpacked binary yields the actual flag:

```bash
python -c "import re; print(re.findall(b'OWASPKL\{[^}]+\}', open('patched_unpackme1', 'rb').read()))"
```

## Flag
`OWASPKL{Unpackm3_4mat3ur0923257}`
