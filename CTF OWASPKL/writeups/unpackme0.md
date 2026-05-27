# unpackme0 - Writeup

## Challenge Description
Identify the packer used for this binary, and unpack it. Provide the md5 hash of the unpacked file as your flag. Example: `OWASPKL{23ac7b66851387b96a20672b5c0dc856}`

## Solution Steps

### 1. Identifying the Packer
By running standard tools such as `strings` or analyzing the binary headers, we can quickly spot the `UPX!` magic bytes. This indicates that the executable has been packed with the UPX packer.

### 2. Unpacking the Binary
Since this is the "easy" version of the challenge without any anti-unpacking techniques applied, we can simply run the standard UPX tool to decompress the binary:
```bash
upx -d unpackme0
```

### 3. Getting the Flag
The challenge states that the flag is the MD5 hash of the unpacked file.
We can compute the MD5 hash using `md5sum` (Linux) or `Get-FileHash` (PowerShell):
```bash
Get-FileHash -Algorithm MD5 unpackme0
```
This yields the hash: `1cc6a3b62cac36ab18e0c4685a7f4bdf`.

## Flag
`OWASPKL{1cc6a3b62cac36ab18e0c4685a7f4bdf}`
