import hashlib, re

filepath = b'C:\x5cUsers\x5cOWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\x5cDesktop\x5clocal.txt'
h = hashlib.md5(filepath)
print(f'filepath: {filepath}')
print(f'md5: {h.hexdigest()}')
flag = 'OWASPKL{' + h.hexdigest() + '}'
print(f'flag: {flag}')
print(f'flag length: {len(flag)}')

# Search for any other paths or hidden strings
data = open('detonate2.exe', 'rb').read()
paths = [m.group() for m in re.finditer(rb'C:\\[^\x00]+', data)]
for p in paths:
    print(f'Found path: {p}')

# Maybe the flag is the md5 hash of the EXE file itself?
h2 = hashlib.md5(data)
print(f'\nMD5 of binary: {h2.hexdigest()}')
print(f'Flag with binary md5: OWASPKL{{{h2.hexdigest()}}}')

# Or sha256?
import hashlib
h3 = hashlib.sha256(data)
print(f'SHA256 of binary: {h3.hexdigest()}')
