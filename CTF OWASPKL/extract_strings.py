import re

with open('f:/ctf/CFT OWASP/malware.xor', 'rb') as f:
    xored = f.read()

data = bytearray(b ^ 0x42 for b in xored)

strings = re.findall(b'[\x20-\x7e]{8,}', data)
with open('f:/ctf/CFT OWASP/strings.txt', 'w', encoding='utf-8') as f:
    for s in strings:
        f.write(s.decode('ascii', errors='ignore') + '\n')
print(f'Extracted {len(strings)} strings to strings.txt')
