import requests, re
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})

csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
if not csrf_match:
    print('Failed to find csrf token. Dumping text:')
    print(r2.text[:500])
    exit(1)
csrf_token = csrf_match.group(1)
r_detail = s.get('https://ligactfstudent.appsecmy.com/api/v1/challenges/15', headers={'CSRF-Token': csrf_token})
file_url = f"https://ligactfstudent.appsecmy.com{r_detail.json()['data']['files'][0]}"
data = s.get(file_url).content

if b'PyInstaller' in data or b'_MEI' in data: print('Type: PyInstaller')
elif b'Go build' in data or b'Go cmd' in data or b'go1.' in data: print('Type: Go')
elif b'Rust' in data or b'cargo' in data: print('Type: Rust')
elif b'sliver' in data.lower(): print('Type: Sliver?')
elif b'covenant' in data.lower(): print('Type: Covenant?')
else: print('Unknown Type')

for match in re.findall(rb'\b(?:10|172|192)\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b', data):
    print('Private IP:', match.decode())

print('Looking for common c2 names...')
c2s = [b'cobaltstrike', b'covenant', b'sliver', b'mythic', b'empire', b'meterpreter', b'poshc2', b'havoc', b'brute ratel', b'merlin', b'shad0w']
for fw in c2s:
    if fw in data.lower():
        print('Found:', fw.decode())
        
for match in re.findall(rb'(?:1\x000\x00|1\x007\x002\x00|1\x009\x002\x00)\.\x00(?:[0-9]\x00){1,3}\.\x00(?:[0-9]\x00){1,3}\.\x00(?:[0-9]\x00){1,3}', data):
    print('Private IP (UTF-16):', match.decode('utf-16le'))
    
for p in [b'api/v1', b'login', b'admin', b'profile']:
    if p in data:
        pass
