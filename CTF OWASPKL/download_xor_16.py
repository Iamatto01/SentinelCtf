import requests, re
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})

csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
csrf_token = csrf_match.group(1)
r_detail = s.get('https://ligactfstudent.appsecmy.com/api/v1/challenges/16', headers={'CSRF-Token': csrf_token})
file_url = f"https://ligactfstudent.appsecmy.com{r_detail.json()['data']['files'][0]}"
print('Downloading Challenge 16 malware...')
data = s.get(file_url).content

print(f'Downloaded {len(data)} bytes')

# XOR with 0x42
xored = bytearray(b ^ 0x42 for b in data)
with open('f:/ctf/CFT OWASP/malware16.xor', 'wb') as f:
    f.write(xored)
print('Saved malware16.xor')
