import requests, re
import io
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})

csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
csrf_token = csrf_match.group(1)
r_detail = s.get('https://ligactfstudent.appsecmy.com/api/v1/challenges/15', headers={'CSRF-Token': csrf_token})
file_url = f"https://ligactfstudent.appsecmy.com{r_detail.json()['data']['files'][0]}"
data = s.get(file_url).content

try:
    import pefile
    pe = pefile.PE(data=data)
    print("PE parsed successfully!")
    print("Compiler/Packer strings in sections:")
    for section in pe.sections:
        print(f"Section {section.Name.decode('utf-8', 'ignore')} size {section.SizeOfRawData}")
        if b'UPX' in section.Name:
            print("UPX detected")
except Exception as e:
    print("Not a valid PE or pefile not installed:", e)

print('Looking for other C2 names...')
print('mythic:', b'mythic' in data.lower())
print('poseidon:', b'poseidon' in data.lower())
print('villain:', b'villain' in data.lower())
print('shad0w:', b'shad0w' in data.lower())
print('bishopfox:', b'bishopfox' in data.lower())

# Check for go build id
m = re.search(rb'Go build ID: "([^"]+)"', data)
if m:
    print("Go Build ID:", m.group(1).decode())
else:
    print("No Go Build ID")
