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

print('Extracting github modules...')
github_urls = set(re.findall(rb'github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', data))
for u in sorted(github_urls):
    print(u.decode())
    
print('Extracting IP addresses (including Unicode/UTF-16)...')
# We could look for 192.168.x.x, 10.x.x.x, 172.x.x.x
# Or literally anything http://
for url in set(re.findall(rb'https?://[a-zA-Z0-9.-]+(?:[:0-9]+)?(?:/[a-zA-Z0-9_.-]+)*', data)):
    if len(url) < 100:
        print('URL:', url.decode())
        
for url16 in set(re.findall(rb'h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:[a-zA-Z0-9.-]\x00)+(?:[:0-9]\x00)*(?:/\x00(?:[a-zA-Z0-9_.-]\x00)+)*', data)):
    if len(url16) < 200:
        print('URL16:', url16.decode('utf-16le'))

# Print all 192, 10, 172 IPs
for ip in set(re.findall(rb'(?:192|10|172)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', data)):
    print('IP:', ip.decode())
