import requests, re
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})

csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
csrf_token = csrf_match.group(1)
r_detail = s.get('https://ligactfstudent.appsecmy.com/api/v1/challenges/15', headers={'CSRF-Token': csrf_token})
file_url = f"https://ligactfstudent.appsecmy.com{r_detail.json()['data']['files'][0]}"
data = s.get(file_url).content

print('Length:', len(data))
if b'Go build' in data: print('Go build')
if b'Go cmd' in data: print('Go cmd')
if b'go1.' in data: print('go1.xxx')

print('sliver:', data.lower().count(b'sliver'))
print('sliverpb:', data.lower().count(b'sliverpb'))
print('havoc:', data.lower().count(b'havoc'))
print('merlin:', data.lower().count(b'merlin'))

ips = re.findall(rb'192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}', data)
print('IPs:', set(ips))

urls = re.findall(rb'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9_.-]+)*', data)
print('URLs count:', len(urls))
print('Sample URLs:', list(set(urls))[:10])
