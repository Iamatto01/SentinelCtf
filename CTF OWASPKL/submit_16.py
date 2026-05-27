import requests, re
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})
csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
csrf_token = csrf_match.group(1)
headers = {'CSRF-Token': csrf_token, 'Content-Type': 'application/json'}

r3 = s.post('https://ligactfstudent.appsecmy.com/api/v1/challenges/attempt', headers=headers, json={'challenge_id': 16, 'submission': 'OWASPKL{192.168.91.243}'})
print(r3.json())
