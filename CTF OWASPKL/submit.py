import requests, re
s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text).group(1)
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data={'name': 'muhammadsaifudinmj@gmail.com', 'password': 'd405d90a80e8d8313cd0f9ad0025969d', 'nonce': nonce, '_submit': 'Submit'})
csrf_match = re.search(r'csrfNonce[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]', r2.text)
csrf_token = csrf_match.group(1)
headers = {'CSRF-Token': csrf_token, 'Content-Type': 'application/json'}

def submit(chal_id, flag):
    r3 = s.post('https://ligactfstudent.appsecmy.com/api/v1/challenges/attempt', headers=headers, json={'challenge_id': chal_id, 'submission': flag})
    print(flag, r3.json())

c2s = ['sliver', 'Sliver', 'cobaltstrike', 'CobaltStrike', 'covenant', 'merlin', 'havoc', 'mythic', 'brute ratel', 'nighthawk', 'shad0w', 'empire']
for c2 in c2s:
    submit(15, f'OWASPKL{{{c2}}}')
