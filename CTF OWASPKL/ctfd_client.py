import requests
import re

s = requests.Session()
r = s.get('https://ligactfstudent.appsecmy.com/login')
nonce_match = re.search(r'name="nonce" type="hidden" value="([^"]+)"', r.text)
nonce = nonce_match.group(1) if nonce_match else ''

data = {
    'name': 'muhammadsaifudinmj@gmail.com', 
    'password': 'd405d90a80e8d8313cd0f9ad0025969d', 
    'nonce': nonce,
    '_submit': 'Submit'
}
r2 = s.post('https://ligactfstudent.appsecmy.com/login', data=data)

if 'muhammadsaifudinmj@gmail.com' in r2.text or 'Profile' in r2.text or '/logout' in r2.text:
    print('Login successful!')
    
    # Extract CSRF token from meta tags for the API requests
    csrf_token = ''
    token_match = re.search(r'csrfNonce": "([^"]+)"', r2.text)
    if token_match:
        csrf_token = token_match.group(1)
    
    headers = {}
    if csrf_token:
        headers['CSRF-Token'] = csrf_token

    r_chals = s.get('https://ligactfstudent.appsecmy.com/api/v1/challenges', headers=headers)
    if r_chals.status_code == 200:
        chals = r_chals.json().get('data', [])
        for c in chals:
            solved = 'x' if c.get('solved_by_me') else ' '
            cat = c.get('category')
            name = c.get('name')
            cid = c.get('id')
            print(f"[{solved}] {cat} - {name} (ID: {cid})")
    else:
        print('Could not fetch API. Status:', r_chals.status_code)
else:
    print('Login failed.')
    if '<title>' in r2.text:
        print('Title after login:', re.search(r'<title>(.*?)</title>', r2.text).group(1))
