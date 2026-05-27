import requests
import re
import os

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
            if not c.get('solved_by_me'):
                cid = c.get('id')
                name = c.get('name')
                print(f"Fetching details for unsolved challenge: {name} (ID: {cid})")
                r_detail = s.get(f'https://ligactfstudent.appsecmy.com/api/v1/challenges/{cid}', headers=headers)
                if r_detail.status_code == 200:
                    detail = r_detail.json().get('data', {})
                    files = detail.get('files', [])
                    
                    target_dir = f"f:/ctf/CFT OWASP/Question/{name.replace('/', '_').replace(':', '_')}"
                    os.makedirs(target_dir, exist_ok=True)
                    
                    with open(f"{target_dir}/description.txt", 'w', encoding='utf-8') as f:
                        f.write(detail.get('description', ''))
                    
                    for file_path in files:
                        file_url = f"https://ligactfstudent.appsecmy.com{file_path}"
                        fname = file_path.split('/')[-1].split('?')[0]
                        print(f"  Downloading {fname}")
                        r_file = s.get(file_url)
                        with open(f"{target_dir}/{fname}", 'wb') as f:
                            f.write(r_file.content)
                else:
                    print(f"Failed to fetch {cid}")
    else:
        print('Could not fetch API. Status:', r_chals.status_code)
else:
    print('Login failed.')
