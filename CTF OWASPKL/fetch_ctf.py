import urllib.request
import urllib.parse
import http.cookiejar
import json
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))
urllib.request.install_opener(opener)

try:
    print('Fetching login page...')
    req = urllib.request.Request('https://ligactfstudent.appsecmy.com/login')
    resp = urllib.request.urlopen(req)
    html = resp.read().decode('utf-8')
    
    match = re.search(r'name="nonce" type="hidden" value="([^"]+)"', html)
    if match:
        nonce = match.group(1)
        print(f'Found nonce: {nonce}')
    else:
        nonce = ''
        print('No nonce found!')
    
    print('Attempting login...')
    login_data = urllib.parse.urlencode({
        'name': 'muhammadsaifudinmj@gmail.com',
        'password': 'd405d90a80e8d8313cd0f9ad0025969d',
        'nonce': nonce,
        '_submit': 'Submit'
    }).encode('utf-8')
    
    req = urllib.request.Request('https://ligactfstudent.appsecmy.com/login', data=login_data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    resp = urllib.request.urlopen(req)
    
    print(f'Login response code: {resp.getcode()}')
    
    print('Fetching challenges list...')
    req = urllib.request.Request('https://ligactfstudent.appsecmy.com/api/v1/challenges')
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode('utf-8'))
    
    with open('challenges.json', 'w') as f:
        json.dump(data, f, indent=2)
        
    if 'data' in data:
        print('\n--- UNSOLVED CHALLENGES ---')
        for chal in data['data']:
            if not chal.get('solved_by_me', False):
                print(f"ID: {chal.get('id')}, Name: {chal.get('name')}, Category: {chal.get('category')}")
                
        # Let's also fetch the specific details for the unsolved challenges
        print('\n--- UNSOLVED CHALLENGE DETAILS ---')
        for chal in data['data']:
            if not chal.get('solved_by_me', False):
                chal_id = chal.get('id')
                req_details = urllib.request.Request(f'https://ligactfstudent.appsecmy.com/api/v1/challenges/{chal_id}')
                resp_details = urllib.request.urlopen(req_details)
                chal_details = json.loads(resp_details.read().decode('utf-8'))
                
                with open(f'challenge_{chal_id}.json', 'w') as f:
                    json.dump(chal_details, f, indent=2)
                
                name = chal_details.get('data', {}).get('name', 'Unknown')
                desc = chal_details.get('data', {}).get('description', '')
                print(f'\n--- {name} ---')
                print(desc[:500] + ('...' if len(desc) > 500 else ''))
                
except Exception as e:
    print(f'Error: {e}')
