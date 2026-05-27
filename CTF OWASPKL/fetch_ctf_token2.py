import urllib.request
import urllib.parse
import json
import ssl
import sys

# Change console encoding to UTF-8
sys.stdout.reconfigure(encoding='utf-8')

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TOKEN = 'Token ctfd_5da567db699924d02e475c9bd28c52fe9259d8bc2be99cb19e3c15ddce1abc44'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

def make_request(url):
    req = urllib.request.Request(url)
    req.add_header('Authorization', TOKEN)
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', USER_AGENT)
    
    response = urllib.request.urlopen(req, context=ctx)
    return json.loads(response.read().decode('utf-8'))

try:
    data = make_request('https://ligactfstudent.appsecmy.com/api/v1/challenges')
    
    if 'data' in data:
        unsolved_ids = []
        for chal in data['data']:
            if not chal.get('solved_by_me', False):
                unsolved_ids.append(chal.get('id'))
                
        for chal_id in unsolved_ids:
            chal_details = make_request(f'https://ligactfstudent.appsecmy.com/api/v1/challenges/{chal_id}')
            
            name = chal_details.get('data', {}).get('name', 'Unknown')
            desc = chal_details.get('data', {}).get('description', '')
            print(f'\n=== {name} (ID: {chal_id}) ===')
            print(desc)
            
            files = chal_details.get('data', {}).get('files', [])
            if files:
                print('\nFiles:')
                for f in files:
                    print(f"  - {f}")
            print("\n" + "-"*50)
            
except Exception as e:
    print(f'Error: {e}')
