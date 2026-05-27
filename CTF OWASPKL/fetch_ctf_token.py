import urllib.request
import urllib.parse
import json
import ssl

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
    print('Fetching challenges list...')
    data = make_request('https://ligactfstudent.appsecmy.com/api/v1/challenges')
    
    with open('challenges.json', 'w') as f:
        json.dump(data, f, indent=2)
        
    if 'data' in data:
        print('\n--- UNSOLVED CHALLENGES ---')
        unsolved_ids = []
        for chal in data['data']:
            if not chal.get('solved_by_me', False):
                print(f"ID: {chal.get('id')}, Name: {chal.get('name')}, Category: {chal.get('category')}")
                unsolved_ids.append(chal.get('id'))
                
        print('\n--- UNSOLVED CHALLENGE DETAILS ---')
        for chal_id in unsolved_ids:
            chal_details = make_request(f'https://ligactfstudent.appsecmy.com/api/v1/challenges/{chal_id}')
            
            with open(f'challenge_{chal_id}.json', 'w') as f:
                json.dump(chal_details, f, indent=2)
            
            name = chal_details.get('data', {}).get('name', 'Unknown')
            desc = chal_details.get('data', {}).get('description', '')
            print(f'\n=== {name} (ID: {chal_id}) ===')
            print(desc)
            
            # Print files if any
            files = chal_details.get('data', {}).get('files', [])
            if files:
                print('\nFiles:')
                for f in files:
                    print(f"  - {f}")
            
except Exception as e:
    print(f'Error: {e}')
