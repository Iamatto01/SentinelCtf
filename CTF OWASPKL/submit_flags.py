import urllib.request
import json
import ssl
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TOKEN = 'Token ctfd_5da567db699924d02e475c9bd28c52fe9259d8bc2be99cb19e3c15ddce1abc44'
USER_AGENT = 'Mozilla/5.0'

def submit_flag(chal_id, flag):
    req = urllib.request.Request('https://ligactfstudent.appsecmy.com/api/v1/challenges/attempt')
    req.add_header('Authorization', TOKEN)
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', USER_AGENT)
    
    data = json.dumps({'challenge_id': chal_id, 'submission': flag}).encode('utf-8')
    
    try:
        response = urllib.request.urlopen(req, data=data, context=ctx)
        result = json.loads(response.read().decode('utf-8'))
        print(f"Submitting '{flag}' -> {result.get('data', {}).get('message', result)}")
        return result
    except Exception as e:
        print(f"Error submitting '{flag}': {e}")
        return None

# Try Detonate2 flags (ID: 9)
candidates = [
    'OWASPKL{4b0ee28588b86f2aed13acd06754470c}',
    'OWASPKL{c6e2147faff18086604a512075e466da}',
    '4b0ee28588b86f2aed13acd06754470c',
    'OWASPKL{85e20e4b2a6fb888d0ac13ed0c475467}'
]

print("=== Submitting Detonate2 Flags ===")
for c in candidates:
    res = submit_flag(9, c)
    if res and res.get('data', {}).get('status') == 'correct':
        print('SUCCESS!!!')
        break
