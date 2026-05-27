import subprocess
import psutil
import time

print('Starting safe2.exe...')
p = subprocess.Popen(['f:/ctf/CFT OWASP/safe2.exe'])

found = False
print(f'Started with PID {p.pid}. Monitoring network connections...')
for i in range(100):
    try:
        proc = psutil.Process(p.pid)
        conns = proc.connections(kind='inet')
        for c in conns:
            if c.raddr:
                print(f'Found connection: {c.raddr}')
                found = True
                break
    except Exception as e:
        pass
        
    if found:
        break
    time.sleep(0.1)

if not found:
    print('No connections found from process. Global check...')
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'SYN_SENT':
            print(f'Global SYN_SENT: {c.raddr} by PID {c.pid}')

try:
    p.kill()
except:
    pass
print('Done.')
