import subprocess
import psutil
import time
import os

print('Starting safe.exe...')
p = subprocess.Popen(['f:/ctf/CFT OWASP/safe.exe'])

found = False
print(f'Started with PID {p.pid}. Monitoring network connections...')
for i in range(100):
    try:
        proc = psutil.Process(p.pid)
        conns = proc.connections(kind='inet')
        for c in conns:
            if c.status == 'SYN_SENT' or c.status == 'ESTABLISHED' or c.status == 'NONE' or c.status:
                print(f'Found connection: {c.raddr}')
                if c.raddr:
                    found = True
                    break
    except Exception as e:
        pass
        
    if found:
        break
    time.sleep(0.1)

if not found:
    print('No connections found. Maybe checking globally...')
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'SYN_SENT':
            print(f'Global SYN_SENT: {c.raddr} by PID {c.pid}')

p.kill()
print('Done.')
