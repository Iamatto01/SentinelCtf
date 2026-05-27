import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("lockbox.appsecmy.com", 9999))
    print("Connected!")
    s.sendall(b"GET_CHALLENGE")
    resp = s.recv(4096)
    print("Response:", resp)
except Exception as e:
    print("Error:", e)
finally:
    s.close()
