import socket
import json
import base64
import struct

def rotate_left_3_bits(buf):
    temp = buf[0] >> 5
    new_buf = [0] * 25
    for i in range(24):
        new_buf[i] = ((buf[i] << 3) | (buf[i+1] >> 5)) & 0xFF
    new_buf[24] = ((buf[24] << 3) | temp) & 0xFF
    return new_buf

def decrypt_with_key(ciphertext, nonce_bytes, key):
    derived_key = list(key)
    for j in range(8):
        derived_key = rotate_left_3_bits(derived_key)
        for i in range(25):
            derived_key[i] ^= nonce_bytes[j]
            
    seed = struct.unpack("<I", bytes(derived_key[:4]))[0] & 0x7FFFFFFF
    
    state = seed
    keystream = []
    for _ in range(len(ciphertext)):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        keystream.append(state & 0xFF)
        
    decrypted = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    return decrypted

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("lockbox.appsecmy.com", 9999))
        s.sendall(b"GET_CHALLENGE")
        resp = s.recv(4096).decode('utf-8')
    finally:
        s.close()
    
    data = json.loads(resp)
    nonce_bytes = bytes.fromhex(data["nonce"])
    ciphertext = base64.b64decode(data["encrypted_flag"])
    
    # Try Key 1: s3cr3t_k3y_g1v3n_by_AE13\x00
    key1 = b"s3cr3t_k3y_g1v3n_by_AE13\x00"
    dec1 = decrypt_with_key(ciphertext, nonce_bytes, key1)
    print("Decrypted with Key 1:", dec1)
    
    # Try Key 2: XORed with 0xAA
    key2 = bytes([b ^ 0xAA for b in key1])
    dec2 = decrypt_with_key(ciphertext, nonce_bytes, key2)
    print("Decrypted with Key 2:", dec2)

if __name__ == '__main__':
    solve()
