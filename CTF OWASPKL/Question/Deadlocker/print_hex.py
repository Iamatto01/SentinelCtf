with open('Deadlocker', 'rb') as f:
    f.seek(0x11d0)
    data = f.read(32)
    print("Bytes:", data.hex())
