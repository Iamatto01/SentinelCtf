with open('Deadlocker', 'rb') as f:
    f.seek(0x3010)
    data = f.read(25)
    print("Original bytes:", data)
    key = bytes([b ^ 0xAA for b in data])
    print("Initialized key (len={}):".format(len(key)), key)
    print("Hex representation:", key.hex())
