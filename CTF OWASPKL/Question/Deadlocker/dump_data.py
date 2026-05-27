with open('Deadlocker', 'rb') as f:
    f.seek(0x3000)
    data = f.read(56)
    print("Data section bytes:")
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        print(f"Offset {hex(i)}:", chunk, "->", chunk.hex())
