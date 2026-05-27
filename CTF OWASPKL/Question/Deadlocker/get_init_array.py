import struct

with open('Deadlocker', 'rb') as f:
    f.seek(0x2d40)
    data = f.read(8)
    addr = struct.unpack("<Q", data)[0]
    print(".init_array address:", hex(addr))
