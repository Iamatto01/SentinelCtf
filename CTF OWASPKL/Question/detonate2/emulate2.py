"""
Try with stat returning failure (file not found) to see if there's a different path.
Also try with various inputs.
"""
from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
import struct

with open('detonate2.exe', 'rb') as f:
    elf = ELFFile(f)
    segments = []
    for seg in elf.iter_segments():
        if seg.header.p_type == 'PT_LOAD':
            segments.append((seg.header.p_vaddr, seg.data(), seg.header.p_memsz))

def run_emulation(stat_returns):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    for vaddr, data, memsz in segments:
        aligned_addr = vaddr & ~0xFFF
        aligned_size = ((vaddr + memsz - aligned_addr + 0xFFF) & ~0xFFF)
        try:
            mu.mem_map(aligned_addr, aligned_size, UC_PROT_ALL)
        except:
            pass
        mu.mem_write(vaddr, data)
    
    STACK_BASE = 0x7fff0000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    RSP = STACK_BASE + STACK_SIZE - 0x2000
    
    HEAP_BASE = 0x200000
    HEAP_SIZE = 0x100000
    mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    global heap_ptr
    heap_ptr = HEAP_BASE
    
    output_parts = []
    
    def heap_alloc(size):
        global heap_ptr
        p = heap_ptr
        heap_ptr += (size + 15) & ~15
        return p
    
    def read_cstr(mu, addr):
        s = b''
        for i in range(10000):
            b = mu.mem_read(addr + i, 1)[0]
            if b == 0: break
            s += bytes([b])
        return s
    
    def str_read(mu, obj):
        ptr = struct.unpack('<Q', bytes(mu.mem_read(obj, 8)))[0]
        length = struct.unpack('<Q', bytes(mu.mem_read(obj + 8, 8)))[0]
        if length > 0 and ptr > 0:
            return bytes(mu.mem_read(ptr, length))
        return b''
    
    def do_ret(mu):
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', bytes(mu.mem_read(rsp, 8)))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)
    
    def hook_code(mu, address, size, user_data):
        if not (0x2020 <= address < 0x2190): return
        
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        r8 = mu.reg_read(UC_X86_REG_R8)
        r9 = mu.reg_read(UC_X86_REG_R9)
        
        if address == 0x2030:
            ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
            mu.reg_write(UC_X86_REG_RAX, ptr)
            do_ret(mu)
        elif address == 0x2040:
            src_ptr = struct.unpack('<Q', bytes(mu.mem_read(rsi, 8)))[0]
            src_len = struct.unpack('<Q', bytes(mu.mem_read(rsi + 8, 8)))[0]
            src_data = bytes(mu.mem_read(src_ptr, src_len)) if src_len > 0 else b''
            if src_len <= 15:
                local_buf = rdi + 16
                mu.mem_write(local_buf, src_data + b'\x00')
                mu.mem_write(rdi, struct.pack('<Q', local_buf))
            else:
                buf = heap_alloc(src_len + 1)
                mu.mem_write(buf, src_data + b'\x00')
                mu.mem_write(rdi, struct.pack('<Q', buf))
            mu.mem_write(rdi + 8, struct.pack('<Q', src_len))
            do_ret(mu)
        elif address == 0x2050:
            mu.reg_write(UC_X86_REG_RAX, len(read_cstr(mu, rdi)))
            do_ret(mu)
        elif address == 0x2060:
            do_ret(mu)
        elif address == 0x2070:
            ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
            length = struct.unpack('<Q', bytes(mu.mem_read(rdi + 8, 8)))[0]
            data = bytearray(mu.mem_read(ptr, length)) if length > 0 else bytearray()
            data.append(rsi & 0xFF)
            buf = heap_alloc(len(data) + 1)
            mu.mem_write(buf, bytes(data) + b'\x00')
            mu.mem_write(rdi, struct.pack('<Q', buf))
            mu.mem_write(rdi + 8, struct.pack('<Q', len(data)))
            mu.reg_write(UC_X86_REG_RAX, rdi)
            do_ret(mu)
        elif address == 0x2080:
            mu.mem_write(rdi + 8, struct.pack('<Q', rsi))
            ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
            mu.mem_write(ptr + rsi, b'\x00')
            do_ret(mu)
        elif address == 0x2090:
            length = struct.unpack('<Q', bytes(mu.mem_read(rdi + 8, 8)))[0]
            mu.reg_write(UC_X86_REG_RAX, length)
            do_ret(mu)
        elif address == 0x20a0:
            mu.emu_stop()
        elif address == 0x20b0:
            mu.reg_write(UC_X86_REG_RAX, rdi + 16)
            do_ret(mu)
        elif address == 0x20c0:
            mu.mem_write(rdi, struct.pack('<Q', rsi))
            do_ret(mu)
        elif address == 0x20d0:
            data = str_read(mu, rsi)
            output_parts.append(data.decode('utf-8', errors='replace'))
            mu.reg_write(UC_X86_REG_RAX, rdi)
            do_ret(mu)
        elif address == 0x20e0:  # stat
            mu.reg_write(UC_X86_REG_RAX, stat_returns)
            do_ret(mu)
        elif address == 0x20f0:
            s = read_cstr(mu, rsi)
            output_parts.append(s.decode('utf-8', errors='replace'))
            mu.reg_write(UC_X86_REG_RAX, rdi)
            do_ret(mu)
        elif address == 0x2100:
            mu.mem_write(rdi, struct.pack('<Q', rsi))
            do_ret(mu)
        elif address == 0x2110:
            ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
            mu.reg_write(UC_X86_REG_RAX, ptr)
            do_ret(mu)
        elif address == 0x2120:
            length = rdx - rsi
            if 0 < length < 10000:
                mu.mem_write(rdi, bytes(mu.mem_read(rsi, length)))
            do_ret(mu)
        elif address == 0x2130:
            do_ret(mu)
        elif address == 0x2140:
            rsp = mu.reg_read(UC_X86_REG_RSP)
            arg7 = struct.unpack('<Q', bytes(mu.mem_read(rsp + 8, 8)))[0] & 0xFF
            result = "%02x%02x%02x%02x" % (rcx & 0xFF, r8 & 0xFF, r9 & 0xFF, arg7)
            mu.mem_write(rdi, result.encode() + b'\x00')
            mu.reg_write(UC_X86_REG_RAX, len(result))
            do_ret(mu)
        elif address == 0x2150:
            mu.emu_stop()
        elif address == 0x2160:
            size_val = struct.unpack('<Q', bytes(mu.mem_read(rsi, 8)))[0]
            buf = heap_alloc(max(size_val + 1, 32))
            mu.reg_write(UC_X86_REG_RAX, buf)
            do_ret(mu)
        elif address == 0x2170:
            do_ret(mu)
        elif address == 0x2180:
            ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
            mu.reg_write(UC_X86_REG_RAX, ptr + rsi)
            do_ret(mu)
        else:
            mu.emu_stop()
    
    mu.hook_add(UC_HOOK_CODE, hook_code)
    
    FAKE_RET = 0xDEAD0000
    try:
        mu.mem_map(0xDEAD0000, 0x1000, UC_PROT_ALL)
    except:
        pass
    mu.mem_write(RSP - 8, struct.pack('<Q', FAKE_RET))
    mu.reg_write(UC_X86_REG_RSP, RSP - 8)
    
    try:
        mu.emu_start(0x2733, FAKE_RET, timeout=60000000)
    except UcError as e:
        rip = mu.reg_read(UC_X86_REG_RIP)
        print(f"  Error at {hex(rip)}: {e}")
    
    return ''.join(output_parts)

print("=== Test 1: stat returns 0 (file found) ===")
out1 = run_emulation(0)
print(f"  Output: {repr(out1)}")

print("\n=== Test 2: stat returns -1 (file not found) ===")
out2 = run_emulation(0xFFFFFFFF)  # -1 as unsigned 32-bit
print(f"  Output: {repr(out2)}")

print("\n=== Test 3: stat returns 1 ===")
out3 = run_emulation(1)
print(f"  Output: {repr(out3)}")
