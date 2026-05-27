from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
import struct
import socket
import json
import base64

def run_emulation(ptrace_val):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # Load ELF segments
    with open('Deadlocker', 'rb') as f:
        elf = ELFFile(f)
        segments = []
        for seg in elf.iter_segments():
            if seg.header.p_type == 'PT_LOAD':
                segments.append((seg.header.p_vaddr, seg.data(), seg.header.p_memsz))
                
    for vaddr, data, memsz in segments:
        aligned_addr = vaddr & ~0xFFF
        aligned_size = ((vaddr + memsz - aligned_addr + 0xFFF) & ~0xFFF)
        try:
            mu.mem_map(aligned_addr, aligned_size, UC_PROT_ALL)
        except:
            pass
        mu.mem_write(vaddr, data)
        
    # Setup Stack
    STACK_BASE = 0x7fff0000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    RSP = STACK_BASE + STACK_SIZE - 0x2000
    
    # Setup Heap
    HEAP_BASE = 0x200000
    HEAP_SIZE = 0x100000
    mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    
    # Write arguments to heap
    arg0_addr = HEAP_BASE + 0x100
    arg1_addr = HEAP_BASE + 0x200
    arg2_addr = HEAP_BASE + 0x300
    
    mu.mem_write(arg0_addr, b"./Deadlocker\x00")
    mu.mem_write(arg1_addr, b"lockbox.appsecmy.com\x00")
    mu.mem_write(arg2_addr, b"9999\x00")
    
    argv_addr = HEAP_BASE + 0x400
    mu.mem_write(argv_addr, struct.pack("<QQQ", arg0_addr, arg1_addr, arg2_addr))
    
    mu.reg_write(UC_X86_REG_RDI, 3)
    mu.reg_write(UC_X86_REG_RSI, argv_addr)
    
    def do_ret(mu):
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', bytes(mu.mem_read(rsp, 8)))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)
        
    def read_cstr(mu, addr):
        s = b''
        for i in range(10000):
            b = mu.mem_read(addr + i, 1)[0]
            if b == 0: break
            s += bytes([b])
        return s
        
    # Keep track of outputs
    outputs = []
    
    user_data = {'ptrace_val': ptrace_val}
    
    def hook_code(mu, address, size, u_data):
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        r8 = mu.reg_read(UC_X86_REG_R8)
        
        # ptrace (0x11e0)
        if address == 0x11e0:
            pval = u_data['ptrace_val']
            mu.reg_write(UC_X86_REG_RAX, pval & 0xFFFFFFFFFFFFFFFF)
            do_ret(mu)
            
        # atoi (0x11f0)
        elif address == 0x11f0:
            s_val = read_cstr(mu, rdi).decode('utf-8')
            mu.reg_write(UC_X86_REG_RAX, int(s_val))
            do_ret(mu)
            
        # memcpy (0x11b0)
        elif address == 0x11b0:
            dest = rdi
            src = rsi
            sz = rdx
            data = mu.mem_read(src, sz)
            mu.mem_write(dest, bytes(data))
            mu.reg_write(UC_X86_REG_RAX, dest)
            do_ret(mu)
            
        # 0x17b4: fetch function
        elif address == 0x17b4:
            host = read_cstr(mu, rdi).decode('utf-8')
            port = rsi
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((host, port))
                sock.sendall(b"GET_CHALLENGE")
                resp = sock.recv(4096).decode('utf-8')
            finally:
                sock.close()
                
            chal_data = json.loads(resp)
            nonce_bytes = bytes.fromhex(chal_data["nonce"])
            ciphertext = base64.b64decode(chal_data["encrypted_flag"])
            
            mu.mem_write(rdx, nonce_bytes)
            mu.mem_write(rcx, ciphertext)
            mu.mem_write(r8, struct.pack("<I", len(ciphertext)))
            
            mu.reg_write(UC_X86_REG_RAX, 0)
            do_ret(mu)
            
        # printf
        elif address == 0x1190:
            val_bytes = read_cstr(mu, rsi)
            outputs.append(f"Flag (hex): {val_bytes.hex()}")
            do_ret(mu)
            
        # fwrite
        elif address == 0x1210:
            s_bytes = read_cstr(mu, rdi)
            outputs.append(f"fwrite (hex): {s_bytes.hex()}")
            do_ret(mu)
            
        # __stack_chk_fail
        elif address == 0x1150:
            print("[Error] __stack_chk_fail triggered!")
            mu.emu_stop()
            
    mu.hook_add(UC_HOOK_CODE, hook_code, user_data)
    
    # Set up return address on stack to stop emulation
    FAKE_RET = 0xDEAD0000
    try:
        mu.mem_map(FAKE_RET, 0x1000, UC_PROT_ALL)
    except:
        pass
    mu.mem_write(RSP - 8, struct.pack('<Q', FAKE_RET))
    mu.reg_write(UC_X86_REG_RSP, RSP - 8)
    
    # Start emulation from main (0x1a55)
    try:
        mu.emu_start(0x1a55, FAKE_RET, timeout=10000000)
    except UcError as e:
        rip = mu.reg_read(UC_X86_REG_RIP)
        print(f"Error at {hex(rip)}: {e}")
        
    return outputs

print("=== Running with ptrace returning 0 (Normal) ===")
res0 = run_emulation(0)
print("Output:", repr(res0))

print("\n=== Running with ptrace returning -1 (Debugged) ===")
res1 = run_emulation(-1)
print("Output:", repr(res1))
