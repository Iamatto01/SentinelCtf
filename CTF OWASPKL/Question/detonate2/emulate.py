"""
Emulate check_flag from detonate2.exe using Unicorn Engine.
Fixed string handling with proper SSO support.
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
    f.seek(0)
    raw_data = f.read()

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
heap_ptr = HEAP_BASE

def heap_alloc(size):
    global heap_ptr
    p = heap_ptr
    heap_ptr += (size + 15) & ~15
    return p

output_parts = []

# The key issue: the string constructor at 0x299c is NOT a PLT call,
# it's an internal function. It calls PLT entries like _M_local_data, 
# Alloc_hider ctor, _S_copy_chars, _M_set_length, etc.
# We need these PLT hooks to work correctly for the internal string
# constructor to function.
#
# GCC std::__cxx11::basic_string layout (64-bit):
# offset 0:  _M_dataplus._M_p (pointer to char data) [8 bytes]
# offset 8:  _M_string_length [8 bytes]
# offset 16: union { _M_local_buf[16]; _M_allocated_capacity; } [16 bytes]
# Total: 32 bytes
# 
# SSO: if length <= 15, data is stored in _M_local_buf (at offset 16)
# and _M_dataplus._M_p points to _M_local_buf (i.e., to this+16)

PLT_RANGE = (0x2020, 0x2190)

def do_ret(mu):
    rsp = mu.reg_read(UC_X86_REG_RSP)
    ret_addr = struct.unpack('<Q', bytes(mu.mem_read(rsp, 8)))[0]
    mu.reg_write(UC_X86_REG_RSP, rsp + 8)
    mu.reg_write(UC_X86_REG_RIP, ret_addr)

def read_cstr(mu, addr):
    s = b''
    i = 0
    while i < 10000:
        b = mu.mem_read(addr + i, 1)[0]
        if b == 0:
            break
        s += bytes([b])
        i += 1
    return s

def str_read(mu, obj):
    """Read a std::string object from memory"""
    ptr = struct.unpack('<Q', bytes(mu.mem_read(obj, 8)))[0]
    length = struct.unpack('<Q', bytes(mu.mem_read(obj + 8, 8)))[0]
    if length > 0 and ptr > 0:
        return bytes(mu.mem_read(ptr, length))
    return b''

call_count = [0]

def hook_code(mu, address, size, user_data):
    if address == 0x27d5:
        print("MD5 INPUT:", str_read(mu, mu.reg_read(UC_X86_REG_RDI)))
    if not (PLT_RANGE[0] <= address < PLT_RANGE[1]):
        return
    
    call_count[0] += 1
    
    rdi = mu.reg_read(UC_X86_REG_RDI)
    rsi = mu.reg_read(UC_X86_REG_RSI)
    rdx = mu.reg_read(UC_X86_REG_RDX)
    rcx = mu.reg_read(UC_X86_REG_RCX)
    r8 = mu.reg_read(UC_X86_REG_R8)
    r9 = mu.reg_read(UC_X86_REG_R9)
    
    if address == 0x2030:  # c_str() const
        ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
        mu.reg_write(UC_X86_REG_RAX, ptr)
        do_ret(mu)
        
    elif address == 0x2040:  # string copy ctor(dst, src)
        # Read source string
        src_ptr = struct.unpack('<Q', bytes(mu.mem_read(rsi, 8)))[0]
        src_len = struct.unpack('<Q', bytes(mu.mem_read(rsi + 8, 8)))[0]
        if src_len > 0:
            src_data = bytes(mu.mem_read(src_ptr, src_len))
        else:
            src_data = b''
        
        # Set up destination with SSO or heap
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
        
    elif address == 0x2050:  # strlen
        l = len(read_cstr(mu, rdi))
        mu.reg_write(UC_X86_REG_RAX, l)
        do_ret(mu)
        
    elif address == 0x2060:  # string dtor
        do_ret(mu)
        
    elif address == 0x2070:  # operator+=(char)
        ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
        length = struct.unpack('<Q', bytes(mu.mem_read(rdi + 8, 8)))[0]
        if length > 0:
            data = bytearray(mu.mem_read(ptr, length))
        else:
            data = bytearray()
        data.append(rsi & 0xFF)
        
        # Always allocate on heap for simplicity
        buf = heap_alloc(len(data) + 1)
        mu.mem_write(buf, bytes(data) + b'\x00')
        mu.mem_write(rdi, struct.pack('<Q', buf))
        mu.mem_write(rdi + 8, struct.pack('<Q', len(data)))
        mu.reg_write(UC_X86_REG_RAX, rdi)
        do_ret(mu)
        
    elif address == 0x2080:  # _M_set_length(n)
        mu.mem_write(rdi + 8, struct.pack('<Q', rsi))
        # Also null-terminate
        ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
        mu.mem_write(ptr + rsi, b'\x00')
        do_ret(mu)
        
    elif address == 0x2090:  # size() const
        length = struct.unpack('<Q', bytes(mu.mem_read(rdi + 8, 8)))[0]
        mu.reg_write(UC_X86_REG_RAX, length)
        do_ret(mu)
        
    elif address == 0x20a0:  # throw_logic_error
        print(f"ERROR: throw_logic_error!")
        mu.emu_stop()
        
    elif address == 0x20b0:  # _M_local_data() - returns ptr to local buffer at obj+16
        mu.reg_write(UC_X86_REG_RAX, rdi + 16)
        do_ret(mu)
        
    elif address == 0x20c0:  # _M_data(char* p) - sets data pointer
        mu.mem_write(rdi, struct.pack('<Q', rsi))
        do_ret(mu)
        
    elif address == 0x20d0:  # operator<<(ostream, string)
        data = str_read(mu, rsi)
        s = data.decode('utf-8', errors='replace')
        output_parts.append(s)
        if 'md5_result' not in repr(s) and len(s) > 0:
            print(f"  OUTPUT(string): {repr(s)}")
        mu.reg_write(UC_X86_REG_RAX, rdi)
        do_ret(mu)
        
    elif address == 0x20e0:  # stat - simulate file found (return 0)
        print("STAT PATH:", read_cstr(mu, rdi))
        mu.reg_write(UC_X86_REG_RAX, 0)
        do_ret(mu)
        
    elif address == 0x20f0:  # operator<<(ostream, const char*)
        s = read_cstr(mu, rsi)
        output_parts.append(s.decode('utf-8', errors='replace'))
        print(f"  OUTPUT(cstr): {repr(s.decode('utf-8', errors='replace'))}")
        mu.reg_write(UC_X86_REG_RAX, rdi)
        do_ret(mu)
        
    elif address == 0x2100:  # Alloc_hider ctor(this, ptr, allocator_ref)
        # _Alloc_hider is basically the data pointer member
        # this->_M_p = ptr (rsi)
        mu.mem_write(rdi, struct.pack('<Q', rsi))
        do_ret(mu)
        
    elif address == 0x2110:  # _M_data() const - returns data pointer
        ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
        mu.reg_write(UC_X86_REG_RAX, ptr)
        do_ret(mu)
        
    elif address == 0x2120:  # _S_copy_chars(dest, src_begin, src_end)
        length = rdx - rsi
        if length > 0 and length < 10000:
            data = bytes(mu.mem_read(rsi, length))
            mu.mem_write(rdi, data)
        do_ret(mu)
        
    elif address == 0x2130:  # _M_dispose() 
        do_ret(mu)
        
    elif address == 0x2140:  # snprintf(buf, size, fmt, ...)
        rsp = mu.reg_read(UC_X86_REG_RSP)
        # 7th arg on stack: [rsp+8] (rsp[0] = ret addr)
        arg7 = struct.unpack('<Q', bytes(mu.mem_read(rsp + 8, 8)))[0] & 0xFF
        result = "%02x%02x%02x%02x" % (rcx & 0xFF, r8 & 0xFF, r9 & 0xFF, arg7)
        mu.mem_write(rdi, result.encode() + b'\x00')
        mu.reg_write(UC_X86_REG_RAX, len(result))
        do_ret(mu)
        
    elif address == 0x2150:  # _Unwind_Resume
        print("ERROR: _Unwind_Resume")
        mu.emu_stop()
        
    elif address == 0x2160:  # _M_create(size_ref, old_capacity)
        size_val = struct.unpack('<Q', bytes(mu.mem_read(rsi, 8)))[0]
        buf = heap_alloc(max(size_val + 1, 32))
        mu.reg_write(UC_X86_REG_RAX, buf)
        do_ret(mu)
        
    elif address == 0x2170:  # _M_capacity(new_cap)
        do_ret(mu)
        
    elif address == 0x2180:  # operator[](idx) - returns reference to char
        ptr = struct.unpack('<Q', bytes(mu.mem_read(rdi, 8)))[0]
        mu.reg_write(UC_X86_REG_RAX, ptr + rsi)
        do_ret(mu)
        
    else:
        print(f"Unhandled PLT at {hex(address)}")
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_code)

FAKE_RET = 0xDEAD0000
mu.mem_map(0xDEAD0000, 0x1000, UC_PROT_ALL)
mu.mem_write(RSP - 8, struct.pack('<Q', FAKE_RET))
mu.reg_write(UC_X86_REG_RSP, RSP - 8)

print("Starting emulation of check_flag at 0x2733...\n")
try:
    mu.emu_start(0x2733, FAKE_RET, timeout=60000000)
except UcError as e:
    rip = mu.reg_read(UC_X86_REG_RIP)
    rsp = mu.reg_read(UC_X86_REG_RSP)
    rbp = mu.reg_read(UC_X86_REG_RBP)
    print(f"Emulation error at RIP={hex(rip)}, RSP={hex(rsp)}, RBP={hex(rbp)}: {e}")

print(f"\nTotal PLT calls: {call_count[0]}")
print(f"\n=== Full Output ===")
full = ''.join(output_parts)
print(repr(full))

if 'OWASPKL{' in full:
    start = full.index('OWASPKL{')
    end = full.index('}', start) + 1
    print(f"\n=== FLAG ===\n{full[start:end]}")
