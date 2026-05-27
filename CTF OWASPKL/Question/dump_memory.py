import ctypes
from ctypes import wintypes
import time
import sys

kernel32 = ctypes.windll.kernel32

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

si = STARTUPINFO()
si.cb = ctypes.sizeof(si)
pi = PROCESS_INFORMATION()

CREATE_SUSPENDED = 0x00000004

if not kernel32.CreateProcessW(None, "unpackme2.exe", None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)):
    print("Failed to start process")
    sys.exit(1)

print(f"Started suspended PID: {pi.dwProcessId}")

kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
ntdll_handle = kernel32.GetModuleHandleW("ntdll.dll")

exit_process_addr = kernel32.GetProcAddress(kernel32_handle, b"ExitProcess")
nt_terminate_process_addr = kernel32.GetProcAddress(ntdll_handle, b"NtTerminateProcess")

print(f"ExitProcess at {hex(exit_process_addr) if exit_process_addr else 'None'}")
print(f"NtTerminateProcess at {hex(nt_terminate_process_addr) if nt_terminate_process_addr else 'None'}")

def hook_func(addr):
    if not addr: return
    old_protect = wintypes.DWORD()
    PAGE_EXECUTE_READWRITE = 0x40
    kernel32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(addr), 2, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
    written = ctypes.c_size_t()
    kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(addr), b"\xEB\xFE", 2, ctypes.byref(written))
    kernel32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(addr), 2, old_protect.value, ctypes.byref(old_protect))

hook_func(exit_process_addr)
hook_func(nt_terminate_process_addr)

print("Hooked exit functions with infinite loop.")

kernel32.ResumeThread(pi.hThread)

print("Thread resumed. Waiting 2 seconds for it to unpack and hit the loop...")
time.sleep(2)

print("Now dumping process memory...")
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

address = 0
all_data = bytearray()

while address < 0x7FFFFFFF:
    mbi = MEMORY_BASIC_INFORMATION()
    if kernel32.VirtualQueryEx(pi.hProcess, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        address += 0x1000
        continue
    base = mbi.BaseAddress or 0
    if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS) and not (mbi.Protect & PAGE_GUARD):
        buffer = ctypes.create_string_buffer(mbi.RegionSize)
        bytesRead = ctypes.c_size_t()
        if kernel32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(base), buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
            all_data.extend(buffer.raw[:bytesRead.value])
    address = base + mbi.RegionSize

print(f"Dumped {len(all_data)} bytes. Saving to dump.bin")
with open("dump.bin", "wb") as f:
    f.write(all_data)

kernel32.TerminateProcess(pi.hProcess, 0)
kernel32.CloseHandle(pi.hProcess)
kernel32.CloseHandle(pi.hThread)
print("Done.")
