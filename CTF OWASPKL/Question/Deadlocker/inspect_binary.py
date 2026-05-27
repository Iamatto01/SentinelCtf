from elftools.elf.elffile import ELFFile

with open('Deadlocker', 'rb') as f:
    elf = ELFFile(f)
    for section in elf.iter_sections():
        print(f"Section: {section.name}, addr: {hex(section.header.sh_addr)}, size: {section.header.sh_size}, offset: {hex(section.header.sh_offset)}")
