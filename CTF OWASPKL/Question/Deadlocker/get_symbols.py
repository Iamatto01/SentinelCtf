from elftools.elf.elffile import ELFFile

with open('Deadlocker', 'rb') as f:
    elf = ELFFile(f)
    print("=== Relocations ===")
    for section in elf.iter_sections():
        if section.name.startswith('.rela'):
            for reloc in section.iter_relocations():
                symbol = elf.get_section(section.header.sh_link).get_symbol(reloc.entry.r_info_sym)
                print(f"Reloc: {hex(reloc.entry.r_offset)} -> {symbol.name}")
