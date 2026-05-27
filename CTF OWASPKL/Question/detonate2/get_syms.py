from elftools.elf.elffile import ELFFile

elf = ELFFile(open('detonate2.exe', 'rb'))
symtab = elf.get_section_by_name('.symtab')
for sym in symtab.iter_symbols():
    if sym.name:
        print(f"{sym.name}: {hex(sym['st_value'])}")
