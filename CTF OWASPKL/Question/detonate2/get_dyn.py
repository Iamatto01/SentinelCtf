from elftools.elf.elffile import ELFFile
elf = ELFFile(open("detonate2.exe", "rb"))
symtab = elf.get_section_by_name(".dynsym")
for sym in symtab.iter_symbols():
    if sym.name:
        print(sym.name)
