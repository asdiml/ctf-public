#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"

code = asm(eval('f"""\n'+open("src.s").read()+'\n"""'))

class Ehdr():
    def __init__(self):
        self.ei_class = 2
        self.ei_data = 1
        self.ei_version = 1
        self.ei_osabi = 0
        self.ei_abiversion = 0
        self.ei_pad = b"\x00"*7
        self.e_type = 3
        self.e_machine = 0x3e
        self.e_version = 1
        self.e_entry = 0
        self.e_phoff = 0x40
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0x38
        self.e_phnum = 1
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0
    def __len__(self): return 0x40
    def create(self):
        e = b"\x7fELF"
        e += p8(self.ei_class)
        e += p8(self.ei_data)
        e += p8(self.ei_version)
        e += p8(self.ei_osabi)
        e += p8(self.ei_abiversion)
        e += self.ei_pad
        e += p16(self.e_type)
        e += p16(self.e_machine)
        e += p32(self.e_version)
        e += p64(self.e_entry)
        e += p64(self.e_phoff)
        e += p64(self.e_shoff)
        e += p32(self.e_flags)
        e += p16(self.e_ehsize)
        e += p16(self.e_phentsize)
        e += p16(self.e_phnum)
        e += p16(self.e_shentsize)
        e += p16(self.e_shnum)
        e += p16(self.e_shstrndx)
        assert len(e) == 0x40
        return e

class Phdr():
    def __init__(self, p_type):
        self.p_type = p_type
        self.p_flags = 7
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0x1000
        self.p_memsz = 0x1000
        self.p_align = 0
    def __len__(self): return 0x38
    def create(self):
        e = p32(self.p_type)
        e += p32(self.p_flags)
        e += p64(self.p_offset)
        e += p64(self.p_vaddr)
        e += p64(self.p_paddr)
        e += p64(self.p_filesz)
        e += p64(self.p_memsz)
        e += p64(self.p_align)
        assert len(e) == 0x38
        return e

e = Ehdr()
p = Phdr(1)
e.e_entry = 0x78
elf = e.create() + p.create() + code
with open("chal", "wb") as f:
    f.write(elf)
