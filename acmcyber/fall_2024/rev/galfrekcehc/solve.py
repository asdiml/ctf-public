#!/usr/bin/env python3

from pwn import *
import math

exe = ELF("./chal")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
    else:
        r = remote("box.acmcyber.com", 31442)

    return r

def main():
    r = conn()

    payload = b''.join([
        p64(0xdeadbeefcafebabe ^ 0xb6dac59daf9cc3dd),
        p64(((0xc0dec0dec0dec0de ^ 0x28600a3a0a309e26) - (0x1337 - 0x7331)) >> 1),
        p32(0x99999999 ^ 0xfcebfcf1), p32(0xc001c0de ^ 0x9f6eae81),
        p64((0x514c4b430f0d1410 + 0x41414141) ^ 1),
        p64((0x123456789 ^ 0xe4e8e6ddf1fbc501) >> 1),
        p64(((0x745f657265775f79 ^ 0x92c0b2d3c130c1f) + 0x1010101010) ^ 3)
    ])
    log.info(f"{payload=}")

    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()