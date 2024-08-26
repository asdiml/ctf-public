#!/usr/bin/env python3

from pwn import *
import sys

context.log_level = 'error'

def conn():
    r = remote("jupiter.challenges.picoctf.org", 57529)
    return r

def main():

    for i in range(-4094, 4096 + 1):
    
        if i == 0: continue

        # Print progress
        sys.stdout.write(f'\rProgress: {i}/4096')
        sys.stdout.flush()

        # Open the connection and guess the first number
        r = conn()
        r.sendlineafter(b'guess?\n', str(i).encode())

        if r.recvline() != b'Nope!\n':
            print(f"\nAnswer = {i}")
            break

        r.close()

if __name__ == "__main__":
    main()