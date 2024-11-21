#!/usr/bin/env python3

'''
Explanation of script
- This script exploits how rand() is a Pseudo-RNG and thus will produce the same output if seeded with the same value
- The seed is time(0), which is a very generous time function that returns the no. of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
- Thus the latency of calling time(0) in the Python script after it is called in the binary isn't likely to be an issue for any one run
- To win, we match each rand()%16 30 times to complete the 30 levels of the game
'''

from pwn import *
from ctypes import *

exe = ELF("./seed_spring")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 8311)

    return r


def main():

    libc = cdll.LoadLibrary('libc.so.6')

    # Initialize an emulated PRNG (with the same initialization conditions) at the
    # starting of the process
    r = conn()
    cur_time = libc.time(0)
    libc.srand(cur_time)

    # Win the game
    for i in range(30): 
        rand = libc.rand()
        r.sendlineafter(b'height: ', str(rand%16).encode())

    r.interactive()


if __name__ == "__main__":
    main()
