# pizza

Format String Exploitation, PIE enabled

## checksec

```bash
[*] '/mnt/d/CTFs/LACTF 2024/pizza/pizza_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

PIE-enabled so we need to use the offsets if jumping manually to a part of the text segment, or libc

## Basic Knowledge about Format String Exploits

For basic knowledge about format string exploits, see https://github.com/ir0nstone/pwn-notes/blob/master/types/stack/format-string.md. 

## Leaking the libc base address

We leak libc by leaking the return address from `main` that is on the stack, using the format string vulnerability. 

Exactly where before/after the start of `__libc_start_main` it is that `main` returns to, we can find by using gdb and setting a breakpoint just as `main` returns. 

We can then use that offset to obtain the libc base address.  

## Leaking write-to address on the stack

We are going to do a ROP attack, so we need to know the address on the stack where the retaddr of `main` is stored, so that it can be overwritten. 

Conveniently, on the stack, we have an address that is a set offset from our desired write-to address. Leaking it and subtracting that offset gives us our write-to address. 

## Constructing the ROP Chain and Injecting the Payload

With the libc base address, we can construct our ROP chain that consists of
- ret gadget
- pop rdi gadget
- /bin/sh\x00 address
- libc system address

With the write-to address (and format string exploit offset), we can write that onto the stack, and when `main` returns, win. 