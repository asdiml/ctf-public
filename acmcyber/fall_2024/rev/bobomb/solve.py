#!/usr/bin/env python3

from pwn import *
import math

exe = ELF("./bobomb")

context.binary = exe

# Extended Euclidean Algorithm to find Modular inverse
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

# Modular inverse code from geeks2geeks
def modInverse(b ,m):
    g = math.gcd(b, m) 
    if (g != 1):
        return -1
    else: 
        eucli_alg_result = extended_gcd(m, b)[2]
        return eucli_alg_result if eucli_alg_result >= 0 else eucli_alg_result + m
 
# Modular division code from geeks2geeks
def modDivide(a,b,m):
    a = a % m
    inv = modInverse(b,m)
    if(inv == -1):
        print("Division not defined")
        return -1
    else:
        return (inv*a) % m

def rev_eng(num_32bit, undo_xor_first = 0):

    def undo_xor(num): 
        return num ^ 0x42
    def undo_mul_and_add(num): 
        return modDivide(num-0xd, 7, 2**32) % 2**32

    operations = [undo_mul_and_add, undo_xor]
    for i in range(undo_xor_first, 5 + undo_xor_first):
        num_32bit = operations[i%2](num_32bit)
    
    return num_32bit

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
    else:
        r = remote("box.acmcyber.com", 31442)

    return r

def main():
    r = conn()

    upper32 = rev_eng(0xa0a68f32, undo_xor_first=0)
    lower32 = rev_eng(0x69cac977, undo_xor_first=1)
    num64 = upper32 * 2**32 + lower32
    log.info(f"{num64=}")

    r.sendlineafter(b'enter x: ', str(num64).encode())

    r.interactive()

if __name__ == "__main__":
    main()