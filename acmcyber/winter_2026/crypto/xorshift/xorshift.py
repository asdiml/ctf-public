#!/usr/local/bin/python3

from Crypto.Util.number import bytes_to_long
from secrets import token_bytes

FLAG = open('flag.txt','r').read()

class RNG:
    def __init__(self):
        s0 = bytes_to_long(token_bytes(8))
        s1 = bytes_to_long(token_bytes(8))
        self.state = (s0, s1)
    
    def next(self):
        s0 = self.state[0]
        s1 = self.state[1]
        result = (s0 + s1) % (1 << 64)

        s1 ^= s0
        state0 = s1
        s0 ^= (s1 << 23) % (1 << 64)
        # Logical shift instead of arithmetic shift
        s0 ^= ((s0 % (1 << 64)) >> 17)
        s0 ^= ((s1 % (1 << 64)) >> 26)
        state1 = s0

        self.state = (state0, state1)

        return result

R = RNG()
for i in range(20):
    print(R.next())
if int(input("Guess the next number: ")) == R.next():
    print(FLAG)
else:
    print("Wrong guess!")

