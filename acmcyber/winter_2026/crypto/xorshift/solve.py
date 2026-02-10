from pwn import *
from z3 import *

r = remote("instancer.acmcyber.com", 32604)

state0, state1 = z3.BitVecs("state0 state1", 64)
s = Solver()

for i in range(20):
    s.add(state0 + state1 == int(r.recvline()))

    s0 = state0
    s1 = state1

    s1 ^= s0
    state0 = s1
    s0 ^= (s1 << 23)
    s0 ^= LShR(s0, 17)
    s0 ^= LShR(s1, 26)
    state1 = s0

if s.check() == sat:
    m = s.model()
    next_rng = (m.evaluate(state0).as_long() + m.evaluate(state1).as_long()) % (1 << 64)
    r.sendlineafter(b'the next number: ', str(next_rng).encode())
    r.interactive()