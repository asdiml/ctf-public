## Welcome Note

Welcome to my dump of solves for picoGym Pwn challenges!

If you don't see a writeup (i.e. only a solve script), that means the concepts used are probably covered in another writeup, or are relatively straightforward. 

## Categories (Easy & Medium)

### Format String Exploitation
- [flag-leak](./flag-leak/solve.py) (Read off stack)
- [format-string-1](./format-string-1/solve.md) (Read off stack)
- [format-string-2](./format-string-2/solve.md) (Write to data segment)
- [format-string-3](./format-string-3/solve.md) (GOT overwrite)
- [stonks](./stonks/solve.md) (Read off stack after brute-forcing offset)

### Stack
- [stack-cache](./stack-cache/solve.md) (Understanding stack frames)

#### Simple Buffer Overflow
- [buffer-overflow-1](./buffer-overflow-1/solve.py) (ret2win)
- [buffer-overflow-2](./buffer-overflow-2/solve.py) (ret2win with args)
- [buffer-overflow-3](./buffer-overflow-3/solve.md) (ret2win with Canary Brute-forcing)
- [clutter-overflow](./clutter-overflow/solve.py) (Overwrite local variable on stack)
- [x-sixty-what](./x-sixty-what/solve.py) (ret2win)

#### ROP
- [heresalibc](./heresalibc/notes.md) (ret2libc)

### Heap

#### Baby
- [heap-0](./heap-0/solve.md) (Address-leaked Adjacent Chunk Heap Overflow)
- [heap-1](./heap-1/solve.py) (Address-leaked Adjacent Chunk Heap Overflow)
- [heap-2](./heap-2/solve.py) (Address-leaked Adjacent Chunk Heap Overflow)
- [heap-3](./heap-3/solve.md) (Use-After-Free)
- [unsubscriptionsarefree](./unsubscriptionsarefree/solve.md) (Use-After-Free)

#### tcache
- [cachemeoutside](./cachemeoutside/solve.md) (Overwrite tcache entry)

### Shellcode
- [filtered-shellcode](./filtered-shellcode/solve.md) (Shellcode, 2-byte max-length instrs)
- [ropfu](./ropfu/solve.md) (ROP to Shellcode)

### Misc

#### Array Out-of-bounds Access
- [babygame01](./babygame01/solve.md) (Array Negative-index write)
- [babygame02 (INCOMPLETE)](./babygame02%20(INCOMPLETE)/solve.md) (Array Negative-index write, ret2win)
- [function-overwrite](./function-overwrite/solve.md) (Array Negative-index write)

#### Others
- [hijacking](./hijacking/solve.md) (Python Library hijacking / Privilege Escalation)
- [RPS](./RPS/solve.py) (Understanding `strstr`)
- [tic-tac](./tic-tac/solve.md) (TOCTOU) **TODO: Review writeup and solution**
- [wine](./wine/solve.md) (wine / Embryo Windows pwn)

## Categories (Hard) **Work-in-Progress**

Pwn gods, please bless me with a solve