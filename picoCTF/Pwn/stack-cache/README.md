# stack-cache

Stack Frames

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/stack-cache/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The canary is not present in the `vuln` function. 

Also, there is no PIE, so we can use the `win` and `UnderConstruction` addresses directly

## Concept

The concept of the exploit is to leak local variable information placed on the stack by a previously-exited stack frame by arranging the return address chain such that 

Thus, in our return address chain, we have the `win` function run first, which stores the flag into a local variable (without printing it to stdout). Then, we have the `UnderConstruction` fuction run, which allocates local variables (of more than sufficient size) and prints them out, thus leaking the flag. 

## Parsing the output of `UnderConstruction`

We set the flag in `flag.txt` to be a DeBrujin sequence (for 32-bit architecture) of 64 bytes, and get the following output from the return address chain

```
b'User information : 0x6161616a 0x61616169 0x61616168 0x61616167 0x61616166 0x61616165\n'
b'Names of user: 0x61616164 0x61616163 0x61616162\n'
b'Age of user: 0x61616161\n'
```

These are all values on the stack interpreted as pointers printed as `%p` using `printf`, so we see that the flag can be parsed in reverse order (accounting for the little-endian byte ordering of the printed "pointers"). 

### Taking a closer look at `UnderConstruction`

The source code of `UnderConstruction` is as follows, where `BUFSIZE` is 16

```c
void UnderConstruction() {
        // this function is under construction
        char consideration[BUFSIZE];
        char *demographic, *location, *identification, *session, *votes, *dependents;
	char *p,*q, *r;
	// *p = "Enter names";
	// *q = "Name 1";
	// *r = "Name 2";
        unsigned long *age;
	printf("User information : %p %p %p %p %p %p\n",demographic, location, identification, session, votes, dependents);
	printf("Names of user: %p %p %p\n", p,q,r);
        printf("Age of user: %p\n",age);
        fflush(stdout);
}
```

Recall that the start of the `flag` buffer allocated in `win` starts at the local pointer variable `age` in this new stack frame (the call to `UnderConstruction`), which is 4 bytes higher (in terms of address) then the previous stack frame. 

This makes sense because in the stack frame of `UnderConstruction`, the 10 pointers of 4 bytes each, plus the consideration buffer of 16 bytes, as well as the push of `ebx`, `edi` and `esi` at the start of `UnderConstruction` (you can figure this out from the gdb disassembly) make it such that `age` is stored at `[ebp-0x44]`. 

> Calculation: `4*10 + 16 + 4*3 = 68 = 0x44`

In the stack frame of `win`, `flag` is written to `[ebp-0x40]` (from gdb), which validates that the stack frame of `UnderConstruction` is 4 bytes above that of `win`. 

## Summary of Steps

1. Use gef's built-in De Brujin sequence generator and searcher to find the return address offset (remember to look at `eip` not `esp` because this binary allows for the loading of addresses of NX segments into `eip`)
2. Figure out how the flag is laid out and leaked by the various pointer prints by `printf` in `UnderConstruction` (see [Parsing the output of `UnderConstruction`](#parsing-the-output-of-underconstruction))

## Flag

```python
[+] Opening connection to saturn.picoctf.net on port 50329: Done
b'User information : 0x80c9a04 0x804007d 0x36343532 0x37383139 0x5f597230 0x6d334d5f'
b'Names of user: 0x50755f4e 0x34656c43 0x7b465443'
b'Age of user: 0x6f636970'
b'picoCTF{Cle4N_uP_M3m0rY_91872546}\x00\x04\x08\x04\x9a\x0c\x08'
[*] Closed connection to saturn.picoctf.net port 50329
```

## Difference between compilations in clang-12 vs gcc 11.4.0

`vuln_gcc` is compiled with the command

```bash
gcc -m32 -fno-stack-protector -no-pie -o vuln_gcc vuln.c
```

For `vuln_gcc`, in the stack frame of `UnderConstruction`, `age` is read from `[ebp-0x30]`, the address from which, going up, the 40 bytes are leaked off the stack. Out of this 0x30 bytes of space, 0x28 = 40 bytes are already used, 4 bytes are for the preserving the callee-saved `ebx` for retrieval, and another 4 bytes are unused (presumably for alignment to the 8-byte / 16-byte boundary). The declared but unused local `consideration` 16-byte buffer is optimized away, its memory not allocated in that stack frame. 

In the stack frame of `win`, `flag` is written to `[ebp-0x4c]`, with `[ebp-0x4c]`, where `[ebp-0xc]` stores the pointer to the file object and `[ebp-0x4]` holds the preserved, callee-saved `ebx`. 

Given that the `ebp` of `UnderConstruction` is 4 byte higher than that of `win`, we see that we end up unable to leak `0x4c - 0x30+ 0x4 = 0x20` bytes of the flag. 

This is validated by the leak for `vuln_gcc`: 

```
b'AAAAAAAAAAAAAAAAAAAAAA\x06\x92\x04\x08~\x92\x04\x08\n'
b'User information : 0x41414141 0x8f691b0 0x616170 0x6161616f 0x6161616e 0x6161616d\n'
b'Names of user: 0x6161616c 0x6161616b 0x6161616a\n'
b'Age of user: 0x61616169\n'
```

where `0x61616161` till `0x61616168` (8*4 = 0x20 bytes) remained unleaked. 

### Summary of Differences

| clang-12 | gcc 11.4.0 |
|---------|--------|
| Allocates in the corresponding stack frame declared but unused local variables | Does not allocate declared but unused local variables |
| Local variables stored (from higher to lower addresses) in order of declaration | Local variables are not necessarily stored in order of declaration |
| Uses many registers (up till 6) to store arguments before placing all of them onto the stack together for a function call. If there are more than arguments, this will have to be done more than once (specifically, `n//6` times, where `n` is the number of arguments) | Uses a single register to repeatedly place arguments onto the stack (or just pushes it directly if possible) before a function call |

Regarding the last point, you will realize it if you stare at the separate assemblies of the two binaries in gdb. 

I am also not completely certain about the second point. 

### Stack Alignment before Procedure Call

Another interesting difference (that is unrelated to the offsets of local variables) is that the binary compiled with clang doesn't align `esp` for every function call, while that compiled with gcc always aligns `esp` to the 16-byte boundary before procedure calls. 

## Questions

### Loading of NX addresses into `eip`

In x86-64 binaries, addresses of NX segments are not loaded into `rip` (a segmentation fault occurs when attempting to put that value into `rip`). However, in this binary, the address of an NX segment can be loaded into `eip`

My question is, is this difference due to the binary being x86 (32-bit), due to it being compiled in clang, or due to something else?

#### Update: Not due to clang / gcc

In both 32-bit clang and gcc, loading of NX addresses into `eip` occurs, so this is unlikely to have arisen from that compiler difference. 