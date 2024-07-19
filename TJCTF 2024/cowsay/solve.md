# cowsay

Format-string Exploit

## checksec

```bash
[*] '/mnt/d/CTFs/TJCTF 2024/cowsay/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Pointer to flag string

Observe in `main` that there is a convenient pointer to the flag string stored on the stack as a local variable

```c
char message[64];
char flag[64];
char *flag_pointer = flag;
```

The last statement in the above code block is translated into the following assembly

```assembly
0x000055555555520e <+69>:    lea    rax,[rbp-0x50]
0x0000555555555212 <+73>:    mov    QWORD PTR [rbp-0xa0],rax
```

which means that `flag_pointer` is stored at `[rbp-0xa0]`. 

We can thus simply use a format string exploit to leak the string which pointer lives at argument `6 + (0xc0 - 0xa0) * 8` of `printf`, since `rsp` is decremented by `0xc0` at the start of `main`. 

## Flag

tjctf{m0o0ooo_f0rmat_atTack1_1337}