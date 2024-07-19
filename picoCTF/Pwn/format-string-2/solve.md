# format string 2

Format-string Exploit (Writing to data segment)

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/format-string-2/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE so the address of the data segment we need to write to will not change

## Core Idea

We want to write the value `0x67616c66` to a global variable `sus` (which is initialized to `0x21737573`) using a format-string exploit. 

Since there is no PIE, we can take the address of `sus` from gdb, which is `0x404060`. 

## How to Arb Write with Format Strings

We can perform arbitrary writes using a format string vulnerability due to the `%n` specifier, which writes the current number of characters printed to a signed integer pointer argument. 

Note that the need for a *signed integer pointer* argument only exists for validation by the compiler. During execution, `printf` simply plucks off the address from the variable argument list and writes the number of characters already printed as a signed 32-bit integer into that address in little-endian. 

Additionally, from [printf documentation](https://cplusplus.com/reference/cstdio/printf/), we see that 
1. The `%{i}$n` format allows us to indicate that the `i`-th argument should be used as the address to which the signed integer/short/char should be written. 
2. The `%hn` and `%hhn` specifiers allow us to write to the specified address with respective granularities of 2 and 1 bytes (instead of 4) i.e. allowing for the writing of a signed short / char instead of a signed int. 
3. The `%{i}$c` specifier allows for the printing of `i` characters (by default, this is the space character). 

Therefore, if we pass in the following string

```c
%256$c%7$n
```

Then `0x100` will be written as a signed integer into the 7th 64-bit argument in `printf`'s variable argument list, interpreted as an address. 

## Offsets

From staring at the assembly, the following buffers are at these addresses relative to the stack frame

```c
rbp-0x410 => buf
rbp-0x450 / rsp => flag 
```

Notice from [vuln.c](./vuln.c) that `printf(buf)` is called with one argument. So `%6$p` will start pulling off the stack and leaking the uninitialized (and thus not useful) `flag` buffer, since that refers to the seventh argument in the variable argument list of `printf`. 

To control the addresses that we write to, we need to specify arguments to be taken from `buf`. Since `buf - flag = 64`, we see that the first 8 bits of `buf` is referenced with `%14$p` (since `6 + 8 = 14`), or can be interpreted as an address to be written to with `%14$n`. 

If we leave 32 = 4 * 8 bytes for the format specifier portion of our payload i.e. the `%{i}$c%{j}$n...` portion, and start dumping addresses to write to after that 32 bytes, then the first address is referenced with `%18$n` (since `14 + 4 = 18`). 

## Payload

We split the writing into `sus` into 2 writes of 2 signed shorts, and thus the payload is 

```bash
[*] payload=b'%26465c%18$hn%1285c%19$hnAAAAAAAb@@\x00\x00\x00\x00\x00`@@\x00\x00\x00\x00\x00'
```

Note that the number of characters printed accumulates. Thus we are writing `26465` to `0x404062` as a signed short, and the signed short `26465 + 1285 = 27750` to `0x404060`. 

## Flag

Some Python scripting then allows us to get the flag

```bash
[+] Opening connection to rhea.picoctf.net on port 59762: Done
[*] payload=b'%26465c%18$hn%1285c%19$hnAAAAAAAb@@\x00\x00\x00\x00\x00`@@\x00\x00\x00\x00\x00'
b'picoCTF{f0rm47_57r?_f0rm47_m3m_e371fb20}'
```