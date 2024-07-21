# flag

Reverse Engineering

## Fumbling Around

I was fumbling around in gef and Binary Ninja without much luck, where
- When I stepped through the instructions in gef, the program would seemingly randomly throw a segmentation fault. Yet if run normally, it would exit normally.  
- The command `readelf -h flag` produced the following output for **every single section**:

```
readelf: Warning: Section XX has an out of range sh_info value of XXXXXXXXXXX
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;which should absolutely not have been the case. 

Eventually, as should be done with all RE challenges, I got to running `strings` on the binary, and two long strings were eye-catching

```bash
asdiml@DESKTOP-XXXXXX:/mnt/c/CTFs/pwnable-kr/flag$ strings flag
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
...
```

It turns out that the binary is UPX-packed, and we need to unpack it. The `readelf` output now makes sense. When running the UPX-packed binary, the unpacking stub unpacks and recreates the original code from the compressed code (which aligns with the section headers of the ELF) before executing it.

It turns out that executable packers like UPX are commonly used by malware authors in an attempt to bypass detection by antivirus signatures. 

## Improvements on Hindsight

On hindsight, I should've used `checksec`, since it detects that the binary is UPX-packed

```bash
[*] '/mnt/c/CTFs/pwnable-kr/flag/flag'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
    Packer:   Packed with UPX
```

## Resources 

- [Dissecting manually unpacking a UPX-packed file](https://tech-zealots.com/reverse-engineering/dissecting-manual-unpacking-of-a-upx-packed-file/)

## Unpacking a UPX-packed Binary

With UPX installed, simply run

```
upx -d flag -o flag_unpacked
```

to unpack the `flag` binary with the output binary being `flag_unpacked`. 

## Overview of Unpacked Binary

The `main` function of the binary (from Binary Ninja) in Pseudo C is as follows

```c
int64_t main()
{
    _IO_puts("I will malloc() and strcpy the f…");
    sub_400320(__libc_malloc(0x64), flag);
    return 0;
}
```

Clicking `sub_400320` sufficiently many times (just 2 was enough for me actually) shows us that it is `strcpy`. 

When examining the assembly in gdb, we see that the returned pointer from `__libc_malloc` is stored on the stack (at `$rbp-0x8`). So we simply need to set a breakpoint after the call to `strcpy`, and then read the C string from the malloc-ed chunk. 

## Flag

We can't use `x/s $rbp-0x8` because that attempts to print the pointer as a string. 

Instead, we need to treat `$rbp-0x8` as a pointer to a long int so that the malloc pointer stored there can be dereferenced as a 8-byte numerical value. We then pass this numerical value to `x/s` so that what it points can finally be printed. 

A little convoluted, I know, but it gets the flag. 

```gdb
gef➤  x/s *(long int *)($rbp-0x8)
0x6c96b0:       "UPX...? sounds like a delivery service :)"
```

