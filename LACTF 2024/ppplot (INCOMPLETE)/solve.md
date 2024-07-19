# ppplot

???????????

## checksec

```bash
[*] '/mnt/d/CTFs/LACTF 2024/ppplot/ppplot'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All protections are turned on. The binary is also stripped, which can be checked with `file ppplot`. 

## Dealing with Stripped Binaries

We first run the command `info file` in gef to find the entry point, which gives the output

```bash
gef➤  info file
Symbols from "/mnt/d/CTFs/LACTF 2024/ppplot/ppplot_patched".
Local exec file:
        `/mnt/d/CTFs/LACTF 2024/ppplot/ppplot_patched', file type elf64-x86-64.
        Entry point: 0x1180
        0x000000000000065e - 0x0000000000000682 is .gnu.version
        0x0000000000000688 - 0x00000000000006b8 is .gnu.version_r
        0x00000000000062e0 - 0x0000000000006490 is .dynsym
        0x00000000000006b8 - 0x00000000000007a8 is .rela.dyn
        0x00000000000007a8 - 0x0000000000000898 is .rela.plt
        0x0000000000001000 - 0x000000000000101b is .init
        0x0000000000001020 - 0x00000000000010d0 is .plt
        0x00000000000010d0 - 0x00000000000010e0 is .plt.got
        0x00000000000010e0 - 0x0000000000001180 is .plt.sec
        0x0000000000001180 - 0x00000000000017d5 is .text
        0x00000000000017d8 - 0x00000000000017e5 is .fini
        0x0000000000002000 - 0x00000000000020b8 is .rodata
        0x00000000000020b8 - 0x000000000000212c is .eh_frame_hdr
        0x0000000000002130 - 0x0000000000002300 is .eh_frame
        0x0000000000003d70 - 0x0000000000003d78 is .init_array
        0x0000000000003d78 - 0x0000000000003d80 is .fini_array
        0x0000000000003f70 - 0x0000000000004000 is .got
        0x0000000000004000 - 0x0000000000004010 is .data
        0x0000000000004020 - 0x0000000000005440 is .bss
        0x0000000000006000 - 0x0000000000006200 is .dynamic
        0x0000000000006200 - 0x00000000000062df is .dynstr
        0x0000000000006490 - 0x00000000000064c0 is .gnu.hash
        0x00000000000064c0 - 0x00000000000064d7 is .interp
        0x00000000000064d8 - 0x00000000000064f8 is .note.ABI-tag
        0x00000000000064f8 - 0x000000000000651c is .note.gnu.build-id
        0x0000000000006520 - 0x0000000000006540 is .note.gnu.property
```

