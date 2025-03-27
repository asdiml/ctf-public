## C++ Pwn

[Blog by ptr-yudai](https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732)

## FSOP

FSOP-related readings
1. https://ctf-wiki.mahaloz.re/pwn/linux/io_file/fsop/
2. https://www.slideshare.net/slideshow/play-with-file-structure-yet-another-binary-exploit-technique/81635564

### _IO_flush_all_lockp

[GLIBC 2.23 `_IO_flush_all_lockp` source code](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/genops.c#L759) from Bootlin

- This function definition isn't actually detected, you have to scroll up from `_IO_flush_all`

## x86 Assembly

[x86 Opcode Cheasheet](https://pnx.tf/files/x86_opcode_structure_and_instruction_overview.pdf)

## ASLR

[Paper: ASLR Smack and Laugh reference](https://www.cs.umd.edu/~jkatz/security/downloads/ASLR.pdf)

## Control Flow Integrity (CFI)

[Paper: Control Flow Integrity - Principles, Implementations and Applications](https://www.cs.columbia.edu/~suman/secure_sw_devel/p340-abadi.pdf)