## Purpose

This writeup serves to document the steps taken to manually unpack the UPX-packed `flag` binary into the output `flag_manually_unpacked` binary for future reference, as well as for a quick recap of a small tidbit of how executable packers work. 

## Reference

Steps were taken from these Medium articles on manually unpacking a UPX-packed ELF
- [Part 1](https://dlnhxyz.medium.com/manually-unpacking-a-upx-packed-binary-with-radare2-part-1-7039317c2ed8)
- [Part 2](https://dlnhxyz.medium.com/manually-unpacking-a-upx-packed-binary-with-radare2-part-2-be00860b5eac)

## Running `strace` to enumerate syscalls

We run a quick strace command (specifically `strace ./flag`) to see if the self-unpacking binary sets up the memory regions in a similar manner as in the [reference articles](#reference)

```
execve("./flag", ["./flag"], 0x7ffdc008ae90 /* 26 vars */) = 0
mmap(0x800000, 2959710, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 0, 0) = 0x800000
readlink("/proc/self/exe", ".../pwnable-kr/flag/flag", 4096) = 32
mmap(0x400000, 2912256, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
mmap(0x400000, 790878, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
mprotect(0x400000, 790878, PROT_READ|PROT_EXEC) = 0
mmap(0x6c1000, 9968, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0xc1000) = 0x6c1000
mprotect(0x6c1000, 9968, PROT_READ|PROT_WRITE) = 0
mmap(0x6c4000, 8920, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x6c4000
munmap(0x801000, 2955614)               = 0
uname({sysname="Linux", nodename="DESKTOP-6HU3MPK", ...}) = 0
brk(NULL)                               = 0x882000
brk(0x8831c0)                           = 0x8831c0
arch_prctl(ARCH_SET_FS, 0x882880)       = 0
brk(0x8a41c0)                           = 0x8a41c0
brk(0x8a5000)                           = 0x8a5000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fe5068ff000
write(1, "I will malloc() and strcpy the f"..., 52I will malloc() and strcpy the flag there. take it.
) = 52
exit_group(0)                           = ?
+++ exited with 0 +++
```

As done in the articles, we shall attempt to breakpoint at program execution after the `munmap` syscall (this only frees the virtual memory where the original packed executable was loaded) and concatenate the `mmap`-ed regions to form the unpacked binary. 

## Using gdb to create the Unpacked Binary

In gdb, we can set a catchpoint for the `munmap` syscall with the command

```
catch syscall munmap
```

Running the packed binary, we arrive the the catchpoint where the next instructions are

```
 ────
 →   0x40000e                  ret    
   ↳    0x401058                  xor    ebp, ebp
        0x40105a                  mov    r9, rdx
        0x40105d                  pop    rsi
        0x40105e                  mov    rdx, rsp
        0x401061                  and    rsp, 0xfffffffffffffff0
        0x401065                  push   rax
```

which tells us that the original entry point (OEP) is 0x401058. Typically, this is the `_start` function, where the address of `main` will be passed to `__libc_start_main` as its first argument, so dumping the instructions in `_start`, 

```
gef➤  x/12i 0x401058
   0x401058:    xor    ebp,ebp
   0x40105a:    mov    r9,rdx
   0x40105d:    pop    rsi
   0x40105e:    mov    rdx,rsp
   0x401061:    and    rsp,0xfffffffffffffff0
   0x401065:    push   rax
   0x401066:    push   rsp
   0x401067:    mov    r8,0x401ae0
   0x40106e:    mov    rcx,0x401a50
   0x401075:    mov    rdi,0x401164
   0x40107c:    call   0x4011b0
   0x401081:    hlt
```

we see that the address  of `main` is 0x401164 (recall from [solve.md](./solve.md#improvements-on-hindsight) that there is no PIE). Using this we could use solve the challenge, but here we're trying to unpack the binary. 

The memory regions are shown with `vmmap`, of which we are interested in the first two

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004c2000 0x0000000000000000 r-x 
0x00000000004c2000 0x00000000006c1000 0x0000000000000000 --- 
0x00000000006c1000 0x00000000006c7000 0x0000000000000000 rw- [heap]
0x0000000000800000 0x0000000000ad3000 0x0000000000000000 rwx 
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

We dump them, and concatenate them together to create the unpacked binary

```
gef➤  dump binary memory 1.bin 0x400000 0x4c2000
gef➤  dump binary memory 2.bin 0x4c2000 0x6c1000
gef➤  exit
asdiml@DESKTOP-XXXXXX:.../pwnable-kr/flag$ cat 1.bin 2.bin > flag_manually_unpacked
```

Unfortunately, when running the executable, we run into a segmentation fault

```
asdiml@DESKTOP-XXXXXX:.../pwnable-kr/flag$ ./flag_manually_unpacked
Segmentation fault
```

## Dealing with the segfault

TODO

## Last Notes

The `flag_manually_unpacked` binary that segfaults has been renamed `flag_manually_unpacked_segfault`. 
