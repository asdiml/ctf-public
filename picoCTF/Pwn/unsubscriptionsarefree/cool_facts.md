## 16-byte Stack Alignment before Call

The `processInput` function starts off as follows

```c
void processInput(){
  scanf(" %c", &choice);
  ...
}
```

which up to the `scanf`, is disassembled to give the following assembly

```x86asm
0x08048bd5 <+0>:     push   ebp
0x08048bd6 <+1>:     mov    ebp,esp
0x08048bd8 <+3>:     push   ebx
0x08048bd9 <+4>:     sub    esp,0x4
0x08048bdc <+7>:     call   0x8048710 <__x86.get_pc_thunk.bx>
0x08048be1 <+12>:    add    ebx,0x241f
0x08048be7 <+18>:    sub    esp,0x8
0x08048bea <+21>:    mov    eax,0x804b064
0x08048bf0 <+27>:    push   eax
0x08048bf1 <+28>:    lea    eax,[ebx-0x2081]
0x08048bf7 <+34>:    push   eax
0x08048bf8 <+35>:    call   0x80486a0 <__isoc99_scanf@plt>
0x08048bfd <+40>:    add    esp,0x10
```

Note that the call to `__x86.get_pc_thunk.bx` is for purposes of enabling PIE, as this allows for the obtaining of the instruction address (of the next instruction, which is `0x08048be1` in this PIE-disabled gdb-run instance), which certain global variables in the data segment are a fixed offset from. 

I was initially particularly confused at instructions `0x08048bd9` and `0x08048be7`, which seem to allocate stack space for no apparent reason, before (e.g. at instruction `0x08048bfd`) deallocating the stack without using that space. 

The [following StackOverflow post](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f#:~:text=x86%2D32%20Function%20Calling%20convention,functions%20on%20Linux%20from%20assembly) addresses this with the following paragraph: 

```
Modern versions of the i386 System V ABI (used on Linux) require 16-byte alignment of %esp before a call, like the x86-64 System V ABI has always required. Callees are allowed to assume that and use SSE 16-byte loads/stores that fault on unaligned. But historically, Linux only required 4-byte stack alignment, so it took extra work to reserve naturally-aligned space even for an 8-byte double or something.

...
```

This is thus a convention of the i386 System V ABI. 

Extra note: Before a function call, `esp` will be 4 mod 16. This so that `esp` will be aligned to the 16-byte boundary upon the call (which pushes the return address onto the stack thereby decrementing `esp` by 4). 
