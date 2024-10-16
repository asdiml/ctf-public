# heap-0

Heap Overflow

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/heap-0/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## General Overview of Binary

The source code is provided that contains the following, where INPUT_DATA_SIZE and SAFE_VAR_SIZE are both defined to be 5. 

```c
input_data = malloc(INPUT_DATA_SIZE);
strncpy(input_data, "pico", INPUT_DATA_SIZE);
safe_var = malloc(SAFE_VAR_SIZE);
strncpy(safe_var, "bico", SAFE_VAR_SIZE);
```

Note that requested number of bytes of memory space on the heap is rounded up to the nearest multiple of 16, so the `input_data` and `safe_var` chunks both have 16 bytes of usable space. If we also include the prior 8 bytes (to the usable portion) that contains metadata about the chunk like its size (see the [structure of an allocated heap chunk](#understanding-an-allocated-heap-chunk)), then the chunks are technically 24 bytes in size. 

Our input data is populated through the following function

```c
void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}
```

which allows us to keep writing past the end of the user data segment of the `malloc`-ed heap chunk. 

## Understanding an allocated heap chunk

An allocated heap chunk is generally of the following format

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Notice that the metadata before and after the user data segment (i.e. the `chunk` and `nextchunk` segments) are both individually 16 bytes in size. Specifically, it is to be noted that these segments overlap between adjacent chunks (i.e. the `chunk` segment of the current chunk occupies the same area of memory as the `nextchunk` segment of the next chunk). 

### Offset between User Data segments of the 2 Chunks

Recall that it was mentioned that the number of bytes of memory allocated is rounded up to a multiple of 16 so that the chunk can be aligned to the 16-byte boundary. This means that the double calls to `malloc` will each allocate 16 bytes (5 rounded up to 16). 

Combined with the 16 bytes of metadata between 2 chunks (it does not matter if they are allocated or freed), we see that user data portions of the two chunks are 32 bytes apart, as illustrated (with arbitrary addresses)

```
0x0000 -> User Data of input_data chunk
0x0010 -> Metadata (chunk segment of input_data, nextchunk segment of safe_var)
0x0020 -> User Data of safe_var chunk
```

This assumes that the `safe_var` chunk is allocated to an address immediately after the end of the first, but we can also see from the binary's output that this is true

```
Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x55d71a0866b0  ->   pico
+-------------+----------------+
[*]   0x55d71a0866d0  ->   bico
+-------------+----------------+
```

Note that the addresses given will change for every runtime due to ASLR of the entire heap onto a randomized page boundary. 

## Completing the Exploit

We are allowed to write directly into the start of the user data segment of the first chunk and overflow it till the user data segment of the second chunk, so it is relatively simple to win with some pwntools scripting. 

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/heap-0/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to tethys.picoctf.net on port 52908: Done
b'\n'
b'YOU WIN\n'
b'picoCTF{my_first_heap_overflow_4fa6dd49}\n'
```

## Note for heap-1 and heap-2

As [heap-1](../heap-1/) and [heap-2](../heap-2/) do not really explore exploitation of the **heap** further (but simply expand on the use of other, relatively simple Pwn concepts), there will be no `solve.md` writeup for those challenges. 