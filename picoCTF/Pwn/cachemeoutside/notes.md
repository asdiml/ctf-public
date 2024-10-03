## Reading up on Tcache Exploitation

https://hackmd.io/@5Mo2wp7RQdCOYcqKeHl2mw/ByTHN47jf

## Ghidra Hotkeys
1. `L` to rename variables / functions
2. `Ctrl-L` to retype variables

## Manual Patching

```bash
patchelf --set-interpreter ./ld-2.27.so ./heapedit
```

Since loader ld-2.27.so is not provided, we can first use `pwninit` to obtain it (although running this will also do the patching for you), or get it from `/lib64/ld-linux-x86-64.so.2` in most Unix systems. 

Then we have

```bash
$ ldd heapedit_patched

> linux-vdso.so.1 (0x00007fff6aa84000)
> libc.so.6 => ./libc.so.6 (0x00007f4ba9c00000)
> s./ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007f4baa0f4000)
```

## Running with provided libc

```bash
LD_PRELOAD=./libc.so.6 ./heapedit
```

The LD_PRELOAD environment variable allows us to specify the libraries to be dynamically linked (loaded) into the executable. 

## Heap-related Commands in gef

```
heap chunks    // Returns chunks allocated on the heap
heap chunk <addr>    // Returns information about the chunk starting at addr
```

## Conventions on the Heap

`ptmalloc` will typically allocate memory to chunks where the 8-byte header (that contains the size of the chunk as well as the A,M,P bits) starts from an address that ends with 0x8 e.g. 0x7fffffff0008. 

See below for the layout of an allocated chunk on the heap

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

For the alignment of potentially complex data structures on the heap, on 64-bit systems, the heap is 16-bit aligned, and for 32-bit systems, the heap is 8-bit aligned. This is done by rounding up the number of bytes of memory allocated. 

The pointer returned by `ptmalloc` points to the `mem` section, not the beginning of the chunk which would be the `chunk` section. 

## Understanding tcache

**USAGE PREREQS: libc-2.26.so onwards**

_tcache_ stands for thread-local cache, where the thread-local nature is specifically to overcome race conditions. It caches, for that thread, the chunks of memory freed from the heap, improving performance since `ptmalloc` is an expensive operation which requires a significant degree of enumeration of the free chunks on the heap. 

The following illustrates the structure of the tcache for a single thread: 

```c
/* There is one of these for each thread, which contains the
    per-thread cache (hence "tcache_perthread_struct").  Keeping
    overall size low is mildly important.  Note that COUNTS and ENTRIES
    are redundant (we could have just counted the linked list each
    time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

> **NOTE:** Bear with how the concepts and data structures are floating around, and just read through this - it will get clearer with the explanation below. 

From the code above, it can be elucidated that the tcache is simply a list of counts (which are byte-sized integers stored as chars) which corresponds with a list of pointers to tcache entries. 

These tcache entries are the addresses of freed chunks from the heap. The tcache itself also usually exists as a chunk on the heap. 

### counts

First, observe that by default, `TCACHE_MAX_BINS` is set to be 64 (in the glibc source code). 

```c
# define TCACHE_FILL_COUNT 7
# define TCACHE_MAX_BINS 64
```

The `counts` array in `tcache_perthread_struct` thus has 64 elements. Specifically, the array stores, consecutively, the number of freed chunks of sizes 24 bytes to 1032 bytes, in 16-byte increments (for 64-bit systems). For 32-bit systems, the sizes are 12 bytes to 516 bytes, in 8-byte increments. 

Note that this size value includes the size field of the chunk (which is an 8-byte / 4-byte field), so the `malloc` call that allocated that chunk must have requested for a number of bytes that, rounded up to a multiple of 16, is `n-8` bytes. 

For example, in x86-64, the numerical value of the char `counts[4]` would be the number of freed chunks of size 88 stored in (or more specifically, tracked by) that particular tcache. 

### entries

The i-th `tcache_entry` pointer in `entries` is the head pointer to the LIFO (last in, first out) singly-linked list of `counts[i]` freed chunks of size `24 + i*16` on the heap. 

We call this singly-linked list of tcache chunks of a particular size a bin. 

The head pointer points directly to the first freed chunk (that exists on the heap) tracked in the tcache. This is because each tcache chunk of a particular size contains a pointer to the next tcache chunk in that bin (that pointer is in fact the first 8-byte data field in the tcache chunk struct). 

Note that each tcache bin can, by default, contain at most 7 chunks (as dictated by the `TCACHE_FILL_COUNT` preprocessor definition previously shown). 