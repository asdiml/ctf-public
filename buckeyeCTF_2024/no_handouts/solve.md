# no_handouts

rop2syscall

## checksec

```
[*] '/mnt/d/CTFs/buckeyeCTF_2024/no_handouts/program/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

There is PIE, so unless the address of the main executable is leaked, we're unable to use ROP gadgets from it. 

## Main Difficulty

The binary runs in a [chroot jail](https://phoenixnap.com/kb/chroot-jail), so there exists no `/bin/sh` (as well as the other usual binaries that exist in a Linux OS such as `cat`) for system to run. 

## Concept

Since the address of `system` is leaked (and we are provided the libc used), we can use that to obtain the libc base address (by subtracting the offset of `system` from the leaked address), and from there use any ROP gadgets within libc. 

The ROP chain implemented in `solve.py` basically conducts the following syscalls
1. `open("flag.txt", O_RDONLY)`, where O_RDONLY = 0, and
2. `sendfile(1, 3, NULL, 0x100)`. 

The 1st syscall opens `flag.txt` and returns a fd (which will be 3 since only 0, 1 and 2 are used), while the 2nd syscall sends 0x100 bytes from fd 3 (opened file) to fd 1 (stdout). This leaks the flag without requiring that `system("/bin/sh")` or `execve("/bin/sh")` be called. 

## Caveat about running `solve.py` locally

If there is no `flag.txt` in the `./program` directory, there will be no output from the script because pwntools does not read stderr. 