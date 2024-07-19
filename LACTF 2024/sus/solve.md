# sus

ROP to libc

## checksec

```bash
[*] '/mnt/d/CTFs/LACTF 2024/sus/sus_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
```

NX enabled, so we cannot write our own shell code in the buffer

While the executable has no PIE, system-wide ASLR will still be applied to libc. Thus, unless system-wide ASLR is disabled (or we can find the pieces for our ROP chain to get the flag entirely from within the binary), we will need to find the base address of libc. 

## Dumping the GOT with gef

The GOT can be dumped with gef with the command `got` as follows

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 3

[0x404000] puts@GLIBC_2.2.5  →  0x401036
[0x404008] setbuf@GLIBC_2.2.5  →  0x401046
[0x404010] gets@GLIBC_2.2.5  →  0x401056
```

which tells us that we can extract the address of the libc `puts` at runtime by passing the pointer 0x404000 as the first argument into `puts`. 

More specifically, the little endian representation of the libc `puts` address will always end with two null bytes, and that is why `puts` will print it out in its entirety. If we get unlucky and ASLR randomizes `puts` to an address that contains a null byte (highly unlikely), then we simply need to try again. 

## Leaking the Base Address of libc

By tinkering around with the executable with a DeBrujin sequence, we realize that part of our buffer (specifically 56 bytes from the start) is written into rdi. 

We are thus able to stick the address of the GOT for `puts` into rdi. 

To leak the libc address of `puts`, we simply need to call `puts` with the first argument (rdi) set as such. Therefore, we need to overwrite the return address with the address of `puts@plt`. 

The return address is 72 bytes from the start of the buffer (using again a DeBrujin sequence), so the payload is as follows

```python
b'A'*56 + p64(exe.got.puts) + b'A'*8 + p64(exe.symbols.puts)
```

We should note that `exe.symbols.puts` in pwntools is the same as `exe.symbols.plt.puts` since pwntools pulls PLT entries from the .plt.sec section. 

The libc base address can then be done by substracting the offset from base of `puts` in the libc of the pwn environment from the leaked address, as follows

```python
libc.address = u64(r.recvline().strip().ljust(8,b'\x00')) - libc.symbols.puts
```

Note that the base address of libc should always end in 000 because libc is aligned to a page, and the size of a page is 0x1000. 

## Reopening the Attack Vector

On one run of the executable, we are only allowed to send one payload. Thus, to reopen the attack vector, we need to call `_start()` so that we can inject another payload after leaking the address of libc. 

The first payload therefore is

```python
b'A'*56 + p64(exe.got.puts) + b'A'*8 + p64(exe.symbols.puts) + p64(exe.symbols._start)
```

## Final Payload

Our objective is to get the program to run `exec('/bin/sh')`, so all we need to do is to load the `/bin/sh` string into rdi (loading into rdi was already shown earlier), and call the `system` function in libc using the leaked libc base address. 

The final payload thus is 

```python
b'A'*56 + p64(next(libc.search(b'/bin/sh'))) + b'A'*8 + p64(ret) + p64(libc.symbols.system)
```

Note that the `ret` gadget is a simple one-instruction return gadget for the purpose of aligning `rsp` to the 16-byte boundary during the call to `system`. 