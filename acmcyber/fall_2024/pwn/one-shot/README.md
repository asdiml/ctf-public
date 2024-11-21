# one_shot

onegadget

## checksec

```python
[*] '/mnt/c/CTFs/acmcyber/fallgm_2024/one_shot/oneshot'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Nothing exploitable to be seen here - we're supposed to use a One Gadget. 

## Concept

This challenge involves figuring out the base address of libc (where it was loaded) from a leak of `stdin` (which is a pointer into libc) and then getting the binary to call the One Gadget in libc. 

A One Gadget is a `execve(“/bin/sh”, 0, 0);` call in any executable segment of a process' vaddr space, that if jumped to, immediately spawns a shell for us. 

One Gadgets used to exist in older versions of libc (such as the one provided), but were patched out in subsequent versions for obvious security reasons. 

### one_gadget constraints

The One Gadget finding tool, `one_gadget`, can be found at the link https://github.com/david942j/one_gadget. 

To install the tool (there is no need to clone the repo), just run

```
gem install one_gadget
```

and then run it on the provided libc. There are some constraints for each One Gadget found (see the following output of `one_gadget` on the provided libc)

```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

so if one doesn't work, try the others because the state of the registers at that point may only allow some (or one or none) of the One Gadgets to work. 

## Leaking the libc base address

From [oneshot.c](./oneshot.c), we see that the binary directly gives us the address of `stdin`. 

Note that this is a pointer into libc (i.e. the address is an address in the vaddr pages where libc is loaded to the process space) because the `stdin` and `stdout` FILE structs exist in libc. If more file descriptors are allocated due to, say, calls to `open`, then those FILE structs are allocated on the heap. 

### Figuring out the symbol of `stdin`

The libc symbol of `stdin` can be found using gef and stepping through the execution of [`oneshot`](./oneshot) until `stdin` is loaded into a register. 

The symbol was found to be `_IO_2_1_stdin_`. 

## Flag

```bash
[+] Opening connection to box.acmcyber.com on port 31389: Done
[*] hex(libc.address)='0x7456dc696000'
/mnt/c/CTFs/acmgmCTF_Fall_2024/one_shot/solve.py:33: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline(str(one_shot))
[*] Switching to interactive mode
 0)
shoot: $ cat flag.txt
cyber{old_glibcs_are_the_best_glibcs}
```

