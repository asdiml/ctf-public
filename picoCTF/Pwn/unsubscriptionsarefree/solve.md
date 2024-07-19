# Unsubscriptions Are Free

Simple Use-After-Free (UAF) heap exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/unsubscriptionsarefree/vuln_patched'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

In the hints, a link is also provided to a lecture about Double Free attacks. 

## Running the binary

When attempting to run `vuln_patched`, we get

```bash
user@host:.../unsubscriptionsarefree$ ./vuln_patched

-bash: ./vuln_patched: No such file or directory
```

which is because it is a 32-bit ELF, i.e. 

```bash
user@host:.../unsubscriptionsarefree$ file vuln_patched

vuln_patched: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=89699d062dc4f47448ba7c5c03105267c060ce30, not stripped
```

Installing the required dynamic linker simply involves installing the `lib32z1` library: 

```bash
sudo apt-get install lib32z1
```

## Understanding the Binary

The binary first dynamically allocates memory for a `user` object and then provides us with the following options for further interaction

```c
void printMenu(){
 	puts("Welcome to my stream! ^W^");
 	puts("==========================");
 	puts("(S)ubscribe to my channel");
 	puts("(I)nquire about account deletion");
 	puts("(M)ake an Twixer account");
 	puts("(P)ay for premium membership");
	puts("(l)eave a message(with or without logging in)");
	puts("(e)xit");
}
```

A summary of the options is as follows:

1. Option `S` leaks the win address which is a function called `hahaexploitgobrrr`, but requires that the `user` object has not been freed. 
2. Option `I` frees the `user` object
3. Option `M` sets the `username` property of the `user` object based on user input
4. Option `P` just prints a string and does nothing
5. Option `l` allocates a chunk of (at least) 8 bytes and dumps its contents to stdout
6. Option `E` exits the program immediately

<br>

## Concept behind the Exploit

The concept behind the exploit is that we want to exploit the Use-After-Free bug in the binary to obtain writing privileges into a dynamically-allocated object that we would not have originally have had write access to. 

Specifically, to solve this challenge, we

0. Leak the win address (Optional because there is no PIE)
    - use option `S`
1. Free the `user` object
    - use option `I`
2. Reallocate a new object (which we have write privileges to) that occupies the same physical address as the freed `user` object
    - use option `l` which `read`s from stdin to the newly-allocated buffer

<br>

Step 2 works because the tcache bin holds the freed `user` object, so reallocating heap memory for an object of the same size (examine the `leaveMessage` function) guarantees that it is the freed `user` object that will be reallocated. 

As the once-freed `user` object is then used (since there is no bookkeeping of freed pointers, or them being set to null), we write the win function's address into the first 4 bytes of `user` for its execution. 

## Flag

```bash
[+] Opening connection to mercury.picoctf.net on port 50361: Done
b'picoCTF{d0ubl3_j30p4rdy_868227ee}\n'
```