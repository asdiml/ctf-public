# heap-3

Use-After-Free exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/heap-3/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## General Description of Constraints

To win in the `check_win` function, we need the `flag` c string of the following object

```c
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;
```

to contain the string "pico". In the `init` function, we see that in dynamically-allocated memory, `x->flag` is set to "bico" instead of "pico". 

```c
x = malloc(sizeof(object));
strncpy(x->flag, "bico", 5);
```

`x` is a pointer to an object of type `object`. We therefore need a method of overwriting the `flag` data member of `x`. 

However, the only opportunity for user input is in the binary's `alloc_object` function, which lets input the size to allocate as well as the entirety of what will be stored into the user data segment of that chunk. 

Fortunately, we are allowed to free `x`, and `x` isn't checked if it is freed in the `check_win` function. We can therefore exploit this Use-After-Free bug to win by writing to the memory location of `x`. 

## General Overview of Exploit

Steps of Exploit
1. Free `x`
2. `malloc` a new object of the same size (35 bytes) and write 'p' into the 31st byte (first character of `x.flag`)
3. Call `check_win`
4. Win

The pre-freeing address of `x` will be returned by `malloc` in step 2 due to how tcache works to improve the performance of `malloc` (see these [notes](../cachemeoutside/notes.md)). In short, freed chunks are cached (tracked) for efficient reallocation should a new allocation require a chunk of the same size. Thus, by `malloc`-ing a chunk of the same size as `x` (and since `x` is the only chunk of that size, rounded to the nearest highest multiple of 16, freed), we guarantee that the pointer returned is the memory address of `x`. 

## Flag

```bash
[+] Opening connection to tethys.picoctf.net on port 53908: Done
b'YOU WIN!!11!!\npicoCTF{now_thats_free_real_estate_79173b73}'
[*] Closed connection to tethys.picoctf.net port 53908
```