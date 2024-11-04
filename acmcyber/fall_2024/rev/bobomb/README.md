# bobomb

x86asm Reverse Engineering, Modular Division

## Overview of Binary

Within the `foo` function of the source, [bobomb.c](./bobomb.c), we see that the upper and lower 32 bits of our input (which is stored in rdi because it is the first argument) are separated into rdx and rcx respectively. 

```c
"mov ecx, edi\n" // rcx is the lower 32 bit of rdi
"mov rdx, rdi\n"
"shr rdx, 32\n" // rdx is the upper 32 bit of rdi
```

Next, rcx is XOR-ed with 0x42 while rdx is multiplied by 7 and 0xd added to it (in `bar` and `baz`), before they are swapped. 

```c
"mov rsi, 0\n"
".lbl:\n"
"xor ecx, 0x42\n" // ecx = input_lower32 ^ 42
"mov edi, edx\n" // edi = input_upper32
"call bar\n"
"push rax\n" // input_upper32 * 7 + 0xd
"push rcx\n" // input_lower32 ^ 42
"pop rdx\n"  // rdx = input_lower32 ^ 42
"pop rcx\n"  // rcx = input_upper32 * 7 + 0xd)
"inc rsi\n"
"cmp rsi, 5\n"
"jl .lbl\n"
```

This loop runs 5 times, such that in the end

```python
rdx = ((((input_lower32 ^ 0x42) * 7 + 0xd) ^ 0x42) * 7 + 0xd) ^ 0x42
rcx = ((((input_upper32 * 7 + 0xd) ^ 0x42) * 7 + 0xd) ^ 0x42) * 7 + 0xd
```

Finally, the function checks if `ecx = 0xa0a68f32` and `edx = 0x69cac977`. If either of these conditions fail, then the resulting ecx and/or edx will not be 0 and result in eax not being 0. 

```c
"xor eax, eax\n"
"xor ecx, 0xa0a68f32\n" // We need ecx = 0xa0a68f32
"xor edx, 0x69cac977\n" // We need edx = 0x69cac977
"or eax, ecx\n"
"or eax, edx\n"
// rax is the return value
"ret\n"
```

We want the return value to be 0 in `main`, so we need both `ecx = 0xa0a68f32` and `edx = 0x69cac977` to hold. 

## Reverse Engineering `foo`

Instead of trying to code 2 separate functions to separately reverse the value of the upper and lower 32 bits of the input number required, recall from earlier that 

```python
rdx = ((((input_lower32 ^ 0x42) * 7 + 0xd) ^ 0x42) * 7 + 0xd) ^ 0x42
rcx = ((((input_upper32 * 7 + 0xd) ^ 0x42) * 7 + 0xd) ^ 0x42) * 7 + 0xd
```

where the same 2 operations take turns to be applied to `input_lower32` and `input_upper32`. 

So only one function needs to be coded that should be able to reverse both types of operations - we only need specify which type of operation undoing is should begin with, before it can undo 5 operations, switching between operations after every operation. 

### Modular Division

Part of the reverse engineering process requires a division by 7. However, is it unlikely that every number that needs to be divided by 7 in the reversing will be divisible by 7 - if it is not, then truncating the remainder will result in an input that will not allow us to obtain the correct output. 

However, note that since edi is used as shown below, the imul output is always modulo 2^32. 

```c
__attribute__((naked)) unsigned int baz(unsigned int) {
    __asm__(
        ".intel_syntax noprefix\n"
        "add edi, 13\n"
        "mov eax, edi\n"
        "ret\n"
        ".att_syntax");
}

__attribute__((naked)) unsigned int bar(unsigned int) {
    __asm__(
        ".intel_syntax noprefix\n"
        "imul edi, 7\n"
        "call baz\n"
        "mov eax, edi\n"
        "ret\n"
        ".att_syntax");
}
```

We can therefore use modular division (where the modulus is 2^32) to reverse the `imul edi, 7` instruction. 

This can be done by first finding the modular inverse of 7 mod 2^32. I used the Extended Euclidean algorithm in [solve.py](./solve.py), but you can just use `pow(7, -1, 2^32)` instead. 

To explain what a modular inverse is, consider some integer $a$. Its modular inverse (which we want to be a positive integer because edi is treated as unsigned value, although it does not, by its Mathematical definition, have to be), $x$, is then given by

$$ ax \equiv 1 \hspace{0.5em} (mod \hspace{0.5em} m)$$

Note that the modular inverse of some integer $a$ only exists if $gcd(a,m)=1$. We know that this is definitely the case since $a=7$ and $m=2^{32}$. 

Then the result of the modular division of some integer $i$ by 7 mod 2^32 is given by

$$ ix \hspace{0.5em} (mod \hspace{0.5em} m) $$

where $x$ is the modular inverse of 7 mod 2^32. This second part is trivial to prove simple because it directly applies the rule for multiplication in modular arithmetic. 

### Implementation

Our final function to reverse engineer the input is

```python
def rev_eng(num_32bit, undo_xor_first = 0):

    def undo_xor(num): 
        return num ^ 42
    def undo_mul_and_add(num): 
        return modDivide(num-0xd, 7, 2**32) % 2**32

    operations = [undo_mul_and_add, undo_xor]
    for i in range(undo_xor_first, 5 + undo_xor_first):
        num_32bit = operations[i%2](num_32bit)
        log.info(f"{hex(num_32bit)=}")
    
    return num_32bit
```

where the `undo_xor_first` named argument will be set based on whether the `^ 0x42` or `* 7 + 0xd` should be undone first. 

## Flag

```python
[+] Opening connection to box.acmcyber.com on port 31442: Done
[*] num64=13371337133713371337
[*] Switching to interactive mode
cyber{x86_rocks}
```