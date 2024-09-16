# leg

ARM asm RE

## How to Win

From [leg.c](./leg.c), we see that we just need to pass in the sum of the results of calling `key1`, `key2` and `key3` to win

```c
int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
        
    ...
```

## `key1`

As a preamble to analyzing `key1`, some resources for learning ARM asm include [arm.md](../../Resources/Pwn/Linux_Pwn/arm.md) in the Resources section, as well as [notes.md](./notes.md) in this directory, which highlights some differences between x86asm and armasm. 

Back to `key1`. We realize that all the function is doing is returning the value of `pc` at an instruction within the function (by moving it into `r3` and then `r0`, which is usually the return register)

```armasm
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.
```

`r11` is akin to `ebp` or `rbp` in x86asm, and in [leg.asm](./leg.asm), we confirm that `r0` is indeed being referenced in `main` as the return value of `key1`. 

As noted in [notes.md](./notes.md#program-counter-related), however, the value of `pc` returned is not `0x8cdc` or `0x8ce0`. It is `0x8ce4`, which is 2 instructions ahead of the instruction referencing `pc`. 

Return value: 0x8ce4

## `key2`

```armasm
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
```

`key2` involves
1. a switch from ARM to THUMB (see [notes.md#switching-to-thumb-state](./notes.md#switching-to-thumb-state)),
2. returning the value of `pc` at a certain instr, incremented by 4. 

Return value: 0x8d0c

## `key3`

```armasm
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
```

`key3` simply returns the retaddr from itself as a subroutine. 

Return value: 0x8d80

## Answer

```python
>>> 0x8ce4 + 0x8d0c + 0x8d80
108400
```

## Flag

```bash
/ $ ./leg
Daddy has very strong arm! : 108400
Congratz!
My daddy has a lot of ARMv5te muscle!
```