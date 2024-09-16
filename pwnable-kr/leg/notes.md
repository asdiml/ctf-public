## Differences between x86 asm and ARM asm

### Register-related
The return address from a function call is not stored on the stack - it is stored in r14, the Link Register. 

The base pointer of the stack (called the frame pointer is ARM) is stored in r11. 

### Instruction Sizes
While instruction sizes can vary in x86asm, instructions are always 4-bytes long in ARM and 2-bytes long in THUMB (although in some versions of THUMB instrs can also be 32-bit - these instrs are suffixed with `.w`). 

### Switching to THUMB state

The Branch Exchange, `bx`, or Branch Link Exchange, `blx`, instructions (as opposed to their `b` or `bl` analogues) are used to switch between ARM and THUMB states. 

`bx` and `blx` require a register argument, and will result in a switch to THUMB (or from THUMB back to ARM) if the least significant bit of register is turned on i.e. if lsb = 1. Basically, the lsb of that register toggles the THUMB flag of the CSPR (similar to EFLAG in x86). 

The tutorial https://azeria-labs.com/arm-conditional-execution-and-branching-part-6/ provides an example of how to switch from ARM to THUMB with a branch exchange instr: 

```armasm
add r3, pc, #1   @ increase value of PC by 1 and add it to R3
bx r3            @ branch + exchange to the address in R3 -> switch to Thumb state because LSB = 1
```

### Program Counter-related
In ARM asm, the program counter (PC) points two instructions ahead of the current instruction. This is because older ARM processors used to always fetch two instructions ahead of the currently-executed instruction, and ARM asm retains this definition to ensure backwards compatibility.

This is obviously different from x86 where the PC always points to the next instruction to be executed.

Note that in a debugger, however, the PC (shown in something like `info registers`) will still likely be shown to point to the current instruction (so that the debugger's internal implementation doesn't need to be changed). However, instructions such as

```armasm
mov r0, pc
```

will adhere to the 2-instructions-ahead definition. 

### Inverted Carry Flag for Borrow

> Remember that the overflow flag exists to indicate signed arithmetic overflow - i.e. indicating overflow should the operands be treated as signed!
>
> The carry flag is for **unsigned arithmetic overflow**. 

ARM uses an inverted carry flag for borrow (i.e. subtraction) whereby the carry flag is set whenever there is no borrow and clear whenever there is. This is unlike x86, which is the opposite i.e. the carry flag works as a borrow flag. 

This design decision makes building an ALU slightly simpler because subtraction works by taking the two's complement of the subtrahend (number being subtracted from the other number) and adding it to the minuend. Thus if there is no borrow (in the x86 sense) then this addition will overflow (which then can directly set the inverted carry flag), and vice versa. 

For example, for `5-3`, the addition that occurs is

```
   0101
 + 1101
=========
  10010
```

which overflows (thus directly setting the ARM inverted carry flag), indicating that the subtraction doesn't borrow. 

In terms of unsigned addition overflow, the x86 and ARM carry flags are identical. 

From https://azeria-labs.com/arm-data-types-and-registers-part-2/

> A carry occurs:
> - if the result of an addition is greater than or equal to 2**32
> - if the result of a subtraction is positive or zero
> - as the result of an inline barrel shifter operation in a move or logical instruction.
> 
> Overflow occurs if the result of an add, subtract, or compare is greater than or equal to 2**31, or less than -2\**31.

### "Third" Operand

The instruction syntax of an ARM asm instruction is as follows

```
MNEMONIC{S}{condition} {Rd}, Operand1, Operand2
```

where `Rd` is the register (destination) for storing the result. This `Rd`, however, is optional, thus giving the impression of an optional third operand. 

Yet `Operand2` is special as compared to `Operand1`. This is because it can take any of the following forms, whereas `Operand1` may only be a register or immediate value

```
#123                    - Immediate value (with limited set of values). 
Rx                      - Register x (like R1, R2, R3 ...)
Rx, ASR n               - Register x with arithmetic shift right by n bits (1 = n = 32)
Rx, LSL n               - Register x with logical shift left by n bits (0 = n = 31)
Rx, LSR n               - Register x with logical shift right by n bits (1 = n = 32)
Rx, ROR n               - Register x with rotate right by n bits (1 = n = 31)
Rx, RRX                 - Register x with rotate right by one bit, with extend
```

### Load-Store Model for Memory Access

In ARM asm, only load (LDR) and store (STR) can access memory - data must be loaded into a register before it can be operated on. This is unlike x86 where most instructions can directly access memory. 

Note that the direction of data movement is different for LDR as compared to for STR

```ARMasm
LDR R2, [R0]   @ [R0] - origin address is the value found in R0.
STR R2, [R1]   @ [R1] - destination address is the value found in R1.
```