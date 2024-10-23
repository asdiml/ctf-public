{
# the code below reads 0x30 bytes from stdin
# into the memory pointed to by $rsp using the read syscall on linux.
# you don't have to worry about understanding syscalls for this challenge
''
}
sub rsp, 0x30
mov eax, 0
mov edi, 0
mov rsi, rsp
mov edx, 0x30
syscall

{
# the following code loads the input into registers 8 bytes at a time.
# for example, if your first 8 bytes are "AAAABBBB", $rax will contain
# the integer value 0x4242424241414141. 
# this happens because x86 uses little-endian storage, which means that 
# the least significant bytes of some value are stored at lower memory addresses.
# when your input is read into memory consecutively by the read syscall,
# the first bytes you send ("AAAA" or 0x41414141) are stored at lower addresses,
# and thus correspond to less significant values in $rax
''
}
mov rax, qword ptr [rsp]
mov rbx, qword ptr [rsp+8]
mov rcx, qword ptr [rsp+0x10]
mov rdx, qword ptr [rsp+0x18]
mov rdi, qword ptr [rsp+0x20]
mov rsi, qword ptr [rsp+0x28]

{
# below contains the arithmetic logic that
# you will need to understand to solve the challenge
''
}
mov r8, 0xdeadbeefcafebabe
xor rax, r8   # First 8 bytes should be p64(0xdeadbeefcafebabe ^ 0xb6dac59daf9cc3dd)

mov r9, rbx
mov r10, rbx
add r10, 0x1337
sub r9, 0x7331
add r10, r9
mov r15, 0xc0dec0dec0dec0de
xor r10, r15 # Second 8 bytes should be p64(((0xc0dec0dec0dec0de ^ 0x28600a3a0a309e26) - (0x1337 - 0x7331)) >> 1)

xor r11, r11
or r11, rcx
mov r15, 0xffffffff
and r11, r15 # r11 = Lower 32-bits of 3rd quadword of input
xor r12, r12
add r12, rcx
shr r12, 32 # r12 = Upper 32-bits of 3rd quadword of input
mov r15, 0xc001c0de
xor r12, r15
mov r15, 0x99999999
xor r11, r15 # Third 8 bytes should be p32(0x99999999 ^ 0xfcebfcf1) + p32(0xc001c0de ^ 0x9f6eae81)

mov rcx, rdx
xor rcx, 1
sub rcx, 0x41414141 # Fourth 8 bytes should be p64((0x514c4b430f0d1410 + 0x41414141) ^ 1)

mov r8, rbx
mov rbx, rdi
imul rbx, 2
mov r15, 0x123456789 
xor rbx, r15 # Fifth 8 bytes should be p64((0x123456789 ^ 0xe4e8e6ddf1fbc501) >> 1)

mov r13, rsi
and r13, r13
xor r13, 3
mov r14, r13
mov r15, 0x1010101010
sub r14, r15
xor r14, r8 # Last 8 bytes should be p64(((0x745f657265775f79 ^ 0x92c0b2d3c130c1f) + 0x1010101010) ^ 3)

{
# the `cmp reg1, reg2` followed by `jne` will only make
# the jump if the registers don't equal each other
''
}
mov rsi, 0xb6dac59daf9cc3dd
cmp rax, rsi
jne incorrect
mov rsi, 0x28600a3a0a309e26
cmp r10, rsi
jne incorrect
mov rsi, 0xfcebfcf1
cmp r11, rsi
jne incorrect
mov rsi, 0x9f6eae81
cmp r12, rsi
jne incorrect
mov rsi, 0x514c4b430f0d1410
cmp rcx, rsi
jne incorrect
mov rsi, 0xe4e8e6ddf1fbc501
cmp rbx, rsi
jne incorrect
mov rsi, 0x92c0b2d3c130c1f
cmp r14, rsi
jne incorrect
jmp correct

incorrect:
{
# this prints "wrong" to stdout
''
}
mov rax, 0xa676e6f7277
push rax
mov eax, 1
mov edi, 1
mov rsi, rsp
mov edx, 6
syscall
jmp exit

correct:
{
# this prints "right" to stdout
''
}
mov rax, 0xa7468676972
push rax
mov eax, 1
mov edi, 1
mov rsi, rsp
mov edx, 6
syscall
jmp exit

exit:
{
# this exits the program
''
}
mov eax, 231
xor edx, edx
syscall
