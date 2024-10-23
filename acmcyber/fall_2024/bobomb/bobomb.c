#include <stdio.h>

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

__attribute__((naked)) unsigned int foo(unsigned long long) {
    __asm__(
        ".intel_syntax noprefix\n"
        "mov ecx, edi\n"
        "mov rdx, rdi\n"
        "shr rdx, 32\n" // rdx is the upper 32 bit of rdi
        "mov rsi, 0\n"
        ".lbl:\n"
        "xor ecx, 0x42\n" // ecx = input_lower32 ^ 42
        "mov edi, edx\n" // edi is the upper 32 bit of input
        "call bar\n"
        "push rax\n" // input_upper32 * 7 + 0xd
        "push rcx\n" // input ^ 42
        "pop rdx\n"  // rdx = (((input_lower32 ^ 42) * 7 + 0xd) ^ 42) * 7 + 0xd) ^ 42
        "pop rcx\n"  // rcx = (((input_upper32 * 7 + 0xd) ^ 42 * 7 + 0xd) ^ 42) * 7 + 0xd
        "inc rsi\n"
        "cmp rsi, 5\n"
        "jl .lbl\n"
        "xor eax, eax\n"
        "xor ecx, 0xa0a68f32\n" // We need ecx = 0xa0a68f32
        "xor edx, 0x69cac977\n" // We need edx = 0x69cac977
        "or eax, ecx\n"
        "or eax, edx\n"
        // rax is the return value
        "ret\n"
        ".att_syntax");
}

void print_flag(void) {
    FILE *flag_file = fopen("flag.txt", "r");
    if (!flag_file) {
        puts("flag.txt not found");
        return;
    }
    char flag[256];
    fgets(flag, sizeof flag, flag_file);
    puts(flag);
    fclose(flag_file);
}

int main(void) {
    setbuf(stdout, NULL);
    printf("enter x: ");
    unsigned long long x;
    // read an unsigned decimal integer into x
    if (scanf("%llu", &x) != 1) {
        puts("input error");
        return -1;
    }
    if (foo(x) == 0) {
        print_flag();
    } else {
        puts("bobooom!");
    }
}
