#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
	setbuf(stdout, 0);
	char buf[0x100];
	printf("%p\n%p\n", printf, buf);
	read(0, buf, 0x200);
	open("flag.txt", O_RDONLY);
	asm volatile(
        "mov $0x1337, %%rax\n\t"
        "syscall\n\t"
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%r8,  %%r8\n\t"
        "xor %%r9,  %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"
        ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
	asm volatile(
		"pop %%rdx\n\t"
		"jmp *%%rdx\n\t"
		::: "rdx"
	);
}
