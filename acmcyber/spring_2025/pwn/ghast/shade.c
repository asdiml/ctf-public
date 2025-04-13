#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#define SHADOW_MAX 1024

int main()
{
	setbuf(stdout, 0);
	puts("spooky!");
    int pid = fork();
    if (!pid) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
		execve("./ghast", 0, 0);
        exit(1);
	}
	waitpid(pid, 0, 0);
	struct user_regs_struct regs;
	for (;;) {
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, 0, 0);
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
		if (regs.orig_rax == 0x1337)
			break;
	}
	int top = 0;
	unsigned long shadow[SHADOW_MAX];
	for (;;) {
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		long op = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0) & 0xff;
		if (op == 0xe8) {
			if (top < SHADOW_MAX)
				shadow[top++] = regs.rip+5;
			else {
				goto done;
			}
		} else if (op == 0xc3) {
			if (!top) {
				goto done;
			}
			unsigned long expect = shadow[--top];
			ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
			waitpid(pid, 0, 0);
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			if (regs.rip != expect) {
				goto done;
			}
			continue;
		}
		ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		waitpid(pid, 0, 0);
	}
done:
	puts("shadow stack violation");
	kill(pid, 9);
    return 0;
}
