#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>

int read_int()
{
	char buf[0x10] = {};
	read(0, buf, sizeof(buf)-1);
	return atoi(buf);
}

#define MAX_MSG 1024
#define MAX_BOX 2
struct box {
	int pid;
	int in[2];
	int out[2];
} boxes[MAX_BOX];
int box_cnt;
int parent;

void exit_all()
{
	for (int i = 0; i < box_cnt; i++)
		kill(boxes[i].pid, SIGKILL);
	exit(1);
}

void add_box()
{
	if (box_cnt >= MAX_BOX) {
		puts("too many boxes");
		return;
	}
	printf("send shellcode (max 0x1000 bytes): ");
	char *shc = mmap(0, 0x1000, 7, MAP_ANON|MAP_PRIVATE, -1, 0);
	memset(shc, 0x90, 0x1000);
	shc[0xfff] = 0xc3;
	read(0, shc, 0x1000);
	pipe(boxes[box_cnt].in);
	pipe(boxes[box_cnt].out);
	boxes[box_cnt].pid = fork();
	if (!boxes[box_cnt].pid) {
		close(2);
		dup2(boxes[box_cnt].in[0], 0);
		dup2(boxes[box_cnt].out[1], 1);
		close(boxes[box_cnt].in[1]);
		close(boxes[box_cnt].out[0]);
		syscall(690);
		((void (*)())shc)();
	loop:
		goto loop;
	}
	close(boxes[box_cnt].in[0]);
	close(boxes[box_cnt].out[1]);
	printf("successfully added box at idx: %d\n", box_cnt);
	box_cnt++;
}

void write_box()
{
	printf("enter box idx: ");
	int idx = read_int();
	if (idx < 0 || idx >= box_cnt) {
		puts("invalid index");
		return;
	}
	char buf[MAX_MSG] = {};
	printf("enter message (max %d bytes): ", MAX_MSG);
	int cnt = read(0, buf, MAX_MSG);
	if (cnt > 0)
		write(boxes[idx].in[1], buf, cnt);
}

void read_box()
{
	printf("enter box idx: ");
	int idx = read_int();
	if (idx < 0 || idx >= box_cnt) {
		puts("invalid index");
		return;
	}
	char buf[MAX_MSG+1] = {};
	int cnt = read(boxes[idx].out[0], buf, MAX_MSG);
	printf("read %d bytes: %s", cnt, buf);
}

int main()
{
	setbuf(stdout, 0);
	puts(" ___  ___  ___  ___");
	puts("_|W|__|E|__|A|__|K|_");
	puts(" ‾‾‾  ‾‾‾  ‾‾‾  ‾‾‾");
	puts("  (1) add box");
	puts("  (2) write to box");
	puts("  (3) read from box");
	puts("  (4) exit");
	puts("   ___  ___  ___");
	puts("___|B|__|O|__|X|____");
	puts("   ‾‾‾  ‾‾‾  ‾‾‾");
	for (;;) {
		write(1, "choice: ", 8);
		switch(read_int()) {
		case 1:
			add_box();
			break;
		case 2:
			write_box();
			break;
		case 3:
			read_box();
			break;
		case 4:
			exit_all();
			break;
		default:
			puts("invalid choice");
			break;
		}
	}
}
