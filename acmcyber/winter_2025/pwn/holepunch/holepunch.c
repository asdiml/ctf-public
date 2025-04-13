#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

unsigned long long read_long()
{
	char buf[0x20] = {};
	read(0, buf, sizeof(buf)-1);
	return strtoull(buf, 0, 10);
}

int main()
{
	setbuf(stdout, 0);
	printf("cod: ");
	mmap(0xdeadbeef000, 0x1000, 7, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
	read(0, 0xdeadbeef000, 0x1000);
	printf("addr: ");
	char *addr = (char*)read_long();
	mmap(addr, 0x1000, 7, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
}
