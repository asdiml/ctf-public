#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

char *cod;

int read_int()
{
	char buf[0x10] = {};
	read(0, buf, sizeof(buf)-1);
	return atoi(buf);
}

int main()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	printf("give prot: ");
	int prot = read_int();
	if (prot & 1) {
		puts("bad prot >:(");
		return 1;
	}
	cod = mmap(0, 0x1000, prot, MAP_PRIVATE|MAP_ANON, -1, 0);
	memset(cod, 0x90, 0x1000);
	for (int i = 1; i < 106; i++) {
		if (i % 105 == 0) {
			printf("fizzbuzz102: ");
			read(0, cod+i, 2);
		} else if (i % 15 == 0) {
			printf("fizzbuzz101: ");
			read(0, cod+i, 1);
		} else if (i % 3 == 0)
			puts("fizz");
		else if (i % 5 == 0)
			puts("buzz");
		else
			printf("%d\n", i);
	}
	cod[107] = 0xc3;
	((void (*)(void))cod)();
	puts("ok bye");
	return 0;
}
