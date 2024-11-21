#include <stdio.h>

int main()
{
	setbuf(stdout, 0);
	puts("guys im ltrace i promise");
	setbuf(stdin, 0);
	printf("setbuf(%p, 0)\n", stdin);
	printf("shoot: ");
	unsigned long shot = 0;
	scanf("%lu", &shot);
	((void (*)(void))shot)();
	return 0;
}
