#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char g_buf[0x100];

/* Call this function! */
void win() {
  char *args[] = {"/bin/cat", "/flag.txt", NULL};
  execve(args[0], args, NULL);
  exit(1);
}

void get_data() {
  printf("Data: ");
  fgets(g_buf, sizeof(g_buf), stdin);
}

int main() {
  int choice;
  char buf[0x100];

  memset(buf, 0, sizeof(buf));
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  puts("1. strcpy\n" "2. strcat");
  while (1) {
    printf("> ");
    if (scanf("%d%*c", &choice) != 1) return 1;

    switch (choice) {
      case 1:
        get_data();
        strcpy(buf, g_buf);
        break;

      case 2:
        get_data();
        strcat(buf, g_buf);
        break;

      default:
        return 0;
    }
  }
}
