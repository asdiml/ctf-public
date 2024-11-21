#include <stdio.h>
#include <string.h>

int main(void) {
  setbuf(stdout, NULL);
  char username[32] = "pleb";
  puts("For help, type \"help\".");
  while (1) {
    char command[32];
    gets(command);
    if (strcmp(command, "help") == 0) {
      puts("Commands:");
      puts("help");
      puts("exit");
      puts("whoami");
      puts("gib-flag");
    } else if (strcmp(command, "exit") == 0) {
      break;
    } else if (strcmp(command, "whoami") == 0) {
      puts(username);
    } else if (strcmp(command, "gib-flag") == 0) {
      if (strcmp(username, "admin") == 0) {
        FILE *flag_file = fopen("flag.txt", "r");
        char flag[64];
        fgets(flag, sizeof flag, flag_file);
        fclose(flag_file);
        puts(flag);
      } else {
        puts("Only admin can read the flag");
      }
    } else {
      puts("Unknown command");
    }
  }
}
