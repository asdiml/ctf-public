# passcode

`scanf` Misuse (Arb write), GOT Overwrite

## checksec

```
[*] '/mnt/c/CTFs/pwnable-kr/passcode/passcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

In particular, because there is only partial RELRO and no PIE, we can write the win address (the branch that `cat`s the flag) into an entry of the GOT and expect execution upon that function being called. 

## Concept

The concept is to exploit the binary's misuse of the standard libc `scanf` function to overwrite an entry in the GOT (specifically fflush) with the win address. 

## Explanation of Binary

There are two important functions: `welcome` and `login`. `welcome` accepts a username and spits it back at us, while the `login` function is supposed to accept two passcodes from the user and check them against hardcoded values for login. 

Take a look at the binary [here](./passcode.c) (it's really not a long read). 

### `scanf` Misuse

The misuse occurs because `scanf` accepts addresses as arguments, but integer (not integer **pointer**) arguments are passed to it

```c
void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        ...
```

If we can control `passcode1`, then not only are we able to control **what** is being written, but also **where** it is being written to. 

## Obtaining arb write to a 32-bit chunk

Since `welcome` and `login` are called in sucession (see below), their stack frames overlap. 

```c
int main(){
        ...
        welcome();
        login();
        ...
}
```

Some exploration in gdb tell us that the last 4 characters of the username accept in `welcome` are taken as the local `passcode1` in `login`. In other words, we control the local `passcode1` in `login` that is not initialized in the function. 

## Overwriting the GOT

Notice that `fflush` is called immediately after the call to `scanf` for `passcode1`. We thus can overwrite the GOT entry for `fflush` to `0x080485e3` (see below) which cats the flag. 

```x86asm
0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af
0x080485ea <+134>:   call   0x8048460 <system@plt>
0x080485ef <+139>:   leave
```

## Getting the Flag

The output of running the script is

```
[+] Connecting to pwnable.kr on port 2222: Done
[*] passcode@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process bytearray(b'./passcode') on pwnable.kr: pid 98659
[*] Switching to interactive mode

enter passcode1 : Sorry mom.. I got confused about scanf usage :(
Now I can safely trust you that you have credential :)
```

### Flag

```
Sorry mom.. I got confused about scanf usage :(
```

