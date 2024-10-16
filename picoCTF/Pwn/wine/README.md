# wine

Windows exe, ret2win 

## `!dh`

No PIE (see [learning_windows_pwn.md](./learning_windows_pwn.md#is-the-executable-a-pie) for the header dump)

## Offset of Return Address

The dissembly of `vuln` is as shown (how the address of `vuln` was found is recapped [here](./learning_windows_pwn.md#finding-the-addresses-of-vuln-and-win-in-windbg-without-symbols-from-a-pdb-file))

```x86asm
004015a9 55               push    ebp
004015aa 89e5             mov     ebp, esp
004015ac 81ec98000000     sub     esp, 98h
004015b2 c7042435404000   mov     dword ptr [esp], 404035h
004015b9 e8c6100000       call    00402684
004015be 8d8578ffffff     lea     eax, [ebp-88h]
004015c4 890424           mov     dword ptr [esp], eax
004015c7 e8d0100000       call    0040269C
004015cc 90               nop     
004015cd c9               leave   
004015ce c3               ret
```

Since the call to `0x402684` uses the "Give me..." string at 0x404035, it is `printf`. Thus `0x040269c` must be `gets` and our input is written to `ebp-0x88`. 

Due to the first `push ebp` instruction, we need `0x88 + 4 = 0x8c` bytes of padding before we write in the address of `win`. 