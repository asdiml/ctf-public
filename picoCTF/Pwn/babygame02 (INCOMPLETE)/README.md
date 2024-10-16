# babygame02

ret2win using Array Out-of-bounds Exploit

> REASON FOR LACK OF COMPLETION: SEE [HERE](#problem-unable-to-flush-stdout)

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/babygame02/game'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No PIE, so the address of `win` does not change per runtime

## Context

Do give the writeup on [babygame01](../babygame01/solve.md) a read as this writeup will not rehash the commonalities between `babygame01` and `babygame02`.  

## Differences

First, stack offset differences (note that this is within the stack frame of `main`). In `babygame01`, we have

```
[ebp-0xa98] -> map
[ebp-0xaa4] -> player_stats
```

where `map = player_stats + 12`, but now in `babygame02`, we have

```
[ebp-0xa95] -> map
[ebp-0xaa0] -> player_stats
```

where `map = player_stats + 11`. This offset (or rather, the exact offset from `ebp`) is now important because of the next difference. 

The other important difference is that there is no mention of the flag (or rather any call to `win`, which prints the flag) at all in `main`. Thus while the `win` function exists in both `babygame01` and `babygame02`, it is only in `babygame02` that we need to overwrite some return address of to point to `win`. 

## Which return address to overwrite?

The `move_player` function (decompiled using Ghidra) that did not change across `babygame01` and `babygame02`  is as follows

```c
void move_player(int *player_stats,char input,int map) {

  ...

  if (input == 'l') {
    iVar1 = getchar();
    player_tile = (undefined)iVar1;
  }

  ...

  *(undefined *)(*player_stats * 0x5a + map + player_stats[1]) = 0x2e;
  if (input == 'w') {
    *player_stats = *player_stats + -1;
  }
  else if (input == 's') {
    *player_stats = *player_stats + 1;
  }
  else if (input == 'a') {
    player_stats[1] = player_stats[1] + -1;
  }
  else if (input == 'd') {
    player_stats[1] = player_stats[1] + 1;
  }
  *(undefined *)(*player_stats * 0x5a + map + player_stats[1]) = player_tile;
  return;
}
```

Since we can set `player_tile` using option `l`, we might assume we have arbitrarily write capability across the stack, but this is not true. The line

```c
*(undefined *)(*player_stats * 0x5a + map + player_stats[1]) = 0x2e;
```

sets the byte at memory address we are moving the player from to a constant `0x2e`, and thus we actually only have control of a single byte. 

We thus cannot overwrite the address that `main` will return to, because that address is usually in `__libc_start_main` which addresses usually differ significantly from the function addresses in the text segment (where `win` resides). 

Instead, we write to **lower** addresses to overwrite the return address of the `move_player` function that `main` calls. 

Why `move_player`? First, it is directly called by `main`, so we do not have to worry about stepping on other things before getting to the return address we want to overwrite. Second, it is exactly the function that we use for the overwrite, so we do not have to ensure that a chain of things still work without error before we hit our target function's return - after making the one-byte overwrite, the target function immediately returns without the possibility of stack frame-alignment errors, etc. 

## Finding Offsets

We set a breakpoint at the call to `move_player` in `main` to inspect `ebp` and `esp` before the call occurs. 

```
gef➤  b *0x8049704
Breakpoint 1 at 0x8049704
gef➤  c

...

gef➤  p $esp
$1 = (void *) 0xffffc2f0
gef➤  p $ebp
$2 = (void *) 0xffffcda8
```

We see that at this point `esp = ebp - 0xab8`, where the `ebp` we reference is still that of the stack frame of `main`. The return address of `move_player` will thus be at `[ebp-0xabc]`. 

Now, in the text segment, `win` comes immediately after `main`, and because there is no PIE, we know that the return address at `[ebp-0xabc]` is `0x08049709`, and the address of `win` is `0x804975d`. So only the least significant byte needs to be overwritten, and for little-endian ordering that byte occurs exactly at `[ebp-0xabc]`. 

## Executing the Write

Recall that `map` starts at `[ebp-0xa95]`, so we need to move `-0x27` from the start of `map` to get to `[ebp-0xabc]`. We see that 

```
-0x27 % 0x5a = 0x33
```

so we want to move the player to row -1 and column 51. 

## PROBLEM: UNABLE TO FLUSH STDOUT

There are issues with flushing stdout before the `printf` in `win` (since only if I included a newline in the flag would it print). 

Not sure how to induce the binary to print a newline or run `fflush(stdout)` or `fflush(null)`

Even trying a different approach (credit to [this writeup](https://github.com/snwau/picoCTF-2023-Writeup/blob/main/Binary%20Exploitation/babygame02/babygame02.md) for the commands) i.e. running

```bash
echo -e $(python3 -c 'print("l]" + "d"*(51-4) + "w"*5)') | ./game
```

or

```bash
echo -e $(python3 -c 'print("l]" + "d"*(51-4) + "w"*5)') | nc saturn.picoctf.net 57631
```

does not work. 