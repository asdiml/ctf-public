# babygame01

Array Out-of-bounds Exploit

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/babygame01/game'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Binary

The Ghidra-decompiled main function looks as follows

```c
undefined4 main(void)
{
  int iVar1;
  undefined4 uVar2;
  int in_GS_OFFSET;
  int player_stats;
  int local_aa8;
  char local_aa4;
  undefined map [2700];
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  init_player(&player_stats);
  init_map(map,&player_stats);
  print_map(map,&player_stats);
  signal(2,sigint_handler);
  do {
    do {
      iVar1 = getchar();
      move_player(&player_stats,(int)(char)iVar1,map);
      print_map(map,&player_stats);
    } while (player_stats != 0x1d);
  } while (local_aa8 != 0x59);
  puts("You win!");
  if (local_aa4 != '\0') {
    puts("flage");
    win();
    fflush(_stdout);
  }
  uVar2 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar2 = __stack_chk_fail_local();
  }
  return uVar2;
}
```

In summary, `main` initializes player stats and the map, prints the map, lets you move the player, and if you reach a certain coordinate, prints "You win!". 

As is apparent, to obtain the flag, we need to fulfil two conditions
1. We must "win" i.e. reach the desired coordinate
2. We must set `local_aa4` to something other than 0

## Notable Details in the Binary

After investigation, we realize that we can treat `player_stats` as a struct of the following construct

```c
struct playerStats {  // The name of the struct type is made-up
    int32_t player_row;
    int32_t player_col;
    char if_flag;
} player_stats;
```

We reach this conclusion after some digging and realizing that `local_aa8` is in fact `player_stats + 4`, and `local_aa4` is `player_stats + 8`. 

Also, notice that `map` is a byte (char) array containing the map of the game. Now, from the assembly of the call to `init_map`, 

```x86asm
0x0804979e <+58>:    lea    eax,[ebp-0xaa4]
0x080497a4 <+64>:    push   eax
0x080497a5 <+65>:    lea    eax,[ebp-0xa98]
0x080497ab <+71>:    push   eax
0x080497ac <+72>:    call   0x80492c8 <init_map>
```

we see that `map` is a 12-byte address increment from `player_stats` (in x86-32, the first argument of a call is pushed last onto the stack, so the `init_map(map,&player_stats)` call reveals this information). In other words, `map = player_stats + 12`. 

In other words, if we can write to a negative index of `map`, then we can overwrite the data stored in `player_stats`. 

## Controlling `local_aa4`

We can precisely overwrite `local_aa4` (which is initialized to the null byte) within the `move_player` function, which is shown below

```c
void move_player(int *player_stats,char input_char,int map)

{
  int iVar1;
  
  if (input_char == 'l') {
    iVar1 = getchar();
    player_tile = (undefined)iVar1;
  }
  if (input_char == 'p') {
    solve_round(map,player_stats);
  }
  *(undefined *)(*player_stats * 0x5a + map + player_stats[1]) = 0x2e;
  if (input_char == 'w') {
    *player_stats = *player_stats + -1;
  }
  else if (input_char == 's') {
    *player_stats = *player_stats + 1;
  }
  else if (input_char == 'a') {
    player_stats[1] = player_stats[1] + -1;
  }
  else if (input_char == 'd') {
    player_stats[1] = player_stats[1] + 1;
  }
  *(undefined *)(*player_stats * 0x5a + map + player_stats[1]) = player_tile;
  return;
}
```

In particular, there is no check to ensure that `*player_stats` (which is `player_row`) and `player_stats[1]` (which is `player_col`) are both nonnegative before the `player_tile` character is written to it. 

We thus zero both `player_row` and `player_col` (by moving the player accordingly), before subtracting an additional 4 from `player_col` (by providing 4 more `a` characters) so that `local_aa4` (or `player_stats + 8`) is overwritten. 

## Winning the Game

Winning the game is simple. We simply input the `p` character, and the game automates the win for us. 

## Flag

```
b'picoCTF{gamer_m0d3_enabled_6aeb6b85}'
```