# ring-opening-polymerization

ret2win w/ args

## checksec

```bash
[*] '/mnt/d/CTFs/TJCTF 2024/ring-opening-polymerization/out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE so the win address is fixed

## Solving

1. Use ROP gadgets to set `rdi` to `0xdeadbeef`
2. End with address of `win`

## Flag

tjctf{bby-rop-1823721665as87d86a5}


