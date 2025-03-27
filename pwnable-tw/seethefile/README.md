# seethefile

Forge `_IO_FILE_plus` and vtable

## checksec

```python
[*] '/mnt/d/CTFs/pwnable-tw/seethefile/seethefile'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Overview of Binary & Vulnerability

We have four functions that can be used, i.e.
1. `openfile`
2. `readfile`
3. `writefile`
4. `closefile`

With these functions we can leak the libc base address by reading from `/proc/self/maps`. 

However, the crux of the challenge lies in what happens when we exit from the loop (which is the fifth option in the menu), shown below

```c
08048acb      printf("Leave your name :");
08048ae0      __isoc99_scanf("%s", name);
08048af5      printf("Thank you %s ,see you next time\n", 0x804b260);
08048b04      if (fp != 0)
08048b0f          fclose(fp);
08048b1c      exit(0);

```

This is an obvious bof into `name` in .bss, which allows us to overwrite `fp`. There is nothing else we can overwrite of importance in the executable, but since that is unused memory in the rw page, we have basically arbitrary amounts of space to forge whatever we want. 

## Forging `_IO_FILE_plus` and the vtable `_IO_file_jumps`

For some context, every open file descriptor in libc will have a corresponding FILE struct allocated for it on the heap. A vtable pointer is tagged to each struct so that dictating IO-related functions is easier to coordinate. 

We thus need to forge the `_IO_FILE_plus` struct and get `fp` (a variable in .bss) to point to it when fclose occurs

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

We also need to know that the size of `_IO_FILE_plus` struct is 0x50 bytes when using `_IO_old_fclose` in i386 for this libc, as well as that we need to forge the vtable `_IO_file_jumps` that the pointer `vtable` points to in order to get a shell. 

### Forging `_IO_FILE`

There is quite a bit to the `_IO_FILE` struct

```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

Thankfully, we do not need to understand everything (or control it for that matter) in the struct. 

Primarily, we are trying to get to the in `_IO_FINISH` macro in `_IO_old_fclose`, which calls the `_IO_file_finish` entry of the vtable

```c
int
attribute_compat_text_section
_IO_old_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

  /* We desperately try to help programs which are using streams in a strange way and mix old and new functions.  Detect new streams here.  */
  if (fp->_vtable_offset == 0)
    return _IO_new_fclose (fp);

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_old_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  
  ...
```

Firstly, we want to avoid going to `_IO_new_fclose`, so the `_vtable_offset` field of the struct should not be 0. 

Second, to avoid potentially problematic functions we would need to emulate or point to correct places i.e. `_IO_un_link` and `_IO_file_close_it`, we should just set the `_IO_IS_FILEBUF` flag to false. We have that this bit is `0x2000` in `_flags` of the FILE struct. 

Third, `_IO_acquire_lock` will attempt to acquire and then release the lock on the FILE struct which will require a valid pointer to a `_IO_lock_t` struct within the FILE. We could just point this to a 12-byte block of zeroes which will allow the lock acquisition and release to be performed properly (see the `_IO_lock_t` struct below)

```c
typedef struct { 
     int lock; 
     int cnt; 
     void *owner;
} _IO_lock_t;
```

or we could just turn the `_IO_USER_LOCK` flag on within the FILE struct so that the lock won't be acquired. This bit is `0x8000` in `_flags` of the FILE struct. 

Lastly, notice that the argument to `_IO_FINISH` is `fp`. So, if we overwrite `_IO_file_finish` in the vtable with libc's system, we just need to ensure that the data in `fp` has no null bytes until a portion where we can put arb data and then stuff in "`;/bin/sh\x00`". 

### Forging the vtable

A truncated version of the `_IO_file_jumps` struct is shown below

```c
const struct _IO_jump_t _IO_file_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),

  ...
```

and we simply need to ensure that the first actual entry is libc's system when forging it. Notably, `JUMP_INIT_DUMMY` is 8 bytes in length, not 4. 

## Flag

```
[+] Opening connection to chall.pwnable.tw on port 10200: Done
[*] hex(libc.address)='0xf760b000'
[*] FLAG{F1l3_Str34m_is_4w3s0m3}
[*] Closed connection to chall.pwnable.tw port 10200
```