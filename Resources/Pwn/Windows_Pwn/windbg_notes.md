## Debugging in Kernel Mode VS User Mode

Kernel mode is the processor access mode in which the OS and privileged programs run. Kernel mode code has permission to access any part of the system, and many hardware device drivers run in kernel mode. 

User mode is the processor access mode in which most applications run - within their own virtual address space. User mode code is restriced from gaining access to many parts of the system. 

When debugging a driver, it is important to determine if the driver is a kernel-mode driver (typically described as a WMD or KMDF driver) or user-mode driver (typically described as a UMDF driver). 

## Useful General WinDbg Commands

| Command | Description |
|---------|--------|
| `g` | Start/Continue program execution |
| `.restart` | Restart program execution |
| `.hh` | Bring up the WinDbg HTML-format documentation |
| `lm` | List loaded modules |
| `lm m <pattern>` | List loaded modules which module name must match `pattern` |
| `qd` | Quits the debugging session and detaches from the debugged application, leaving it running (not possible for remote debugging)


## Useful WinDbg Commands relating to Symbols

| Command | Description |
|---------|--------|
| `.sympath <path>` | Specfies the path(s) in which WinDbg will look for .pdb (symbol) files, for more info see [here](#symbol-search-path-specification) | 
| `.reload` | Updates and loads symbols for currently-loaded modules based on the current symbol path | 
| `.reload /f` | Forces WinDbg to discard all exisiting symbol information and reload the symbols for all modules. This loads all deferred symbols which loading has been deferred due to [lazy symbol loading](#lazy-symbol-loading) |
| `x notepad!*` | Shows all loaded symbols in the notepad.exe module (the symbols need to be loaded first) |
| `x notepad!*main*` | Shows all loaded symbols in the notepad.exe module which contain the string "main" (capitalization-insensitive search) |

### Symbol Search Path Specification

An example expanded symbol search path is shown below

```
cache*;SRV*https://msdl.microsoft.com/download/symbols
```

For further explanation of the syntax, see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path. 


### Lazy Symbol Loading

WinDbg's default behavior is to use lazy symbol loading, where symbols are not loaded until they are required. This includes when the symbol path is changed e.g. when using the `.symlink <path>` command. 

## Useful WinDbg Commands relating to Breakpoints

| Command | Description |
|---------|--------|
| `bp <addr/symbol>` | Set a breakpoint at a specified address or resolved symbol |
| `bu <symbol>` | Set a breakpoint at a unresolved symbol. The breakpoint only becomes active when the symbol is loaded and resolved. |
| `bl` | Lists all set breakpoints |
| `bc <bp_num>` | Clear breakpoint `bp_num` |
| `bc *` | Clear all breakpoints |

### Typical Breakpoints

A breakpoint is usually set on a module's `WinMain` or `wWinMain` function. In line with the typical notepad.exe example, we would use

```
bu notepad!WinMain
```

or `bu notepad!wWinMain`. We could also set a breakpoint on entry, which would be done using 

```
bp $exentry
```

where `$exentry` is the address of the entry point of the first executable of the current process. Other pseudo-registers, and how they should be expressed, can be found at this [WinDbg documentation page](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/pseudo-register-syntax). 

#### WinMain vs wWinMain

`WinMain` and `wWinMain` are the entry points for Windows applications that use ANSI (which usually refers to the Windows-1252-character encoding) and Unicode (usually UTF-16) encodings, respectively. 

Some readings on ANSI vs Unicode include
1. [High-Level Overview of Different Encodings on StackOverflow](https://stackoverflow.com/questions/700187/unicode-utf-ascii-ansi-format-differences)
2. [Brief rundown of the History of ANSI (a set of 8-bit encodings) and Unicode by Joel Spolsky](https://www.joelonsoftware.com/2003/10/08/the-absolute-minimum-every-software-developer-absolutely-positively-must-know-about-unicode-and-character-sets-no-excuses/)

Regardless of the encoding standard used (shown below is using ANSI), their signature is of the format

```c
int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nCmdShow
);
```

where
- `hInstance` is a handle to the current instance of the application, 
- `hPrevInstance` is a handle to the previous instance of the application (which is always NULL is Win32 applications), 
- `lpCmdLine` is a pointer to the command line arguments as a ANSI/Unicode string (ANSI in this case), and
- `nCmdShow` is a flag that indicates how the window should be shown.

Under UTF-16 (also known as UCS-2) encoding which is usually what is meant by the phrase "Unicode encoding", the type `LPWSTR` is used in place of `LPSTR`, and string literals are prepended with the `L` character e.g. `L"Hello"` instead of `"Hello"`. 

## Useful WinDbg Commands for Stepping

| Command | Description |
|---------|--------|
| `t` or F11 or F8 | Step into (similar to `si` in gdb) |
| `p` or F10 | Step over (similar to `ni` in gdb) |
| `gu` or Shift+F11 | Step out (similar to `fini` in gdb) |

## Useful WinDbg Commands relating to the Stack Backtrace

| Command | Description |
|---------|--------|
| `k` | Display the stack backtrace with default options |
| `kb <maxdepth>` | Displays the stack backtrace with up to 3 passed params per function call, and up to an hexadecimal integer max depth |
| `kp` | Displays all parameters for each function that's called in the stack trace, where each parameter's data type, name, and value are included. This requires full symbol information

## Useful WinDbg Commands to show Memory

| Command | Description |
|---------|--------|
| `ds <addr>` | Dumps the string / ANSI string (see [winMain VS wWinMain](#winmain-vs-wwinmain) for resources on ANSI vs Unicode) starting at `addr` |
| `dS <addr>` | Dumps the Unicode string (see [winMain VS wWinMain](#winmain-vs-wwinmain) for resources on ANSI vs Unicode) starting at `addr` |
| `dt -r <struct_name> <addr>` | Dumps the data members of the `struct_name` instance starting at `addr` by recursively dumping subtype fields |
| `s -a <start_addr> <win_addr> <str>` | Searches memory from `start_addr` to `end_addr` for the ASCII string `str` (not necessarily null-terminated). However, results may be cut off by a null byte. | 

### Example use of `dt`

`dt` is very useful in dumping the internals of a struct. An example of the command to dump the fields of a PE header is shown below

```
dt -r ntdll!_IMAGE_NT_HEADERS <start_addr_of_PE>
```

Personally, I was unable to find where the struct definition of `_IMAGE_NT_HEADERS` resides, but this should work (in theory) if that can be found. 

## Useful WinDbg Commands to edit Memory

| Command | Description |
|---------|--------|
| `eb <addr> <vals>` | Overwrite 1 or more bytes at `addr` with space-separated `vals` |
| `ew <addr> <vals>` | Overwrite 1 or more words (2 bytes) at `addr` with space-separated `vals` |
| `ed <addr> <vals>` | Overwrite 1 or more double-words (4 bytes) at `addr` with space-separated `vals` |
| `eq <addr> <vals>` | Overwrite 1 or more quad-words (8 bytes) at `addr` with space-separated `vals` |

### Editing the `BeingDebugged` Byte of the Process Environment Block (PEB)

When a process is being debugged, the `BeingDebugged` byte data member of the [`_PEB` struct](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) is set to 1. 

The struct looks something like this

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  ...
} PEB, *PPEB;
```

As an anti-RE measure, some malware will exit if that bit is set to true. To unset that bit, we can run the WinDbg command 

```
eb $peb+0x2 0x0
```

where `$peb` is one of WinDbg's useful [pseudo-registers](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/pseudo-register-syntax). 

## WinDbg Bang Commands

WinDbg bang commands (or extension commands) are commands called from debugger extension DLLs. They can be run with the syntax

```
!<cmd_name>
```

It is also possible to call an exported function of an extension, with the syntax

```
<dll_name>!<module_name>
```

### Useful WinDbg Bang Commands

| Command | Description |
|---------|--------|
| `!address` | Returns the general memory layout of the applicatio (similar to `vmmap` or `vm` in gdb) |
| `!address <addr>` | Provides information about the page(s) of the region in which `addr` resides |
| `!dh <addr>` | Displays the headers (i.e. DOS, PE, optional and section headers) of an image (binary / DLL) |
| `!findstack <string>` | Greps for the exact `string` literal (patterns may not be used) on the call stack of each thread (displays the results per-thread) |
| `!writemem <target_file_path> <start_addr> <end_addr>` | Dumps the memory from `start_addr` to `end_addr` into the file given by `target_file_path` |

#### A closer look at the `!address` command 

For example, to examine the region of the stack, we might run

```
0:000> !address @rsp

Usage:                  Stack
Base Address:           000000f2`8328f000
End Address:            000000f2`832a0000
Region Size:            00000000`00011000 (  68.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        000000f2`83220000
Allocation Protect:     00000004          PAGE_READWRITE
More info:              ~0k
```

To examine the text segment that `rip` currently points to, run

```
0:000> !address @rip

Usage:                  Image
Base Address:           00007ff7`90fb1000
End Address:            00007ff7`90fd9000
Region Size:            00000000`00028000 ( 160.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000020          PAGE_EXECUTE_READ
Type:                   01000000          MEM_IMAGE
Allocation Base:        00007ff7`90fb0000
Allocation Protect:     00000080          PAGE_EXECUTE_WRITECOPY
Image Path:             notepad.exe
Module Name:            notepad
Loaded Image Name:      C:\Windows\System32\notepad.exe
Mapped Image Name:      
More info:              lmv m notepad
More info:              !lmi notepad
More info:              ln 0x7ff790fb19a0
More info:              !dh 0x7ff790fb0000
```