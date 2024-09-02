#!/usr/bin/env python3

'''
NOTE: THIS SCRIPT IS MEANT TO BE RUN ANYWHERE IN THE /tmp DIRECTORY OF
THE SSH HOST (I had no access to /tmp on the input2 account, so I had to
create a subfolder in /tmp)

Because the binary expects flag to be in $PWD which would be the 
/tmp/XXXX subfolder, we need to create a symlink `flag` to the flag in
/home/input2

Issues to figure out:
- Flag gets printed before the rest of the statements which the binary
prints to stdout

Other solutions:
- Pwntools: https://n1ght-w0lf.github.io/binary%20exploitation/input/
- C: https://jaimelightfoot.com/blog/pwnable-kr-input-walkthrough/
'''

import subprocess, os, socket, time

# If running this locally, uncomment the second line after this
exe_path = b'/home/input2/input' 
#exe_path = b'./input'

def setup():

    # Stage 2 SETUP: Creating a pipe to write to stderr
    # Required because passing subprocess.PIPE as a named stderr argumment to Popen only makes
    # process.stderr a readable, not writeable stream
    r, w = os.pipe()

    # Stage 4 - file (use commented line if testing locally)
    with open("./\x0a", 'wb') as f:
    #with open("./\x0a", 'wb') as f:
        f.write(b'\x00'*4) # Create the file and write to it

    return r, w

def cleanup(r, w):

    # Delete created file (use commented line if testing locally)
    os.remove("./\x0a")
    #os.remove("./\x0a")

    # Close pipes
    os.close(r)
    os.close(w)

def main():

    # Get the r/w fds from setup
    r, w = setup()

    # Stage 1: argv - rmb, exe_path also contributes to the argc count
    # Null bytes are not permitted as cmd line args, so we have to use empty strings
    # The 67th argument is used in Stage 5 as the port that the socket listens on
    argmts = [b''] * 65 + [b'\x20\x0a\x0d'] + [b'4000'] + [b''] * 32

    # Stage 2: stdio (PART 1)
    # Use previously-instantiated pipe to write to stderr before starting the process
    os.write(w, b'\x00\x0a\x02\xff')

    # Stage 3: env 
    envp = {
        b'\xde\xad\xbe\xef': b'\xca\xfe\xba\xbe',
    }

    # START THE PROCESS
    process = subprocess.Popen(
        [exe_path] + argmts, 
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, 
        stderr=r,
        env=envp,
    )

    ## FOR DEBUGGING
    #print(f"Started process with PID: {process.pid}")
    #input("Press Enter after attaching GDB...")

    # Stage 2: stdio (PART 2)
    process.stdin.write(b'\x00\x0a\x00\xff')
    process.stdin.flush()

    ## FOR DEBUGGING
    #print(f"Process has PID: {process.pid}")
    #input("Press Enter after being ready for connection...")

    # Wait a bit for the server by ./input to be setup and listening
    time.sleep(1)

    '''
    The line above should solve all connection issues, but if not: 
    - If a "ConnectionRefusedError: [Errno 111] Connection refused" is 
    thrown, re-run the script again. It should work in a few tries. 
    - if "bind error, use another port\n" occurs more than twice, look for
    a process running ./input with `ps aux` and kill it with `kill -9 <pid>`,
    or try a different port (change both the value in the argmts list and
    for the socket's port). 
    '''

    # Stage 5: network
    host = 'localhost'
    port = 4000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(b'\xde\xad\xbe\xef')
    s.close()

    for i in range(10):
        print(process.stdout.readline())

    cleanup(r, w)

if __name__ == "__main__":
    main()