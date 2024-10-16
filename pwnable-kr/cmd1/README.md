# cmd1

Filtered Shell Script Execution

## Understanding the Challenge

Our only way of accessing the flag is through the `cmd1` binary compiled from the [following source code](./cmd1.c). 

We need to pass the binary a shell command to execute that does not contain any of the substrings "flag", "sh" or "tmp". 

The `PATH` environmental variable has also been altered, but that isn't particularly consequential as we can simply specify the full path of the command binaries we wish to execute. 

## My Approach

My approach was to use the inode number of the `flag` file to bypass detection of the "flag" substring. 

In short, after obtaining the inode number of `flag` (which is a file-specific number) using the commnd `ls -li`, run

```bash
./cmd1 "/usr/bin/find -inum <flag_file_inode_number> -exec /bin/cat {} \;"
```

replacing `<flag_file_inode_number>` with the actual inode number. 

## Other Approaches

https://n1ght-w0lf.github.io/binary%20exploitation/cmd1/

