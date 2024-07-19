## Clear-screen Sequence

Most terminals follow the ANSI standard which defines a number of escape sequences. 

`\x1b[2J` is such a sequence, and its effect is to clear the screen. Note the capital J. 

On such a terminal, `fputs("\x1b[2J", stdout)` clears the screen. 