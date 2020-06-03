# Greek ECSC Quals 2020 - Reversing - findme
First of all, we start with `$ strings` to see if we can get any easy info from the binary.

```
...
Enter password: 
i_am_the_master
Welcome, master!!
You're not my master :(
...
```
That's pretty straightforward! The binary asks for a password and the correct answer seems to be: `i_am_the_master`
Well, we still don't get the flag after that. Let's analyze it in **IDA**.  
Name of the challenge -> `findme`
So, let's find a place where the flag could be stored.
### Disassembly

![rax](https://i.imgur.com/typ9J8d.png) 

This seems the only place in the binary to store something. Now we need to get to this address and check the registers. In order to get there, we need to get into `sub_12F3` function

![cmp](https://i.imgur.com/g6HmqVY.png)

That means the `jnz` in `12C6` should jump to `12DB`.
Let's open up **gdb** and debug it.

### Debug

In gdb (w):
```
gef➤  br *0x5555555552C2
Breakpoint 1 at 0x5555555552c2
gef➤  r
Starting program: /home/w3th4nds/ctfs/ecsc2020_quals/rev/findme 
Enter password: i_am_the_master
i_am_the_master
```
Then, we should change `$rax` in order to reverse the result of the comparison and jmp where we want.
```
gef➤  set $rax = 0
gef➤  ni
```

When we reach the desired function `→ 0x5555555552e7 call   0x5555555552f3`, we sould *step* into it with `si`.

After some instructions, we see that a `strcpy` occurs.
```
   0x55555555534c                  call   0x5555555550d0 <strncpy@plt>
 → 0x555555555351                  mov    BYTE PTR [rbp-0x9], 0x0
   0x555555555355                  mov    DWORD PTR [rbp-0x18], 0x250d1cee
   0x55555555535c                  lea    rax, [rbp-0xd]
   0x555555555360                  mov    eax, DWORD PTR [rax]
   0x555555555362                  sub    eax, DWORD PTR [rbp-0x18]
```
At `0x555555555362` all the *modification* that happened to the string(a part of the "i_am_the_master") is stored to `$eax`. So, if we print the value of rax and convert it to string, we get this:
```
gef➤  p $rax
$7 = 0x4854427b
```
```
>>> "4854427b".decode("hex")
'HTB{'
```
If we keep doing that after the `strcpy` we get the whole flag :D

**FLAG: HTB{U_f0uNd_m3}**

