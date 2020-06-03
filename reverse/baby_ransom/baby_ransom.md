# Greek ECSC Quals 2020 - Reversing - Baby_Ransom

This challenge provides:
* CuteKitty.exe
* info.pdf.meow

First things first, we run `$ strings` on CuteKitty.exe.
```sh
$ strings CuteKitty.exe 
!This program cannot be run in DOS mode.
@Rich@
UPX0
UPX1
```
The file is `UPX` packed, so we need to unpack it with: 
```sh
$ upx -d CuteKitty.exe
```
Results: 
```
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     14848 <-      9728   65.52%    win64/pe     CuteKitty.exe

Unpacked 1 file.
```
Now that our file is unpacked, we are ready to go!

Open up **IDA** to see what is going on.
Taking a look at the functions we found this at `sub_140001360`:
[pastebin](https://i.imgur.com/lIIrOQF.png)
From this we get:
* pastebin.com
* /raw/NWiZfk1u

and go to url: https://pastebin.com/raw/NWiZfk1u  
We get this key: `k2G3:E47xM8!xM$>`  
Inside `sub_140001000`, occurs the encryption part of the file. I didn't proceed into further analysis because I wanted to search a bit more about ransomwares. What I found was that common windows ransomwares were encrypted with **RSA** or **AES_128**. I tried my luck to search for a github tool-decryptor and I fell on that: https://gist.github.com/hasherezade/2860d94910c5c5fb776edadf57f0bef6  
I downloaded the .cpp and compiled it while changing the key to `k2G3:E47xM8!xM$>`.

After that, we compile the program we run it with the specified params:
```
C:\Users\Thanos\source\repos\decryptor69\Debug\decryptor69.exe "info.pdf.meow" FLAG.pdf 69
```
![decryptor](https://i.imgur.com/g3VO96j.png)

We open the FLAG.pdf on browser

![flag](https://i.imgur.com/kbtLiUO.png)

**FLAG: HTB{w3_wi11_g3t_u_n3xt!}**


