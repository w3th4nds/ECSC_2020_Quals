# Greek ECSC Quals 2020 - Forensics - Millerntor regen

This challenge provides:  
* regen.001  

Check what type of file this is:
```sh
$ file regen.001
regen.001: DOS/MBR boot sector MS-MBR,D0S version 3.3-7.0 english at offset 0x8b "Invalid partition table" at offset 0xa3 "Error loading operating system" at offset 0xc2 "Missing operating system", disk signature 0x91f72d24; partition 1 : ID=0x7, start-CHS (0x0,32,33), end-CHS (0xe,254,63), startsector 2048, 253952 sectors
```
Not knowing much about `DOS/MBR boot sector`, my friend `Google` gave me this: `foremost`.  

```sh
$ foremost regen.001 
Processing: regen.001
|**|
```  
An `output` directory is created with some files.  
```
$ ls output/
audit.txt  jpg  pdf
```
Open the `.pdf` and we get the flag.  

![flag_from_pdf](https://i.imgur.com/KqCwspI.png)  

**FLAG: HTB{EXFAT_DIR4CT0RY_3NTRY}**
