# Greek ECSC Quals 2020 - Crypto - Weak RSA

This challenge provides:
* flag.enc  
* pubkey.pem

Knowing that the algorithm is `RSA`, we are gonna use `RsaCtfTool`. (link: https://github.com/Ganapati/RsaCtfTool)  
```sh
$ python3 RsaCtfTool.py --publickey ./pubkey.pem --uncipherfile ./flag.enc 
```

Results:
```
[*] Testing key ./pubkey.pem.
Can't load smallfraction because sage is not installed
Can't load qicheng because sage is not installed
Can't load ecm2 because sage is not installed
Can't load ecm because sage is not installed
Can't load boneh_durfee because sage is not installed
[*] Performing comfact_cn attack on ./pubkey.pem.
[*] Performing cube_root attack on ./pubkey.pem.
[*] Performing primefac attack on ./pubkey.pem.
[*] Performing pastctfprimes attack on ./pubkey.pem.
[*] Performing pollard_p_1 attack on ./pubkey.pem.
[*] Performing londahl attack on ./pubkey.pem.
[*] Performing fermat attack on ./pubkey.pem.
[*] Performing wiener attack on ./pubkey.pem.

Results for ./pubkey.pem:

Unciphered data :
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HTB{b16_e_5m4ll_d_3qu4l5_w31n3r_4774ck}'
```  

**FLAG: HTB{b16_e_5m4ll_d_3qu4l5_w31n3r_4774ck}**
```