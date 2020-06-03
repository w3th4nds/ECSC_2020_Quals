# Greek ECSC Quals 2020 - stego - LSBattleme
The challenge gives us a `kirby_crane.jpg`. First things first, we `$ strings` the image.  
Bottom line: `aUZlZWxMaWtlU29tZUFwcGxlUGllCg==`
An interesting base64.
```
$ echo 'aUZlZWxMaWtlU29tZUFwcGxlUGllCg==' | base64 -d
iFeelLikeSomeApplePie
```
Now that we have a a password, we go to: https://futureboy.us/stegano/decinput.html
* Upload the image
* password: **iFeelLikeSomeApplePie**

and we get the flag.  

**FLAG: HTB{th3_dr3@m_f0unt@1n_cup_w1ll_b3_m@1n}**