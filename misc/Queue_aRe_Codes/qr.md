# Greek ECSC Quals 2020 - coding - Queue_aRe_Codes

This challenge creates a random QR code everytime we refresh the page and there is a submit box that takes our answer. If our response is not fast enough, we get "You failed" message.
Doing it manually for the first time, we see that in the source code, the QR is in **base64** form. After we decrypt the image, we get another encrypted message.
Now it is a **ROT13** with a **base64** at the end. (Instances are down so I couldn't provide images :/).
The new **base64** is a an operation between random numbers. So we need to evaluate this and provide it as an answer.  

### Exploit

```python
#!/usr/bin/python3
from pwn import *
import requests
import re
import hashlib
import sys,os
import qrtools
import codecs
import base64

port = 32074
url = 'http://docker.hackthebox.eu:'
url += str(port) + "/"

#Get the request
try:
    r = requests.get(url)
except:
    print("Error Connecting. Check Port")

#Strip away the html tags etc

# Split to get the base64 value
split = str(r.content).split('"')
base_64 = split[1][23:]

# Convert base64 to image
os.system("echo '" + str(base_64) + "' | base64 -d > qr.png")
qr = qrtools.QR()

# Decode the image
qr.decode("qr.png")
qr.data
rot13 = lambda s : codecs.getencoder("rot-13")(s)[0]

# Convert the ROT13 and get the final base64
rot13_decoded = rot13(qr.data) 
rot13_decoded = rot13_decoded[40:].strip()

# Decode it to get the operations
final = base64.b64decode(rot13_decoded)

# Replace "[]" with "()" to call eval()
final = final.replace(b"[", b"(")
final = final.replace(b"]", b")")
result = eval(final)
print(result)

# Send the answer to the new url
new_url = 'http://docker.hackthebox.eu:32074/solve'

# Get the flag
flag = requests.post(new_url, data={'answer': str(result)})
print(flag.text)
```

**FLAG : HTB{qr_c0des_4re_c00l}**