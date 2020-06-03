# Greek ECSC Quals 2020 - Forensics - Clang

For this challenge I used a *Windows* machine. The only reason is that the `audio` crashed my `kali`.
So, let's begin.

The challenge provides a `clang.pcap` file. We open it with `Wireshark` and see the traffic. 

![RTP](https://i.imgur.com/8Yj6Iuz.png)

`RTP` stands for: `Real-time Transport Protocol` and as wiki says: 
```
"The Real-time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks."
```
So, we go to Wireshark bar -> `Telephony` -> `VoiP calls`, pick the stream and play it.  

![player](https://i.imgur.com/t7YHwJX.png)

**FLAG: HTB{3242459345}**

