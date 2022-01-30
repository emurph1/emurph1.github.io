+++
author = "Emily Murphy"
title = "MetaCTF 2021"
date = "2021-12-03"
description = "MetaCTF CyberGames 2021"
tags = [
    "ctfs",
    "writeups",
]
categories = ["writeups"]
+++

Starting Friday, December 3rd, 2021, MetaCTF will host it's 7th annual virtual jeopardy-style CTF! This event is free and open to everyone, and participants can compete in teams of up to 4.

This CTF will challenge participants of all skill levels to learn new cybersecurity techniques and skills, with problems covering a variety of topics such as web exploitation, cryptography, binary exploitation, reverse engineering, forensics, and reconnaissance.
<!--more-->

# Intro
This CTF was the first time our club has participated and it was an absolute blast. Thank you to my awesome team members (Rohan, Lane, and Bode)!!! We placed 58th overall and 25th amongst student teams!

# Darryl Vault
Dread Pirate Darryl has no qualms with a little bit - or a lot - of thievery, as you recently found out to your detriment. Suffice it to say his loot stash has grown quite a bit, and you find yourself down a whole bunch of valuables. This is, put simply, unacceptable. You need to rectify this situation, and returning the favor ought to do the trick.

As a Dread Pirate, Dread Pirate Darryl has much better things to do than remembering all of his secrets, such as raiding other innocent CTF-goers or shouting "ARRRRR" at the top of his lungs repeatedly. Darryl commissioned a secret vault program to be written for him so that when he needs to take newly acquired loot back to his lair, he can ask it where he has to go.

Unfortunately for Dread Pirate Darryl, the developer from whom he commissioned the vault was very proud of his work and wanted to show it off, and we here at MetaCTF have acquired a copy of it. Find Dread Pirate Darryl's treasures! Enact your revenge!

Note: The flag is the password used to access the location of Dread Pirate Darryl's treasure.

## Solve
First, i just ran the file to see what was going on and saw that there were four different options. 
I went to ghidra, looked at the entry, got the first argument of libc start main and renamed main 
Rebase Ghidra 
Break main and look at what it’s doing
We have four possible inputs, right? 
1, 2 3, 4

Mother’s maiden name does not prompt for a password

The password for 2&3 is just chilling in strings DARRYL_IS_THE_GREATEST

4 asks for a password, but it doesnt output anything else. Hmmmmmmmmmmmm 👀

Essentially, the password is checked on three separate occasions
We return to ghidra. Defined strings go burrrrr. “Hey, Darryl, I'm going to need your password” has three functions nearby it. Three???? hmmmmmmmmmmmmmmm

![idek](/content/posts/images/metactf/message.png)

Why dont we click on those functions 👀 

Oh cool that last one looks sexy 

This is where i found the function i named funcwithtoomanynums. U will know it when u see it

Inside that, the memcmp 0x27 goooo burrrrrr 

Let’s just fuck around in gdb and break at this memcmp with ‘aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa’ bc its len is 0x27

Gdb go burrrrrr
ty gdb v cool

![flag in memory](/posts/images/metactf/flag.png)

# Easy as it is
Caleb was designing a problem for MetaCTF where the flag would be in the telnet plaintext. Unfortunately, he accidentally stopped the packet capture right before the flag was supposed to be revealed. Can you still find the flag? Note: You'll need to decrypt in CyberChef rather than using a command line utility. 

## Solve
Get the PGP message and private key from the pcap. Put it in CyberChef and notice it is still messed up. So, mess around with the decrompression and find that `gzip` works.

![cyberchef](/posts/images/metactf/cyberChef.png)

`MetaCTF{cleartext_private_pgp_keys}`

# I Hate Python
I hate Python, and now you will too. Find the password.

## Solve
Scripting fun:
```python
import random

def do_thing(a, b):
    return ((a << 1) & b) ^ ((a << 1) | b)

def checkFlag(x, prevLen):
    random.seed(997)
    k = [random.randint(0, 256) for _ in range(len(x))]
    a = { b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k) }
    b = list(range(len(x)))
    random.shuffle(b)
    c = [a[i] for i in b[::-1]]
    # print(k)
    # print(c)
    kn = [47, 123, 113, 232, 118, 98, 183, 183, 77, 64, 218, 223, 232, 82, 16, 72, 68, 191, 54, 116, 38, 151, 174, 234, 127]
    valid = len(list(filter(lambda s: kn[s[0]] == s[1], enumerate(c))))
    # print(valid)
    if valid > prevLen:
        return True
    return False

#random.seed(997)

k = [random.randint(0, 256) for _ in range(25)]
# print(k)

#x = "A"*25

# a = {b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k)}

#kn = [47, 123, 113, 232, 118, 98, 183, 183, 77, 64, 218, 223, 232, 82, 16, 72, 68, 191, 54, 116, 38, 151, 174, 234, 127]

# write a loop to go through all the possible ascii 
# values and do_thing it with all values in k

currFlag = 'MetaCTF{'

for i in range(25 - 8):
    for j in range(0, 128):
        nextFlag = currFlag + chr(j) + 'A'*(16-i)
        # print("test")
        print(nextFlag)
        assert(len(nextFlag) == 25)
        if checkFlag(nextFlag, len(currFlag)):
            # print(nextFlag)
            currFlag = currFlag + chr(j)
            break

# print(currFlag)
```

`MetaCTF{yOu_w!N_th1$_0n3}`

# Interception I
192.168.0.1 is periodically (once every 4 seconds) sending the flag to 192.168.0.2 over UDP port 8000. Go get it.
ssh ctf-1@host.cg21.metaproblems.com -p 7000

If you get an SSH host key error, consider using
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ctf-1@host.cg21.metaproblems.com -p 7000

Note that the connection can take a while to initialize. It will say Granting console connection to device... and then three dots will appear. After the third dot you should have a connection. 

## Solve (Note I did this at 2 AM)
Gotta do some ip spoofing.

1. first changed ip address to spoofy

`ifconfig eth0 192.168.0.2 netmask 255.255.255.0`

2. then do a lil ping to test connection and refresh arp cache so we changed the ip address

`ping 192.168.0.1`

3. then do a lil nmap mappy

`nmap -sn -PU 192.168.0.0/24`

4. then do a lil net catty cat

`nc -lu 192.168.0.2 8000`

`MetaCTF{addr3s5_r3s0lut1on_pwn4g3}`

# Interception II
Someone on this network is periodically sending the flag to ... someone else on this network, over TCP port 8000. Go get it.
ssh ctf-46ed3559da08@host.cg21.metaproblems.com -p 7000

## Solve
Similar process to Interception I.

1. There are more hosts up, so let's see what is open.

`nmap -p 8000 192.168.0.0/24 -v | grep open`

```python
Discovered open port 8000/tcp on 192.168.0.78
8000/tcp open http-alt
```

2. Ping to test connection.

`ping 192.168.0.78`

3. Check interface that we gotta change

`arp -a`

```python
ip-192-168-0-78.ec2.internal (192.168.0.78) at 02:42:0a:00:a3:c3 [ether] on eth0
```

4. Change the ip

`ifconfig eth0 192.168.0.78 netmask 255.255.255.0`

5. `ping 192.168.0.78` to refresh the arp cache so it does the spoofy

6. Setup the netcat connection

`nc -lvp 8000`

`MetaCTF{s0_m4ny_1ps_but_wh1ch_t0_ch00s3}`

# Interception III
192.168.55.3 is periodically sending the flag to 172.16.0.2 over UDP port 8000. Go get it.
By the way, I've been told the admins at this organization use really shoddy passwords.
ssh ctf-f36ef72cadc1@host.cg21.metaproblems.com -p 7000
Note: The password for this user is the flag from Interception I. You must finish Interception I before starting this challenge. 

## Solve
First enumerate.... `nmap -v 192.168.0.0/24`

![nmap scan](/posts/images/metactf/I3scan.png)

So... telnet means we can connect to smtn... we know it is a router bc usually default gateways have an end address of <0-9>.<0-9>.<0-9>.**1**

Gotta identify the router

`nmap -O 192.168.0.1`

```
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-05 08:57 UTC
Nmap scan report for ip-192-168-0-1.ec2.internal (192.168.0.1)
Host is up (0.000077s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
23/tcp open  telnet
MAC Address: 02:42:0A:00:0F:42 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
```

Important: **Linux 4.15-5.6**

google search: routers that use Linux 4.15 - 5.6 -> TP-Link

Find root login -> [TP Link Default Creds](https://www.cleancss.com/router-default/TP-Link)

```
username: root
password: admin
```

When you get access, and do an `ls`, find bird-2.0.8 ->
https://blog.kintone.io/entry/bird and https://bird.network.cz/?get_doc&f=bird-4.html

Did not solve, but was ON THE RIGHT TRACK. At 4AM, I tried changing the OSPF cost BUT I CHANGED THE WRONG INTERFACE'S COST. BIG SAD.

Here is the writeup from another person... for next time.

![solve](/posts/images/metactf/birdShit.png)

# Where in the World
I must say, every time I see one of these directional signs, I think I've got to make this into a CTF problem. It's the idea of Open Source Intelligence (OSINT) or Geospatial Intelligence (GEOINT). The idea of being able to take an image and use all of the clues within it to infer details such as where it's at or what's happening in the photo.

Here is one such picture of those signs. Your goal? Use those little details to find the name of the marina it's at which you'll submit for the flag (so MetaCTF{name of marina}

![picture](/posts/images/metactf/sign_of_cities.png)

## Solve
Google image search go brrrr.

[Search](https://www.google.com/search?tbs=simg:CAESYgm4egF4qbenjhpXCxCwjKcIGjsKOQgEEhSLHvcB1A2jDM8esSSJJsYRqS2wGhobsSNyV5t0GyxbYWZWX4cdF4DSw67Sa_1SydHZ0IAUwBAwLEI6u_1ggaCgoICAESBAXC5ToM&q=marina+&tbm=isch#imgrc=lI4Z2r9ahay2oM)

[Egg Harbor](https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.facebook.com%2FEgg-Harbor-Marina-Beach-206274509466545%2F&psig=AOvVaw19faRmXpPwUl5JjE_6oYTM&ust=1638681451821000&source=images&cd=vfe&ved=0CAwQjhxqFwoTCJCsmqGyyfQCFQAAAAAdAAAAABAD)

`MetaCTF(egg_harbor)`

# Yummy Vegetables
I love me my vegetables, but I can never remember what color they are! I know lots of people have this problem, so I made a site to help.

Here's some sauce to go with the vegetables: index.js

## Solve
Looking at the JS, we see that a query is sent so you can do a UNION attack on this boi.

Make sure you have the same number of columns as the first query though.

To find the number of columns, look at the response after submitting a query (we can just do a empty search).

`UNION SELECT 1, 2, flag FROM the_flag_is_in_here_730387f4b640c398a3d769a39f9cf9b5;--1`

`MetaCTF{sql1t3_m4st3r_0r_just_gu3ss_g0d??}`

# The Best Laid Plain
Sometimes, routers can break packets up into fragments to meet abnormal networking requirements, and the endpoint will be responsible for putting these back together. Sometimes however, this doesn't go as planned, as Microsoft found out with CVE-2021-24074. We'd like to see the function responsible for this vulnerability, but we're having some trouble finding its name... Could you see if you could find it?

## Solve
https://duckduckgo.com/?q=%22CVE-2021-24074%22+writeup&t=ffab&ia=web

https://www.armis.com/blog/from-urgent11-to-frag44-microsoft-patches-critical-vulnerabilities-in-windows-tcpip-stack/

`MetaCTF{Ipv4pReceiveRoutingHeader}`

# Pattern of Life
Hackers have breached our network. We know they are there, hiding in the shadows as users continue to browse the web like normal. As a threat hunter, your job is to constantly be searching our environment for any signs of malicious behavior.

Today you just received a packet capture (pcap) from a user's workstation. We think that an attacker may have compromised the user's machine and that the computer is beaconing out to their command and control (C2) server. Based on some other logs, we also think the attacker was *not* using a fully encrypted protocol and also did not put much care into making their C2 server look like a normal website. Your task? We'd like you to submit the port number that the C2 server is listening on in the form of MetaCTF{portnumber} as the flag.

## Solve
So from the prompt, we know we should look at HTTP(S) things. HTTP Command and Control beaconing is a thing.

1. Look at the HTTP Objects: File -> Export Objects -> HTTP Objects
2. Notice the port is 8080

`MetaCTF{8080}`

# The Searcher
Alright analyst. We need your help with some investigative work as we dive deeper into one of the infections on our company's network. We've taken a small packet capture that we know contains some C2 traffic. In order to give us some more leads for the investigation though, we'd like to see if we can identify what C2 framework the attacker was using. This will give us some leads into potential host-based artifacts that might be left behind.

Please submit the name of the C2 Framework being used in the form of MetaCTF{c2frameworkname}

## Solve 
Looking at the pcap -> notice the user agent (this is a good way to identify C2 frameworks).

```python
GET /en-us/docs.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Host: 52.44.115.131:8080
Cookie: ASPSESSIONID=fc1060eace; SESSIONID=1552332971750

HTTP/1.1 200 OK
Date: Mon, 22 Nov 2021 01:33:24 GMT
Content-Type: text/plain; charset=utf-8
Server: Microsoft-IIS/7.5
Transfer-Encoding: chunked
```

Google search on the SESSIONID: find [GitHub](https://github.com/sclow/covenant_mgmt/blob/main/config.yml.example)

`MetaCTF{Covenant}`


