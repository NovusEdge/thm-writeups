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

Starting off with some port scans and basic enumeration stuffs;
```shell-session
$ rustscan -b 4500 -a 10.10.225.44 -r 1-65535 --ulimit 5000 -t 2000 -- -oN rustscan_port_scan.txt
PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

$ rustscan -b 4500 -a 10.10.225.44 -p 80,443 --ulimit 5000 -t 2000 -- -sV -oN rustscan_service_scan.txt
PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Apache httpd
443/tcp open  ssl/http syn-ack Apache httpd


$ rustscan -b 4500 -a 10.10.225.44  --ulimit 5000 -t 2000 -- --script=vuln -oN rustscan_vuln_scan.txt 
PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
443/tcp open  https   syn-ack
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|_  /wp-login.php: Possible admin folder
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
```

Nice! Let's check some of these results:
```shell-session
$ curl http://10.10.225.44/robots.txt    
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Well! We have the first key it seems :)
```shell-session
$ curl http://10.10.225.44/key-1-of-3.txt
073403c8a58a1f80d943455fb30724b9
```

> What is key 1?
> 
> Answer: `073403c8a58a1f80d943455fb30724b9`

The other file: `fsociety.dic` seems like a wordlist of sorts, let's save it for later:
```shell-session
$ wget http://10.10.225.44/fsocity.dic
$ wc -l fsocity.dic 
858160 fsocity.dic

## removing duplicates from the wordlist (just in case :P):
$ sort fsocity.dic | uniq > fsocity.dic.uniq
```

From the vulnerability scan, we know that there's a wordpress login form on `wp-login.php`.
Brute forcing the login page using `hydra` shows us that the credentials we must use are: `Elliot:ER28-0652`. Using these to log into the service, we see the following:




## Conclusion

If this writeup helps, please consider following me on github (https://github.com/NovusEdge) and/or dropping a star on the repository: https://github.com/NovusEdge/thm-writeups

---

- Author: Aliasgar Khimani
- Room: [Mr Robot CTF](https://tryhackme.com/room/mrrobot) by [ben](https://tryhackme.com/p/ben)
