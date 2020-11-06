---
title: HackTheBox — Mobile Challenges
date: 2020-11-6 04:33:00 +0530
categories: [HackTheBox, Mobile Challenges]
tags: [hackthebox, ctf, challenges, mobile, leaks data,files, secure coding, reverse engineer, encryption, application security]
image: /assets/img/Posts/mobilechallenges.jpg
---
>The challenges of Hack the Box in the field of mobile applications,
have a kind of intelligence and test your ability to search, and you will learn about some types of files,
and about types of encryption as well.

## Cat Challenge
>Easy leaks.

After downloaded the file and unzipped it, we get a `.ab` file
```shell
ezi0x00@kali:~/HTB/Cat$ ls -lah
total 8.1M
drwxr-xr-x  2 ezi0x00 ezi0x00 4.0K Nov  5 16:39 .
drwxr-xr-x 10 ezi0x00 ezi0x00 4.0K Nov  5 16:39 ..
-rwxr--r--  1 ezi0x00 ezi0x00 4.1M Mar  6  2020 cat.ab
-rw-r--r--  1 ezi0x00 ezi0x00 4.1M Nov  5 16:27 Cat.zip
```
>These AB files are backup files used to restore data associated to 
 an Android application development project created using the Android SDK software.

```shell
ezi0x00@kali:~/HTB/Cat$ file cat.ab
cat.ab: Android Backup, version 5, Compressed, Not-Encrypted
```
After researching how to decompress this type of file, we found the solution here [**Solution**](https://stackoverflow.com/questions/18533567/how-to-extract-or-unpack-an-ab-file-android-backup-file)

`I used linux command` 
```shell
ezi0x00@kali:~/HTB/Cat$ ( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 cat.ab ) |  tar xfvz -
```
After extracted a many of file 
```shell
ezi0x00@kali:~/HTB/Cat$ ls -lah
total 8.1M
drwxr-xr-x  4 ezi0x00 ezi0x00 4.0K Nov  5 16:51 .
drwxr-xr-x 10 ezi0x00 ezi0x00 4.0K Nov  5 16:39 ..
drwxr-xr-x 50 ezi0x00 ezi0x00 4.0K Nov  5 16:51 apps
-rwxr--r--  1 ezi0x00 ezi0x00 4.1M Mar  6  2020 cat.ab
-rw-r--r--  1 ezi0x00 ezi0x00 4.1M Nov  5 16:27 Cat.zip
drwxr-xr-x  3 ezi0x00 ezi0x00 4.0K Nov  5 16:51 shared
```
We got two folders
Let's see what these files contain
We own two folder, Shared folder and apps folder

`apps folder`:
![website](/assets/img/Posts/appsfolder.png)
There is nothing important or interesting.
The Folders in the image only contain manifest files that do not have anything.
so we will move to the `shared folder`:
![website](/assets/img/Posts/sharedfolder.png)
After you enter the shared folder, you will find 0 folder in this folder,
you will find empty folders in the picture, except `Pictures`: 
![website](/assets/img/Posts/sharedfolderpictures.png)
You will find beautiful cats and a `weird man`
Let's see what files the man catches:
![website](/assets/img/Posts/catmobileflag.png)

And here we found the flag from leaked data.

## Cryptohorrific Challenge
>Secure coding is the keystone of the application security!

After downloaded file and unzipped it, we get a hackthebox.app folder
```shell
ezi0x00@kali:~/HTB/hackthebox.app$ ls -lah
total 72K
drwx------  4 ezi0x00 ezi0x00 4.0K May  3  2018 .
drwxr-xr-x 10 ezi0x00 ezi0x00 4.0K Nov  5 16:39 ..
drwx------  4 ezi0x00 ezi0x00 4.0K May  3  2018 Base.lproj
-rw-r--r--  1 ezi0x00 ezi0x00  185 May  3  2018 challenge.plist
drwx------  2 ezi0x00 ezi0x00 4.0K May  3  2018 _CodeSignature
-rw-r--r--  1 ezi0x00 ezi0x00  32K May  3  2018 hackthebox
-rw-r--r--  1 ezi0x00 ezi0x00 9.6K May  3  2018 htb-company.png
-rw-r--r--  1 ezi0x00 ezi0x00 1.2K May  3  2018 Info.plist
-rw-r--r--  1 ezi0x00 ezi0x00    8 May  3  2018 PkgInfo
```
We were presented with a `IOS` mobile application.
Since the plist files were not easily readable, I started to research this as the challenge.plist file seemed to contain an interesting base64 string. 
After finding this [**article**](https://osxdaily.com/2016/03/10/convert-plist-file-xml-binary-mac-os-x-plutil/) on converting plist files to XML, 
I quickly found the plistutil tool for linux and was able to convert plist to xml 
```shell
ezi0x00@kali:~/HTB/hackthebox.app$ plistutil -i challenge.plist -o challenge.plist.xml
ezi0x00@kali:~/HTB/hackthebox.app$ cat challenge.plist.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
        <dict>
                <key>flag</key>
                <string>Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==</string>
                <key>id</key>
                <string>123</string>
                <key>title</key>
                <string>HackTheBoxIsCool</string>
        </dict>
</array>
</plist>
```
We found encoding line.

let's do some reverse engineering, i think it be required because we have Mach-O 64-bit x86_64 executable file.
i will use hopper disassembler 
![website](/assets/img/Posts/reversemobile1.png)

let's see `ViewController SecretManager` function
![website](/assets/img/Posts/reversemobile2.png)

After analysis it uses Apple’s CCCrypt, this function did not (yet) help me much. 
Looking further to where the function was called upon, appeared to be in the `viewDidLoad` function.
This function call showed also the Key and IV value

let's see `ViewController viewDidLoad`
![website](/assets/img/Posts/reversemobile3.png)

hollaaaaa :"D we found iv key 
```shell
!A%D*G-KaPdSgVkY
```
>this kind of encryption, it's called `AES` is a symmetric encryption algorithm.
it used `IV`  initialization vector as a secret key for data encryption.
so we have encoded text in plist file then we nedd iv key to decode it. 

let's decrypt it with this [**tool**](https://www.devglan.com/online-tools/aes-encryption-decryption)

![website](/assets/img/Posts/decrypt1.png)

![website](/assets/img/Posts/decrypt2.png)

and here we are finished all mobile challenes 

Thanks for reading, Suggestions & Feedback are appreciated !


