---
title: Malware Reverse Engineering - CyberTalents Quals 2020
published: true
---

Hello Hackers.
This is my writeup for Cybertalents Qualifications. <br>
I'll continue the writeup for CyberTalents Quals Next Category is Reverse Engineering <br>

> Challange Name: isolation <br>
> Category: Malware Reverse Engineering <br>
> Points: 100  <br>
> Difficulty: Medium <br>
> Description: Devoloper think that the real hacker does not need any buttons to get the flag.

It is an .apk file .. you can download the apk from [here](https://hubchallenges.s3-eu-west-1.amazonaws.com/Reverse/isolation.apk
https://www.dcode.fr/brainfuck-language) <br>


First of all i install the apk file on genymotion emulator and run it <br>


![](/../../assets/img/1.PNG)<br>


When i open the application i see login page but without login button

![](/../../assets/img/blahdf.PNG)<br>

this is the thing which mentioned in the description 

Then I realized that there is another page i will access it from outside the application and this issue called access control issue 

![](/../../assets/img/hackerman.PNG)<br>

first thing came in my mind it's decode the apk file

![](/../../assets/img/apk.PNG)<br>

I decode the app using apktool `apktool d isolate.apk`

![](/../../assets/img/2.PNG)<br>

Then i inspect AndroidManiFest.XML looking for any activities

![](/../../assets/img/3.PNG)<br>

As we see there is an Activity called `SECRETBOX` and it is protected with an intent filter 
and the intent filter should not use it as a protection mechanism because when using the intent filter whe an app component like activity the component is publicly exported , so the activity is vulenrable and it can be invoke from any outside application

So let's make some fun 

via adb shell i use this command ` am start -W com.cybertalents.otherside/.SecretBox `

and finally we made it.. 

![](/../../assets/img/4.PNG)<br>

D1FCF5F5F6B9FFEBF6F4B9DAB2B2


