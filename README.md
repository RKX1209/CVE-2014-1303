# CVE-2014-1303 PoC for Linux
CVE-2014-1303 (WebKit Heap based BOF) proof of concept for Linux.  
This repository demonstrates the WebKit heap based buffer overflow vulnerability (CVE-2014-1303) on **Linux**.  

**NOTE:** Original exploit is written for Mac OS X and PS4 (PlayStation4).  

I've ported and tested work on Ubuntu 14.04, [WebKitGTK 2.1.2](https://webkitgtk.org/releases/)  

## Usage
Firstly you need to run simple web server,  
```
$ python server.py
```  
then  
```
$ cd /path/to/webkitgtk2.1.2/
$ ./Programs/GtkLauncher http://localhost
```
You can run several tests like,  
- Crash ROP (Jump to invalid address like 0xdeadbeefdeadbeef)
- Get PID (Get current PID)
- Code Execution (Load and execute payload from outer network)  
- File System Dump (Dump "/dev" entries)  

## Description
**exploit.html**           .....  trigger vulnerability and jump to ROP chain  
**scripts/roputil.js**     .....  utilities for ROP building  
**scripts/syscall.js**     .....  syscall ROP chains  
**scripts/code.js**        .....  hard coded remote loader  
**loader/**                .....  simple remote loader (written in C)  
**loader/bin2js**          .....  convert binary to js variables (for loader)  

## Purpose
I've created this WebKit PoC for education in my course.    
I couldn't, of course, use actual PS4 console in my lecture for legal reason :(  

## Reference
CVE 2014-1303 Proof Of Concept for PS4  
(https://github.com/Fire30/PS4-2014-1303-POC)  
Liang Chen, WEBKIT EVERYWHERE: SECURE OR NOT? [BHEU14]   
(https://www.blackhat.com/docs/eu-14/materials/eu-14-Chen-WebKit-Everywhere-Secure-Or-Not.PDF)
