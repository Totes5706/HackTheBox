## Table of Contents

### Tier 0

 1. ✓ [Level 1: Meow](#level-1-meow) 
 2. ✓ [Level 2: Fawn](#level-2-fawn) 
 3. ✓ [Level 3: Dancing](#level-3-dancing) 
 4. ✓ [Level 4: Redeemer](#level-4-redeemer) 
 5. ✓ [Level 5: Explosion](#level-5-explosion) 
 6. ✓ [Level 6: Preignition](#level-6-preignition) 

### Tier 1

 1. ✗ [Level 1: Appointment](#level-1-appointment) 
 2. ✗ [Level 2: Sequel](#level-2-sequel) 
 3. ✗ [Level 3: Crocodile](#level-3-crocodile)
 4. ✗ [Level 4: Responder](#level-4-responder) 
 5. ✗ [Level 5: Ignition](#level-5-ignition) 
 6. ✗ [Level 7: Bike](#level-6-bike) 
 7. ✗ [Level 8: Pennyworth](#level-6-pennyworth) 
 8. ✗ [Level 9: Tactics](#level-6-tactics) 

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



## Level 4: Redeemer

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host was running an Redis on port 6379. Logging in, we were then able to get access to the database, a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 


## Level 5: Explosion

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	FreeRDP   |    	Used to connect to Windows RDP machines | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |
| 2 | 	RDP Port 3389 exposed externally   |    	 | X |  |  |

Using nmap, we were able to discover the host had RDP port 3389 open externally. Using FreeRDP, we were then able to get access remote access to the machine, a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 

## Level 6: Preignition

### Scope

The first step is listing the available information given in this scenario. We can define this setup as a grey-box, since we have been given partial information about the server. The following information is what we know about the scenario:

| # | 	Description 	| Value |
| ----------- | ----------- | ----------- |
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

Kali Linux by default comes equiped with an assortment of wordlists to run against. The first choice will be a common list for directories located at:

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
| ----------- | ----------- | ----------- |
| 1 | 	nmap   |    	Used for scanning ports on hosts. | 
| 2 | 	gobuster   |    	Used to connect to Windows RDP machines | 

| # | 	Vulnerabilities 	| Critical | High | Medium | Low |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 	Default/Weak Credentials   |    	X |  |  |  |

Using nmap, we were able to discover the host had a webserver communicating on port 80. Using gobuster, we were then able to get a directory structure of the website to locate hidden pages that were not visible. We then found admin.php, where we were able to log in as a consequence of the server administrator having poorly configured the default login credentials.


[Table of Contents](#table-of-contents) 

