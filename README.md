Contributed By: Joe Totes

## Tier 0

 1. [Level 1: Meow](#level-1-meow) - July 16th, 2022
 2. [Level 2: Fawn](#level-2-fawn) - July 16th, 2022
 3. [Level 3: Dancing](#level-3-dancing) - July 16th, 2022
 4. [Level 4: Redeemer](#level-4-redeemer) - July 16th, 2022
 5. [Level 5: Explosion](#level-5-explosion) - July 16th, 2022
 6. [Level 6: Preignition](#level-6-preignition) - July 16th, 2022

## Level 1: Meow

### Enumeration

The first step is understanding what information we currently have access too. We have been given an IP address of the machine, so we can start initiating a port scan using nmap.

First we can try to see if we can make contact with the machine with a ping request.

```
ping {ip address}
```

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
nmap -p- --min-rate 5000 -sC -sV {ip address}
```

Where:

```
-p-: scans ALL ports
--min-rate <number>: Send packets no slower than <number> per second
-sC: equivalent to --script=default
-sV: Probe open ports to determine service/version info
```


