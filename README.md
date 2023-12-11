# tuninetd

Network event emitter with **pcap** and **nflog** sensors.

Could be used as VPN dispatcher, by demand service handler, remote launcher etc...


### 1. How it works

There are two events which **tuninetd** emits. "start", when network activity is detected, and "stop" if sensors no receive packets for certain amount of time. Both of events processed by external executable written on language whatever you like.

#### 1.1. pcap sensor
You should configure network device first, then run **tuninetd** with **-i** flag and **-f** for filter (optional). It starts listening on the interface, until network traffic will be detected. After that command defined with **-c** will be executed. 

```sh
# tuninetd -i tun0 -f "! host 1.2.3.4" -c /path/to/launcher -t 3600
```
>then "start" command from **tuninetd** will be:
```sh
# /path/to/launcher start > /dev/null 2>&1
```

After **-t** seconds of idle (no packets), **tuninetd** runs "stop" command and wait for activity again to start process over.

Since **tuninetd** based on **libpcap**, it's a good idea to play with filters using **tcpdump** first, which is based on the same library.

>**! Notice !** *Modern Linux distributions periodically send 'icmpv6 router solicitation' packets and other broadcast messages, which force tuninetd keep or change its state. So, using filters highly recommended to prevent unexpected behavior even on **tun** devices*

#### 1.2. nflog sensor

In general, behavior the same as pcap in terms of start/stop events. You could simply use netfilter nfgroup (*iptables **NFLOG** target*) to capture packets from, and "filter" already in nflog rule(s). No binding to certain network interface required. This is preferable mode since straightforward, lightweight and flexible

```sh
# tuninetd -n 1 -c /path/to/launcher
```
#### 1.3. pcap + nflog
You could use both sensors at the same time. In this case, event will be triggered from first sensor which receive a network packets. And yes, both sensors should be idle for **-t** seconds, before "stop" event fired
```sh
# tuninetd -i enp3s0 -f "arp and host 4.3.2.1" -n 1 -c /path/to/executable/toggletunnel.sh
```

### 2. Installation:
If you're using Debian/Ubuntu, please check deb-packages folder. Run following with root privileges:
```sh
# dpkg -i tuninetd_ver_arch.deb
# apt-get -f install
```
To install from sources, please download src folder. In case Debian/Ubuntu, don't forget to install **build-essential**, **libpcap-dev** and **libnetfilter-log-dev** packages first.<br/>
```sh
# cd /download/folder/src
# make
```

Congrats! Tuninend ready to use, check ./bin folder.

### 3. Usage
#### 3.1. Launch

```
tuninetd -i <ifname> -c <path> [-a] [-d] [-f <filter>] [-n <nflog-group>] [-t <ttl>] [-w <path>]
tuninetd -n <nflog-group> -c <path> [-a] [-d] [-i <ifname> [-f <filter>]] [-t <ttl>] [-w <path>]

-a: use only tcp[ack] packets to zero TTL timer (see -t)
-c <path>: to executable, will be run with 'start' and 'stop' parameter accordingly
-d: daemonize process
-f <filter>: apply packet filter, similar to tcpdump
-i <ifname>: network interface to use with pcap
-n <nflog-group>: netfilter nflog group ID
-t <ttl>: seconds of interface idle before 'stop' command will be run. Default 600
-w <path>: dump "start event" packets to pcap-savefile as well

-h: print this help
-v: print version
```

#### 3.2. Signals
SIGHUP  (-1): don't wait ttl, jump to "stop" event right now<br/>
SIGUSR1 (-10): write to syslog current configuration and state

### 4. Examples
Before launching as a daemon make sure there is no errors. In daemon mode tuninetd write status messages and errors to syslog.

```sh
# tuninetd -n 1 -c /path/to/executable/toggletunnel.sh -w /path/to/pcap-savefile
# tuninetd -i tap0 -c /path/to/executable/toggleservice.sh -a
# tuninetd -i tun0 -f "! host 1.2.3.4" -c /path/to/executable/somebinary -t 3600 -d
# tuninetd -i enp3s0 -f "arp and host 4.3.2.1" -n 1 -c /path/to/executable/run.py
```

Check ```example``` folder to find some scripts.

### 5. Logging

Here some syslog example with brief packet info which caused "start" event:
```
Nov  1 21:32:14 router1 tuninetd: Success! Tuninetd has been started with PID: 23686
Nov  1 21:32:14 router1 tuninetd: Binding to interface enp3s0
Nov  1 21:32:14 router1 tuninetd: Start listening nflog-group 1
Nov  1 21:32:14 router1 tuninetd: NFLOG: adjust nfnl_rcvbufsiz to 300000
Nov  1 21:48:34 router1 tuninetd: NFLOG: start command done
Nov  1 21:48:35 router1 tuninetd: |- IPv4 192.168.1.1 > 13.107.42.14, NXT_HDR: 0x06 (TCP)
Nov  1 21:48:35 router1 tuninetd: |- MAC: 1b:1c:0d:45:a9:e1 > f4:6d:04:64:11:25, EtherType: 0x0800 (IPv4)
Nov  1 22:08:59 router1 tuninetd: CORE: executing STOP command...
Nov  1 22:36:07 router1 tuninetd: PCAP: start command done
Nov  1 22:36:08 router1 tuninetd: |- IPv6 fe80::f66d:4ff:fe64:1124 > ff02::2, NXT_HDR: 0x3A (IPv6-ICMP)
Nov  1 22:36:08 router1 tuninetd: |- MAC: f4:6d:04:64:11:24 > 33:33:00:00:00:02, 802.1Q VID: 3, EtherType: 0x86DD (IPv6)

```

```sh
# killall -10 tuninetd 
```

```
Nov  1 22:42:17 router1 tuninetd: SIGUSR1 caught:
Nov  1 22:42:17 router1 tuninetd: - capture engine: pcap, enp3s0
Nov  1 22:42:17 router1 tuninetd: -- pcap filter: "ip6"
Nov  1 22:42:17 router1 tuninetd: - capture engine: nflog group 1
Nov  1 22:42:17 router1 tuninetd: - using packets with tcp[ack] flag to reset TTL timer
Nov  1 22:42:17 router1 tuninetd: - file to dump start event packets (pcap format): /path/to/pcap.file
Nov  1 22:42:17 router1 tuninetd: - event path: /etc/tuninetd/toggletunnel.sh
Nov  1 22:42:17 router1 tuninetd: - TTL: 600 sec.
Nov  1 22:42:17 router1 tuninetd: - current status: up (ON), time since last captured packet: 112 sec.

```

### 6. Tuntapd
I've found **tuntapd** in this package, what this for? 

Well, if you're about to use tun/tap device with pcap sensor, you need some program binded to the interface, or pcap can't capture any packets. In some cases, network services release tun/tap when shutting down. Tuntapd could be used to keep device alive for pcap. Start tuntapd from your executable by "stop" event handler, after desired service go down and vise-versa.

### License
MIT
### Author
Paul aka root4root \<root4root at gmail dot com><br/>
**Any comments and suggestions are welcomed.**
