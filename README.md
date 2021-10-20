# tuninetd

Simple yet powerful event emitter by **tun/tap** (with/without **pcap** filter) or **nflog** source. 

Could be used as: VPN dispatcher, simplified detection system, by demand service handler, tricky lock etc...

### 1. How it works:
#### 1.1. tun/tap + pcap mode:
You should create and configure tun/tap device first, then run **tuninetd**. It starts listening on this interface, until network traffic will be detected. After that, interface immediately releasing and specified command (with -c) will execute. From now on, daemon in monitoring state.

---
>For example:
```sh
# tuninetd -i tun0 -c /path/to/launcher
```
>then "start" command from **tuninetd** will be:
```sh
# /path/to/launcher start > /dev/null 2>&1
```
>"stop" command in the same manner.
---

After -t seconds of interface idle (no packets through), tuninetd send "stop" command by path that defined with -c, and start listening interface by itself again.

Since **tuninetd** based on **libpcap**, you can specify capture filter. To test pcap rules might use tcpdump which is based on the same library.

>**! Notice !** *Modern Linux distributions periodically send 'icmpv6 router solicitation' packets, which cause tuninetd keep or change state. This situation appears in tun/tap mode without pcap filter applied.*

#### 1.2. nflog mode:

In general, behavior the same as tun/tap in part of start/stop. You could simply use netfilter nfgroup (*iptables **NFLOG** target*) to reading packets from. No binding to tun/tap device nor libpcap sensor. This is more lightweight mode and, because of that, - more reliable.

### 2. Installation:
If you're using Debian/Ubuntu please check deb-packages folder. Choose appropriate architecture, then run following command with root privileges:
```sh
# dpkg -i tuninetd_ver_arch.deb
# apt-get -f install
```
To install from sources download src folder. In case Debian/Ubuntu, you should also install **build-essential**, **libpcap-dev** and **libnetfilter-log-dev** packages first. To build tuninetd just run:<br/>
```sh
# cd /download/folder/src
# make
```

Congrats! Tuninend ready to use. Check ./bin folder.

### 3. Usage:
#### 3.1. Launch:

```sh
# tuninetd {-i <ifname> | -n <nflog-group>} -c <path> [-m <iftype>] [-f <filter>] [-t <ttl>] [-d]
```

**-i \<ifname>**: interface to use (tun or tap). Must be up and configured.<br/>
**-n \<nflog-group>**: iptables NFLOG group ('-i', '-m' and '-f' will be ignored).<br/>
**-c \<path>**: will execute with 'start' and 'stop' parameter.<br/>
**-m \<iftype>**: 'tun' or 'tap' mode. By default 'tun', should be set properly.<br/>
**-f \<filter>**: specify pcap filter, similar to tcpdump<br/>
**-t \<ttl>**: seconds since last packet before 'stop' command (default is 600).<br/>
**-d**: daemonize process<br/>
**-h**: print this help

---

#### 3.2. Signals:
SIGHUP  (-1): switch tuninetd to standby mode (deadlock resolving)<br/>
SIGUSR1 (-10): write to syslog current state (debug information)



### 4. Examples:
Before launching as a daemon make sure there is no errors. In daemon mode tuninetd write status messages and errors to syslog.

```sh
# tuninetd -i tun0 -c /test/runtunnel.sh -f "! host 1.2.3.4" -t 3600 -d
# tuninetd -n 2 -c /test/runtunnel.sh -t 3600 -d
```

Check ```example``` folder to find some shell scripts.

To create and bring up ```tun``` device could be used following commands:
```sh
# ip tuntap add dev tun0 mode tun
# ip link set tun0 up
```

For more information about routing and configuring network devices, I strongly suggest LARTC how-to.

<br/>

---
```sh
# killall -10 tuninetd 
```
syslog:<br/>

>Oct 20 18:42:20 router1 tuninetd: SIGUSR1 caught:<br/>
>Oct 20 18:42:20 router1 tuninetd: - Capture engine: nflog group 1<br/>
>Oct 20 18:42:20 router1 tuninetd: - cmd_path = /etc/tuninetd/toggletunnel.sh<br/>
>Oct 20 18:42:20 router1 tuninetd: - TTL = 600 sec.<br/>
>Oct 20 18:42:20 router1 tuninetd: - Current status: up (ON), time since last captured packet: 2 sec.
---


### License:
MIT
### Author:
Paul aka root4root \<root4root at gmail dot com><br/>
**Any comment/suggestions are welcomed.**
