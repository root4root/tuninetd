# tuninetd

Network event emitter with **pcap** and **nflog** sensors

Could be used as a VPN dispatcher, by demand service handler, remote launcher etc...


### 1. How it works

There are two events which **tuninetd** emits: 'start', when network activity is detected, and 'stop', if sensors receive no packets for a certain amount of time. Both events are processed by an external executable written in whatever language you like

#### 1.1. pcap sensor
Configure the network device first, then run **tuninetd** with the **-i** flag and **-f** for the filter (optional). It starts listening on the interface until network traffic is detected. After that, the command defined with **-c** will be triggered immediately

```sh
# tuninetd -i tun0 -f "! host 1.2.3.4" -c /path/to/launcher -t 3600
```
>based on this example, 'start' command will be:
```sh
# /path/to/launcher start > /dev/null 2>&1
```

After **-t** seconds of idle time (no packets), **tuninetd** runs the 'stop' command and waits for activity again.

Since **tuninetd** is based on **libpcap**, it's a good idea to test your filters using **tcpdump** first, as it uses the same library.

>**! Notice !** *Modern Linux distributions periodically send 'ICMPv6 router solicitation' packets and other broadcast messages, which can force tuninetd to maintain or change its state. Therefore, using filters is highly recommended to prevent unexpected behavior, even on **tun** devices*

#### 1.2. nflog sensor

In general, the behavior is the same as with pcap regarding start/stop events. You can simply use a Netfilter nfgroup (via the iptables **NFLOG** target) to capture packets; the 'filter' is then handled directly by your nflog rules. No binding to a specific network interface is required. This is the preferred mode, as it is straightforward, lightweight, and flexible.

```sh
# tuninetd -n 1 -c /path/to/launcher
```
#### 1.3. pcap + nflog
Both sensors can be used simultaneously. In this case, the event will be triggered by the first sensor to receive network packets. Both sensors must be idle for **-t** seconds before the 'stop' event is fired.
```sh
# tuninetd -i enp3s0 -f "arp and host 4.3.2.1" -n 1 -c /path/to/executable/toggletunnel.sh
```

### 2. Installation:
If you're using Debian/Ubuntu, please check deb-packages folder. Run following with root privileges:
```sh
# dpkg -i tuninetd_ver_arch.deb
# apt-get -f install
```
To install from source, please download the 'src' folder. For Debian or Ubuntu, ensure you install **build-essential**, **libpcap-dev**, and **libnetfilter-log-dev** packages first.<br/>
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
SIGHUP  (-1): don't wait ttl, jump to 'stop' event right now<br/>
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

Here some syslog example with brief packet info which caused 'start' event:
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
I've found **tuntapd** in this package; what is this for?

Well, if you intend to use a tun/tap device with a pcap sensor, you need a program bound to the interface, or pcap will not be able to capture any packets. In some cases, network services release (remove) the tun/tap device when shutting down. Tuntapd can be used to keep the device alive for pcap. You can start tuntapd from your executable's 'stop' event handler after the target service goes down, and vice versa.

### License
MIT
