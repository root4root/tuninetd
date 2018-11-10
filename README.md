# tuninetd

Simple yet powerful tun/tap event emitter. Could be used like VPN dispatcher...

### How it works:
You should create and configure tun/tap device, then run **tuninetd**. It starts listening on that interface until network traffic will be detected. After that, interface will be released and certain command executed. From now on daemon is in monitoring state.
After N seconds of interface idle, tuninetd send "stop" command by path that you define and start listening interface by its own again.
 
Since **tuninetd** based on **libpcap**, you can specify filter to trigging "start" and monitoring iddle (i.e. cutoff unwanted traffic). To test/debug pcap rules you might use tcpdump which is based on the same library.

**! OR !**

You can simply use netfilter nfgroup (*iptables NFLOG target*), for reading packets from. No need binding to tun/tap interface nor heavy libpcap sensor. This is more lightweight mode and because of that - more reliable. Option available since v1.1.0.


**tuninetd** allows deploy "VPN by demand" or any other "by demand" services, which is the main idea of the project.

### Installation:
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

Congrats! Tuninend is ready to use. Check ./bin folder. :)

### Usage:

tuninetd {-i \<ifname> | -n \<nflog-group>} -c \<path> [-m \<iftype>] [-f \<filter>] [-t \<ttl>] [-d]

**-i \<ifname>**: interface to use (tun or tap). Must be up and configured.<br/>
**-n \<nflog-group>**: iptables NFLOG group number ('-i', '-m' and '-f' will be ignored).<br/>
**-c \<path>**: will be executed with 'start' and 'stop' parameter.<br/>
**-m \<iftype>**: 'tun' or 'tap' mode. By default 'tun', should be set properly.<br/>
**-f \<filter>**: specify pcap filter, similar to tcpdump<br/>
**-t \<ttl>**: seconds of interface (traffic) idle, before 'stop' command (default is 600).<br/>
**-d**: demonize process<br/>
**-h**: prints this help

`--- If tuninetd stuck in start condition for any reason, you can reset to "standby" (i.e. stop state) with SIGHUP. ---`

### Examples:
Before launching as daemon make sure there is no errors occurs. In daemon mode tuninetd write status messages and errors to syslog.

```sh
# tuninetd -i tun0 -c /test/runtunnel.sh -f "! host 1.2.3.4" -t 3600 -d
# tuninetd -n 2 -c /test/runtunnel.sh -t 3600 -d
```

Check ```example``` folder to find some shell scripts.

To create and bring up ```tun``` device, could be used following commands:
```sh
# ip tuntap add name tun0 mode tun
# ip link set tun0 up
```

For more information about routing and configuring net devices, I strongly suggest LARCT how-to.

*! Notice ! Modern Linux distributions periodically send 'icmpv6 router solicitation' packets, which cause tuninetd keep or change its status (calling 'start' script for example). This situation appears in tun/tap mode without pcap filter applied.*

### License:
MIT
### Author:
Paul aka root4root \<root4root at gmail dot com><br/>
**Any comment/suggestions are welcomed.**
