# tuninetd

Is a simple daemon for tun/tap devices, similar to classic inetd by its logic, but for mentioned interfaceces, instead of a ports.

### How it works:
First, you create and configure tun/tap device, then run **tuninetd**. It start listening on that interface, until network packet will be received.
Next, interface will be released and certain command is executed. From now on, daemon in monitoring state.
After N seconds of interface idle, tuninetd send "stop" command by path, that you define, and start listening interface by its own again.

Since, **tuninetd** based on **libpcap**, you can specify filter to trigging "start" event and monitoring iddle (i.e. cutoff unwanted traffic).
To test/debug filters rules - use tcpdump, because it built upon the same library.

**tuninetd** allows you deploy "VPN by demand" or any other "by demand" services, which is the main idea of the project.

### Installation:
If you're using Debian/Ubuntu, check deb-packages folder. Choose appropriate architecture, then run following command with root privileges:
```sh
# dpkg -i tuninetd_ver_arch.deb
```
To install it from sources, download src folder. In case Debian/Ubuntu, you should also install **build-essential** and **libpcap-dev** packages. To build tuninetd, run:<br/>
```sh
# cd /download/folder/src
# make
```
After that, bin folder should appears, which contains tuninetd.

### Usage:

tuninetd -i \<ifname> -c \<path> [-m \<iftype>] [-f <filter>] [-t \<ttl>] [-d]

**-i \<ifname>**: interface to use (tun or tap). Must be up and configured.<br/>
**-c \<path>**: will be executed with 'start' and 'stop' parameter.<br/>
**-m \<iftype>**: 'tun' or 'tap' mode. By default 'tun', should be set properly.<br/>
**-f \<filter>**: specify pcap filter, similar to tcpdump<br/>
**-t \<ttl>**: seconds of interface idle, before 'stop' command (default is 600).<br/>
**-d**: demonize process<br/>
**-h**: prints this help text

### Examples:
Before launching as daemon, make sure there is no errors occurs. In daemon mode, tuninetd write status messages and errors to syslog.

```sh
# tuninetd -i tun0 -c /test/runtunnel.sh -f "! host 1.2.3.4" -t 3600 -d
```

You can find example script 'runtunnel.sh', within examples folder.

To create and up tun device, could be used next commands:
```sh
# ip tuntap add name tun0 mode tun
# ip link tun0 up
```

For more information about routing and configuring net devices, please check official documentation.

*! Notice, that the modern Linux distributions periodically send 'icmpv6 router solicitation' packets, which, probably, doesn't make sense in your case, but cause tuninetd state changing (call of 'start' script).*

### License:
MIT
### Author:
Paul aka root4root \<root4root at gmail dot com><br/>
**Any suggestions will be appreciated.**
