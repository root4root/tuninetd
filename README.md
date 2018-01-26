# Tuninetd

**tuninetd** - is a simple daemon for tun/tap devices, similar to classic inetd by its logic, but for mentioned interfaceces, instead of a ports.

#### How it works:
First, you create and configure tun/tap device, then run **tuninetd**. It start listening on that interface, until network packet will be received.
Next, interface will be released and certain command is executed. From now on, daemon in monitoring state.
After N seconds of interface idle, tuninetd send "stop" command by path, that you define, and start listening interface by its own again.

Since, **tuninetd** based on **libpcap**, you can specify filter to trigging "start" event and monitoring iddle (i.e. cutoff unwanted traffic).
To test/debug filters rules - use tcpdump, because it built upon the same library.

**tuninetd** allows you deploy "VPN by demand" or any other "by demand" services, which is the main idea of the project.

#### Installation:
To build tuninetd, you need to have libpcap-dev library (Debian)<br/>
Download all files and:
```sh
# cd /folder/with/sourcefiles
# make
```

#### Usage:

tuninetd -i \<ifname> -c \<path> [-m \<iftype>] [-f <filter>] [-t \<ttl>] [-d]

**-i \<ifname>**: interface to use (tun or tap). Must be up and configured.<br/>
**-c \<path>**: will be executed with 'start' and 'stop' parameter.<br/>
**-m \<iftype>**: 'tun' or 'tap' mode. By default 'tun', should be set properly.<br/>
**-f \<filter>**: specify pcap filter, similar to tcpdump<br/>
**-t \<ttl>**: seconds of interface idle, before 'stop' command (default is 600).<br/>
**-d**: demonize process<br/>
**-h**: prints this help text

#### Example:
```sh
# tuninetd -i tun0 -c /test/runtunnel.sh -f "! host 1.2.3.4" -t 3600 -d
```

### License:
MIT
### Author:
Paul aka root4root \<root4root at gmail dot com><br/>
**Any suggestions will be appreciated.**
