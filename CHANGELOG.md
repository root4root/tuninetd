tuninetd changelog
--------
**1.4.0**
* protocol decoder for IPv4, IPv6, Ethernet, 802.1Q and combinations (README section 5)
* tun/tap listener is a separate daemon now, named *tuntapd* (README section 6)
* *pcap* sensor not hard-coupled with tun/tap interface anymore, could be used on any
* *nflog* and *pcap* sensors can work simultaneously
