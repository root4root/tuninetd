tuninetd changelog
--------
**1.5.0**
* Stack recognition improvements
* Log event packets to pcap file as well. Could be decoded later with tcpdump or Wireshark
* Use only tcp[ack] packets to zero TTL timer - indirect failure resolve

**1.4.0**
* protocol decoder for IPv4, IPv6, Ethernet, 802.1Q and combinations (README section 5)
* tun/tap listener is a separate daemon now, named *tuntapd* (README section 6)
* *pcap* sensor not hard-coupled with tun/tap interface anymore, could be used on any
* *nflog* and *pcap* sensors can work simultaneously
