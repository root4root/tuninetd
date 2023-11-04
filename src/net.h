#ifndef NET_H_
#define NET_H_

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETH_OFFSET 14  // Ethernet II header offset
#define VLAN_OFFSET 18 // 802.1Q Ethernet + VLAN offset

#define NETWORK_ORDER 1
#define HOST_ORDER 2

#define IPv4_VER 4    //
#define IPv6_VER 6    //

typedef struct Ethernet_ {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    union {
        uint16_t vlan_h[2]; //[0] - TPID, [1] - :3 Priority + :1 CFI + :12 VID (if 802.1Q)
        uint16_t etype;     //Encapsulated protocol if not-802.1Q frame
    };
    uint16_t vlan_etype;    //If type is 802.1Q, this field represents encapsulated protocol number
} __attribute__((__packed__)) ether_h;


typedef struct IPV4_ {
    uint8_t verhl;          // :4 IP version + :4 header length (in 32-bit words)
    uint8_t tos;            // :6 DSCP + :2 ECN
    uint16_t len;           // Total Length
    uint16_t id;            // Identification
    uint16_t frag;          // :3 Flags + :13 Fragment Offset
    uint8_t ttl;            // Time To Live
    uint8_t next_proto;     // Encapsulated Protocol
    uint16_t checksum;      // Header Checksum

    uint8_t src[4];         // Src IP Address
    uint8_t dst[4];         // Dst IP Address
    //Options field begins here

} __attribute__((__packed__)) ipv4_h;


typedef struct IPV6_ {
    union {
        uint8_t ver;    // :4 Version + :4 of :8 MSB Traffic Class
        uint32_t flow;  // :4 Version + :8 Traffic class + :20 Flow label
    };
    uint16_t plen;      // Payload Length
    uint8_t next_proto; // Encapsulated Protocol
    uint8_t hlimit;     // Hop limit

    uint16_t src[8];    // Src IP Address
    uint16_t dst[8];    // Dst IP Address
} __attribute__((__packed__)) ipv6_h;


typedef struct Headers_ {
    ether_h *ethernet;
    ipv4_h *ipv4;
    ipv6_h *ipv6;
} headers;


const char* proto_name(uint8_t);
uint16_t ipv4_header_checksum(const uint16_t *);
const char* ethertype_name(uint16_t, uint8_t); //HOST_ORDER | NETWORK_ORDER
uint8_t protocol_recognition(headers *, const uint8_t *);
#endif /* NET_H_ */
