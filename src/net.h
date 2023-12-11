#ifndef NET_H_
#define NET_H_

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#define SUCCESS 0
#define FAIL 1

#define ETH_HDR_LEN 14   // Ethernet II header offset
#define DOT1Q_HDR_LEN 18 // 802.1Q offset
#define IPv6_HDR_LEN 40  // IPv6 header offset

#define NETWORK_ORDER 1
#define HOST_ORDER 2

#define IPv4_VER 4    //
#define IPv6_VER 6    //

//- LINK LAYER
#define ETH   0x01000000
#define DOT1Q 0x02000000
#define LINK_MASQ 0xFF000000

//- NETWORK LAYER
#define IPV4 0x00080000
#define IPV6 0x0086DD00
#define NET_MASQ 0x00FFFF00

//- TRANSPORT LAYER
#define TCP 0x00000006
#define UDP 0x00000011
#define TRANSP_MASQ 0x000000FF

#define ACK 0b00010000 // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN

typedef struct PCAP_GLOBAL_ {
    uint32_t magic_number;  // 0xA1B2C3D4 byte order or 0xD4C3B2A1
    uint16_t version_major; // 0x2 current
    uint16_t version_minor; // 0x4 current
    int32_t thiszone;       // 0x0 in practice
    uint32_t sigfigs;       // 0x0 in practice
    uint32_t snaplen;       // 0x40000 in octets (max length of captured packets)
    uint32_t network;       // 0x1 - Ethernet, 0x65 - RAW IPv4/IPv6
} __attribute__((__packed__)) pcap_file_h;


typedef struct PCAP_PACKET_ {
    uint32_t ts_sec;    // timestamp seconds
    uint32_t ts_usec;   // timestamp microseconds (souldn't reach 1 second)
    uint32_t incl_len;  // number of OCTETS of packet saved in file
    uint32_t orig_len;  // actual length of packet
} __attribute__((__packed__)) pcap_pkt_h;


typedef struct ETHERNET_ { // 14 bytes
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t etype;     //Encapsulated protocol if not-802.1Q frame
} __attribute__((__packed__)) ether_h;


typedef struct DOT1Q_ { // 18 bytes
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t tpid;        // TPID
    uint16_t pcv;         // :3 Priority + :1 CFI + :12 VID
    uint16_t etype;       // EtherType
} __attribute__((__packed__)) dot1q_h;


typedef struct IPV4_ { // 20 - 60 bytes
    uint8_t verhl;          // :4 IP version + :4 header length (in 32-bit words)
    uint8_t tos;            // :6 DSCP + :2 ECN
    uint16_t len;           // Total Length
    uint16_t id;            // Identification
    uint16_t frag;          // :3 Flags + :13 Fragment Offset
    uint8_t ttl;            // Time To Live
    uint8_t next_proto;     // Encapsulated Protocol
    uint16_t checksum;      // Header Checksum

    uint8_t src[4];         // SRC Address
    uint8_t dst[4];         // DST Address
    //Options field begins here

} __attribute__((__packed__)) ipv4_h;


typedef struct IPV6_ {  // 40 bytes
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


typedef struct TCP_ {  // 20 - 60 bytes
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;  // :4 data offset (hdr length in 32-bit words) + :4 Reserverd (0000)
    uint8_t flags;        // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint8_t win_size;
    uint16_t checksum;
    uint16_t urg_ptr;     // Urgent pointer
    // Variable length options field begins here
} __attribute__((__packed__)) tcp_h;


typedef struct LAYER_ {
    uint16_t h_len;     // Length of a header
    void *header;         // Pointer to stat a header
} layer;


typedef struct PACKET_ {
    uint32_t stack;      // :8 data link code + :16 ethertype + :8 IP protocol
    pcap_pkt_h pkt_h;
    void *raw_pkt_ptr;   // Pointer to raw packet received from sensor
    layer link_l;
    layer network_l;
    layer transport_l;
} packet;


const char* proto_name(uint8_t);
const char* ethertype_name(uint16_t, uint8_t); //HOST_ORDER | NETWORK_ORDER
void stack_recognition(packet *);

#endif /* NET_H_ */
