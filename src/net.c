#include "net.h"

/**
 * @brief   returns EtherType name
 *
 * @param   type - Ethernet type ID
 * @param   order - NETWORK_ORDER or HOST_ORDER
 *
 * @return  const string - Ethernet type name
 */
const char* ethertype_name(uint16_t type, uint8_t order) //HOST_ORDER
{
    if (order == NETWORK_ORDER) {
        type = ntohs(type);
    }

    switch (type) {
            case 0x0800: return "IPv4";
            case 0x0806: return "ARP";
            case 0x86DD: return "IPv6";
            case 0x8100: return "802.1Q";
            case 0x0842: return "Wake-on-LAN";
            case 0x8035: return "RARP";
            case 0x809B: return "AppleTalk";
            case 0x80F3: return "AppleTalk ARP";
            case 0x8137: return "IPX";
            case 0x8808: return "Ethernet-Flowcontrol";
            case 0x8847: return "MPLS-unicast";
            case 0x8848: return "MPLS-multicast";
            case 0x8863: return "PPPoE-Discovery";
            case 0x8864: return "PPPoE-Session";
            case 0x88BF: return "MikroTik-RoMON";
            case 0x88CC: return "LLDP";
        }

        return "unresolved";
}

const char* proto_name(uint8_t proto)
{
    switch (proto) {
        case 6:   return "TCP";
        case 17:  return "UDP";
        case 1:   return "ICMP";
        case 58:  return "IPv6-ICMP";
        case 47:  return "GRE";
        case 4:   return "IP-in-IP";
        case 115: return "L2TP";
        case 89:  return "OSPF";
        case 88:  return "EIGRP";
        case 2:   return "IGMP";
        case 3:   return "GGP";
        case 41:  return "IPv6";
        case 43:  return "IPv6-Route";
        case 44:  return "IPv6-Frag";
        case 50:  return "ESP";
        case 52:  return "I-NLSP";
        case 55:  return "MOBILE";
        case 56:  return "TLSP";
        case 59:  return "IPv6-NoNxt";
        case 60:  return "IPv6-Opts";
        case 66:  return "RVD";
        case 97:  return "ETHERIP";
        case 98:  return "ENCAP";
        case 108: return "IPComp";
        case 111: return "IPX-in-IP";
        case 124: return "IS-IS-over-IPv4";
        case 129: return "IPLT";
        case 132: return "SCTP";
        case 136: return "UDPLite";
        case 137: return "MPLS-in-IP";
        case 143: return "Ethernet";
    }

    return "unresolved";
}

/**
 * @brief   validate IPv4 header checksum
 *
 * @param   packet - pointer to beginning of IPv4 packet
 *
 * @return  0 if checksum is valid
 */
uint16_t ipv4_header_checksum(const uint16_t *packet)
{
    //IPv4 header length in bytes
    uint8_t hdr_length_b = (*packet & 0x0F) * 4; //IHL = number of 32-bit words. IHL * 32 / 8 = IHL * 4

    uint32_t checksum = 0;

    for (uint8_t i = 0; i < hdr_length_b / 2; ++i) {
        checksum += packet[i];
    }

    checksum = (checksum >> 16) + (checksum & 0x0000FFFF);

    return (uint16_t) ~checksum;
}

/**
 * @brief   parse packet to respective headers
 *
 * @param   hdrs - struct of founded headers
 * @param   pkt  - pointer to beginning of some packet
 *
 * @return  IP version, 0 if not discovered
 */
uint8_t protocol_recognition(headers *hdrs, const uint8_t *pkt)
{
    uint8_t ver = *pkt >> 4;

    if (ver == IPv4_VER) {
        if (ipv4_header_checksum((uint16_t*)pkt) == 0) {
            hdrs->ipv4 = (ipv4_h*)pkt;
            return IPv4_VER;
        }
    }

    hdrs->ethernet = (ether_h*)pkt;

    if (hdrs->ethernet->etype == 0x0008) { //0x0800 (IPv4) - network order
        if (ipv4_header_checksum((uint16_t*)(pkt + ETH_OFFSET)) == 0) {
            hdrs->ipv4 = (ipv4_h*)(pkt + ETH_OFFSET);
            return IPv4_VER;
        }
    }

    if (hdrs->ethernet->etype == 0xDD86) { //0x86DD (IPv6) - network order
        if (pkt[ETH_OFFSET] >> 4 == IPv6_VER) {
            hdrs->ipv6 = (ipv6_h*)(pkt + ETH_OFFSET);
            return IPv6_VER;
        }
    }

    if (hdrs->ethernet->etype == 0x0081) { //0x8100 (802.1Q) - network order

        if (hdrs->ethernet->vlan_etype == 0x0008) {
            if (ipv4_header_checksum((uint16_t*)(pkt + VLAN_OFFSET)) == 0) {
                hdrs->ipv4 = (ipv4_h*)(pkt + VLAN_OFFSET);
                return IPv4_VER;
            }
        }

        if (hdrs->ethernet->vlan_etype == 0xDD86) {
            if (pkt[VLAN_OFFSET] >> 4 == IPv6_VER) {
                hdrs->ipv6 = (ipv6_h*)(pkt + VLAN_OFFSET);
                return IPv6_VER;
            }
        }
    }


    if (ver == IPv6_VER) {

        hdrs->ipv6 = (ipv6_h*)pkt;

        /*
         * Since IPv6 header hasn't a checksum, the best what we can do
         * is guessing based on common encapsulated protocol ID.
         *
         * Or implement full stack recognition with checksums verification on each layer,
         * which is great amount of efforts (not for this project anyway)
         *
         * If you have any suggestions, please let me know
         */
        switch (hdrs->ipv6->next_proto) {
            case 41:    //IPv6
            case 43:    //IPv6-Route
            case 59:    //IPv6-NoNxt
            case 60:    //IPv6-Opts
            case 58:    //IPv6-ICMP
            case 44:    //IPv6-Frag
            case 17:    //UDP
            case 6:     //TCP
                hdrs->ethernet = NULL;
                return IPv6_VER;
            default:
                hdrs->ipv6 = NULL;
        }
    }

    return 0;
}
