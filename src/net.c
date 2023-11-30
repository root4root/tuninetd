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
 * FROM Suricata project - https://github.com/OISF/suricata
 * EXACT LOCATION - https://github.com/OISF/suricata/blob/suricata-7.0.2/src/decode-ipv4.h#L196-L244C2
 *
 * @brief Calculate or validate the checksum for the IP packet
 *
 * @param pkt  Pointer to the start of the IP packet
 * @param hlen Length of the IP header
 * @param init The current checksum if validating, 0 if generating.
 *
 * @return csum For validation 0 will be returned for success, for calculation
 *    this will be the checksum.
 */
static inline uint16_t ipv4_checksum(const uint16_t *pkt, uint16_t hlen, uint16_t init)
{
    uint32_t csum = init;

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[6] + pkt[7] +
        pkt[8] + pkt[9];

    hlen -= 20;
    pkt += 10;

    if (hlen == 0) {
        ;
    } else if (hlen == 4) {
        csum += pkt[0] + pkt[1];
    } else if (hlen == 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
    } else if (hlen == 12) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5];
    } else if (hlen == 16) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7];
    } else if (hlen == 20) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9];
    } else if (hlen == 24) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11];
    } else if (hlen == 28) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13];
    } else if (hlen == 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
    } else if (hlen == 36) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17];
    } else if (hlen == 40) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17] + pkt[18] + pkt[19];
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}

static inline uint8_t handle_ipv4(ipv4_h *ipv4, packet *packet)
{
    packet->network_l.h_len = (ipv4->verhl & 0x0F) * 4;

    if (ipv4_checksum((uint16_t*)ipv4, packet->network_l.h_len, ipv4->checksum) == SUCCESS) {

        packet->stack |= IPV4;
        packet->network_l.header = (void*)ipv4;

        if (ipv4->next_proto == TCP) {
            packet->stack |= TCP;
            packet->transport_l.header = ((void*)ipv4) + packet->network_l.h_len;
            packet->transport_l.h_len = (((tcp_h*)packet->transport_l.header)->data_offset >> 4) * 4;
        }

        return SUCCESS;
    }
    return FAIL;
}

static inline uint8_t handle_ipv6(ipv6_h *ipv6, packet *packet)
{
    if (ipv6->ver >> 4 == IPv6_VER) {

        packet->stack |= IPV6;
        packet->network_l.h_len = IPv6_OFFSET;
        packet->network_l.header = (void*)ipv6;

        if (ipv6->next_proto == TCP) {
            packet->stack |= TCP;
            packet->transport_l.header = (void*)(ipv6 + 1);
            packet->transport_l.h_len = (((tcp_h*)packet->transport_l.header)->data_offset >> 4) * 4;
        }

        return SUCCESS;
    }
    return FAIL;
}

/**
 * @brief   thread-safe parse packet to respective layers
 *
 * @param   packet - struct of founded headers by layers (void*)
 *
 * @return  IP version, 0 if not discovered
 */
void stack_recognition(packet *packet)
{
    /*
     *  Assume that most common scenario will be capturing from tun* device or NFLOG source
     *  and most common protocol is IPv4. In this case packet starts with IPv4 header
     */
    uint8_t ver = *(uint8_t*)packet->raw_pkt_ptr >> 4;

    if (ver == IPv4_VER && handle_ipv4((ipv4_h*)packet->raw_pkt_ptr, packet) == SUCCESS) {
        return;
    } //First header not an IPv4 for sure

    packet->link_l.header = packet->raw_pkt_ptr; //put link layer to stack, assuming it either Ethernet or 802.1Q
    packet->link_l.h_len = ETH_OFFSET;
    packet->stack |= ETH;

    ether_h *eth = (ether_h*)packet->raw_pkt_ptr;

    if (eth->etype == 0x0008 && handle_ipv4((ipv4_h*)(eth + 1), packet) == SUCCESS) { //0x0800 (IPv4) - network order
        return;
    }

    if (eth->etype == 0xDD86 && handle_ipv6((ipv6_h*)(eth + 1), packet) == SUCCESS) { //0x86DD (IPv6) - network order
        return;
    }

    if (eth->etype == 0x0081) { //0x8100 (802.1Q) - network order
        packet->stack &= ~LINK_MASQ;
        packet->link_l.h_len = DOT1Q_OFFSET;
        packet->stack |= DOT1Q;
        dot1q_h *dot1q = (dot1q_h*)packet->raw_pkt_ptr;

        if (dot1q->etype == 0x0008 && handle_ipv4((ipv4_h*)(dot1q + 1), packet) == SUCCESS) {
            return;
        }

        if (dot1q->etype == 0xDD86 && handle_ipv6((ipv6_h*)(dot1q + 1), packet) == SUCCESS) {
            return;
        }

    }


    if (ver == IPv6_VER) {
        ipv6_h *ipv6 = (ipv6_h*)packet->raw_pkt_ptr;

        switch (ipv6->next_proto) {
            case 6:     //TCP
                packet->stack |= TCP;
                packet->stack &= ~LINK_MASQ;
                packet->link_l.header = NULL;
                packet->link_l.h_len = 0;
                packet->transport_l.header = (void*)(ipv6 + 1);
                packet->transport_l.h_len = (((tcp_h*)packet->transport_l.header)->data_offset >> 4) * 4;
                /* no break */
            case 41:    //IPv6
            case 43:    //IPv6-Route
            case 59:    //IPv6-NoNxt
            case 60:    //IPv6-Opts
            case 58:    //IPv6-ICMP
            case 44:    //IPv6-Frag
            case 17:    //UDP
                packet->stack |= IPV6;
                packet->network_l.header = packet->raw_pkt_ptr;
                packet->network_l.h_len = IPv6_OFFSET;

        }

    }

}
